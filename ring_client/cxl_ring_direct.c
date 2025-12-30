#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Binary ring client matching redis/src/cxl_ring.c (version=2, slot_size=4096).
 * Request: u8 op (1=GET,2=SET), u8 key_len, u16 val_len (LE), key, val
 * Response: u8 status (0=OK,1=MISS,2=ERR), u16 val_len (LE), val (for GET hit)
 * Ring slot layout keeps 16-byte header (cid,u16 type,u16 flags,u32 len,u32 resv) + payload.
 * Latency/cost collection is optional (--latency/--cost) to avoid overhead in fast paths.
 */

#define MAGIC "CXLSHM1\0"
#define VERSION 2
#define MSG_DATA 1
#define MSG_CLOSE 2
#define SLOT_SIZE 4096

#define OP_GET 1
#define OP_SET 2
#define STATUS_OK 0
#define STATUS_MISS 1
#define STATUS_ERR 2

/* Only grab a lock when >1 thread shares the same ring (protect head/tail). */
static int use_lock = 0;
static pthread_mutex_t req_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t resp_lock = PTHREAD_MUTEX_INITIALIZER;

static volatile int running = 1;
static void handle_sig(int sig) { (void)sig; running = 0; }

struct ring_info {
    size_t req_off, req_sz;
    size_t resp_off, resp_sz;
    uint32_t slots;
};

struct layout {
    uint32_t ring_count;
    struct ring_info rings[8];
};

struct latency_stats {
    double *samples;
    int cap;
    int count;
    double sum;
};

struct cost_stats {
    uint64_t push_retries;
    uint64_t sleep_ns;
};

struct ts_queue {
    uint64_t *buf;
    int cap;
    int head;
    int tail;
};

struct stage_ctx {
    int collect_latency;
    int collect_cost;
    struct ts_queue q;
    struct latency_stats ls;
    struct cost_stats cs;
};

struct bench_result {
    double set_sec;
    double get_sec;
    int n;
    int tid;
    struct latency_stats set_lat;
    struct latency_stats get_lat;
    struct cost_stats set_cost;
    struct cost_stats get_cost;
};

struct agg_latency {
    double avg;
    double p50, p75, p90, p99, p999, p9999;
    int count;
};

static inline uint64_t nowns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void tsq_init(struct ts_queue *q, int cap) {
    q->buf = (uint64_t *)calloc(cap, sizeof(uint64_t));
    q->cap = cap;
    q->head = 0;
    q->tail = 0;
}

static void tsq_free(struct ts_queue *q) {
    free(q->buf);
    q->buf = NULL;
    q->cap = q->head = q->tail = 0;
}

static int tsq_push(struct ts_queue *q, uint64_t v) {
    if (!q->buf || q->cap == 0) return 0;
    int next = (q->head + 1) % q->cap;
    if (next == q->tail) return -1; /* full */
    q->buf[q->head] = v;
    q->head = next;
    return 0;
}

static int tsq_pop(struct ts_queue *q, uint64_t *out) {
    if (!q->buf || q->head == q->tail) return -1;
    *out = q->buf[q->tail];
    q->tail = (q->tail + 1) % q->cap;
    return 0;
}

static void lat_init(struct latency_stats *ls, int cap) {
    ls->samples = (double *)calloc(cap, sizeof(double));
    ls->cap = cap;
    ls->count = 0;
    ls->sum = 0.0;
}

static void lat_record(struct latency_stats *ls, double us) {
    if (!ls->samples || ls->count >= ls->cap) return;
    ls->samples[ls->count++] = us;
    ls->sum += us;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static double percentile(double *arr, int n, double p) {
    if (n == 0) return 0.0;
    double idx = p * (n - 1);
    int i = (int)idx;
    if (i < 0) i = 0;
    if (i >= n) i = n - 1;
    return arr[i];
}

static void compute_agg_latency(struct latency_stats *ls, struct agg_latency *out) {
    memset(out, 0, sizeof(*out));
    if (!ls || ls->count == 0 || !ls->samples) return;
    qsort(ls->samples, ls->count, sizeof(double), cmp_double);
    out->count = ls->count;
    out->avg = ls->sum / ls->count;
    out->p50 = percentile(ls->samples, ls->count, 0.50);
    out->p75 = percentile(ls->samples, ls->count, 0.75);
    out->p90 = percentile(ls->samples, ls->count, 0.90);
    out->p99 = percentile(ls->samples, ls->count, 0.99);
    out->p999 = percentile(ls->samples, ls->count, 0.999);
    out->p9999 = percentile(ls->samples, ls->count, 0.9999);
}

static void stage_init(struct stage_ctx *s, int collect_latency, int collect_cost, int cap_hint) {
    memset(s, 0, sizeof(*s));
    s->collect_latency = collect_latency;
    s->collect_cost = collect_cost;
    if (collect_latency) {
        int cap = cap_hint;
        if (cap < 1024) cap = 1024;
        tsq_init(&s->q, cap + 1); /* +1 for ring buffer sentinel */
        lat_init(&s->ls, cap);
    }
}

static void stage_free(struct stage_ctx *s) {
    tsq_free(&s->q);
    /* caller frees latency samples after aggregation */
}

static int load_layout(unsigned char *mm, struct layout *lo) {
    const char *magic = (const char *)mm;
    if (memcmp(magic, MAGIC, 8) != 0) return -1;
    uint32_t ver = 0;
    memcpy(&ver, mm + 8, 4);
    if (ver != VERSION) return -1;
    uint32_t ring_count = 0;
    memcpy(&ring_count, mm + 12, 4);
    if (ring_count == 0 || ring_count > 8) return -1;
    lo->ring_count = ring_count;
    for (uint32_t i = 0; i < ring_count; i++) {
        uint64_t req_off = 0, req_sz = 0, resp_off = 0, resp_sz = 0;
        memcpy(&req_off, mm + 24 + i * 32, 8);
        memcpy(&req_sz, mm + 32 + i * 32, 8);
        memcpy(&resp_off, mm + 40 + i * 32, 8);
        memcpy(&resp_sz, mm + 48 + i * 32, 8);
        lo->rings[i].req_off = (size_t)req_off;
        lo->rings[i].req_sz = (size_t)req_sz;
        lo->rings[i].resp_off = (size_t)resp_off;
        lo->rings[i].resp_sz = (size_t)resp_sz;
        lo->rings[i].slots = (req_sz > 16) ? (req_sz - 16) / SLOT_SIZE : 1;
    }
    return 0;
}

static int ring_push(unsigned char *mm, const struct ring_info *ri, uint32_t cid, uint16_t type, const unsigned char *payload, uint32_t len) {
    uint64_t head = 0, tail = 0;
    memcpy(&head, mm + ri->req_off, 8);
    memcpy(&tail, mm + ri->req_off + 8, 8);
    if (head - tail >= ri->slots) return 0; /* full */
    if (len > SLOT_SIZE - 16) return -1;
    uint64_t idx = head % ri->slots;
    size_t slot_off = ri->req_off + 16 + idx * SLOT_SIZE;
    uint32_t flags = 0, reserved = 0;
    memcpy(mm + slot_off, &cid, 4);
    memcpy(mm + slot_off + 4, &type, 2);
    memcpy(mm + slot_off + 6, &flags, 2);
    memcpy(mm + slot_off + 8, &len, 4);
    memcpy(mm + slot_off + 12, &reserved, 4);
    memcpy(mm + slot_off + 16, payload, len);
    if (SLOT_SIZE > 16 + len) memset(mm + slot_off + 16 + len, 0, SLOT_SIZE - 16 - len);
    head++;
    memcpy(mm + ri->req_off, &head, 8);
    return 1;
}

static int ring_pop(unsigned char *mm, const struct ring_info *ri, uint32_t *cid, uint16_t *type, unsigned char **payload, uint32_t *len) {
    uint64_t head = 0, tail = 0;
    memcpy(&head, mm + ri->resp_off, 8);
    memcpy(&tail, mm + ri->resp_off + 8, 8);
    if (tail == head) return 0;
    uint64_t idx = tail % ri->slots;
    size_t slot_off = ri->resp_off + 16 + idx * SLOT_SIZE;
    memcpy(cid, mm + slot_off, 4);
    memcpy(type, mm + slot_off + 4, 2);
    memcpy(len, mm + slot_off + 8, 4);
    if (*len > SLOT_SIZE - 16) *len = SLOT_SIZE - 16;
    *payload = mm + slot_off + 16;
    tail++;
    memcpy(mm + ri->resp_off + 8, &tail, 8);
    return 1;
}

static inline int ring_push_safe(unsigned char *mm, const struct ring_info *ri, uint32_t cid, uint16_t type, const unsigned char *payload, uint32_t len) {
    if (!use_lock) return ring_push(mm, ri, cid, type, payload, len);
    int r;
    pthread_mutex_lock(&req_lock);
    r = ring_push(mm, ri, cid, type, payload, len);
    pthread_mutex_unlock(&req_lock);
    return r;
}

static inline int ring_pop_safe(unsigned char *mm, const struct ring_info *ri, uint32_t *cid, uint16_t *type, unsigned char **payload, uint32_t *len) {
    if (!use_lock) return ring_pop(mm, ri, cid, type, payload, len);
    int r;
    pthread_mutex_lock(&resp_lock);
    r = ring_pop(mm, ri, cid, type, payload, len);
    pthread_mutex_unlock(&resp_lock);
    return r;
}

static int push_set(unsigned char *mm, const struct ring_info *ri, uint32_t cid, int idx) {
    char key[32], val[32];
    snprintf(key, sizeof(key), "k%d", idx);
    snprintf(val, sizeof(val), "v%d", idx);
    uint8_t klen = (uint8_t)strlen(key);
    uint16_t vlen = (uint16_t)strlen(val);
    unsigned char buf[SLOT_SIZE];
    size_t need = 4 + klen + vlen;
    if (need > SLOT_SIZE - 16) return -1;
    buf[0] = OP_SET;
    buf[1] = klen;
    buf[2] = (uint8_t)(vlen & 0xff);
    buf[3] = (uint8_t)((vlen >> 8) & 0xff);
    memcpy(buf + 4, key, klen);
    memcpy(buf + 4 + klen, val, vlen);
    return ring_push_safe(mm, ri, cid, MSG_DATA, buf, (uint32_t)need);
}

static int push_get(unsigned char *mm, const struct ring_info *ri, uint32_t cid, int idx) {
    char key[32];
    snprintf(key, sizeof(key), "k%d", idx);
    uint8_t klen = (uint8_t)strlen(key);
    unsigned char buf[SLOT_SIZE];
    size_t need = 4 + klen;
    buf[0] = OP_GET;
    buf[1] = klen;
    buf[2] = 0;
    buf[3] = 0;
    memcpy(buf + 4, key, klen);
    return ring_push_safe(mm, ri, cid, MSG_DATA, buf, (uint32_t)need);
}

static int drain_one(unsigned char *mm, const struct ring_info *ri, struct stage_ctx *stage) {
    uint32_t cid, len;
    uint16_t type;
    unsigned char *pl;
    if (!ring_pop_safe(mm, ri, &cid, &type, &pl, &len)) return 0;
    if (type != MSG_DATA || len < 3) return 1;
    if (stage && stage->collect_latency) {
        uint64_t t0 = 0;
        if (tsq_pop(&stage->q, &t0) == 0) {
            uint64_t now = nowns();
            double us = (double)(now - t0) / 1000.0;
            lat_record(&stage->ls, us);
        }
    }
    return 1;
}

static void drain_many(unsigned char *mm, const struct ring_info *ri, int *outstanding, int target, struct stage_ctx *stage) {
    while (*outstanding > target && running) {
        if (drain_one(mm, ri, stage)) {
            (*outstanding)--;
        } else {
            struct timespec ts = {0, 500000};
            nanosleep(&ts, NULL);
            if (stage && stage->collect_cost) stage->cs.sleep_ns += 500000;
        }
    }
}

static void run_bench_internal(unsigned char *mm, const struct ring_info *ri, int n, int pipeline, int quiet, int tid, struct bench_result *out, int max_inflight, int collect_latency, int collect_cost) {
    struct timespec ts1, ts2, ts3;
    uint32_t cid_set = (uint32_t)(tid * 2 + 1);
    uint32_t cid_get = cid_set + 1;
    int inflight = 0;
    if (max_inflight <= 0) max_inflight = (int)(ri->slots / 4);
    if (max_inflight < 1) max_inflight = 1;

    struct stage_ctx set_stage, get_stage;
    stage_init(&set_stage, collect_latency, collect_cost, n + max_inflight + 64);
    stage_init(&get_stage, collect_latency, collect_cost, n + max_inflight + 64);

    clock_gettime(CLOCK_MONOTONIC, &ts1);
    if (!quiet) fprintf(stderr, "[bench tid=%d] pushing %d SET (pipeline=%d)\n", tid, n, pipeline);
    for (int i = 0; i < n; i++) {
        if (pipeline) drain_many(mm, ri, &inflight, max_inflight, &set_stage);
        while (!push_set(mm, ri, cid_set, i)) {
            struct timespec ts = {0, 500000};
            nanosleep(&ts, NULL);
            if (collect_cost) set_stage.cs.sleep_ns += 500000;
            set_stage.cs.push_retries++;
        }
        if (collect_latency) tsq_push(&set_stage.q, nowns());
        if (pipeline) inflight++;
        if (!pipeline) {
            while (!drain_one(mm, ri, &set_stage)) {
                struct timespec ts = {0, 500000};
                nanosleep(&ts, NULL);
                if (collect_cost) set_stage.cs.sleep_ns += 500000;
            }
        }
    }
    if (pipeline) drain_many(mm, ri, &inflight, 0, &set_stage);
    clock_gettime(CLOCK_MONOTONIC, &ts2);

    if (!quiet) fprintf(stderr, "[bench tid=%d] pushing %d GET\n", tid, n);
    for (int i = 0; i < n; i++) {
        if (pipeline) drain_many(mm, ri, &inflight, max_inflight, &get_stage);
        while (!push_get(mm, ri, cid_get, i)) {
            struct timespec ts = {0, 500000};
            nanosleep(&ts, NULL);
            if (collect_cost) get_stage.cs.sleep_ns += 500000;
            get_stage.cs.push_retries++;
        }
        if (collect_latency) tsq_push(&get_stage.q, nowns());
        if (pipeline) inflight++;
        if (!pipeline) {
            while (!drain_one(mm, ri, &get_stage)) {
                struct timespec ts = {0, 500000};
                nanosleep(&ts, NULL);
                if (collect_cost) get_stage.cs.sleep_ns += 500000;
            }
        }
    }
    if (pipeline) drain_many(mm, ri, &inflight, 0, &get_stage);
    clock_gettime(CLOCK_MONOTONIC, &ts3);

    double set_sec = (ts2.tv_sec - ts1.tv_sec) + (ts2.tv_nsec - ts1.tv_nsec) / 1e9;
    double get_sec = (ts3.tv_sec - ts2.tv_sec) + (ts3.tv_nsec - ts2.tv_nsec) / 1e9;
    if (out) {
        out->set_sec = set_sec;
        out->get_sec = get_sec;
        out->n = n;
        out->tid = tid;
        out->set_lat = set_stage.ls;
        out->get_lat = get_stage.ls;
        out->set_cost = set_stage.cs;
        out->get_cost = get_stage.cs;
    }
    if (!quiet) {
        printf("tid=%d SET: %.2f req/s\n", tid, n / set_sec);
        printf("tid=%d GET: %.2f req/s\n", tid, n / get_sec);
    }
    stage_free(&set_stage);
    stage_free(&get_stage);
}

struct thread_arg {
    unsigned char *mm;
    const struct ring_info *ri;
    int n;
    int pipeline;
    int tid;
    struct bench_result *res;
    int max_inflight;
    int collect_latency;
    int collect_cost;
};

static void *bench_thread(void *p) {
    struct thread_arg *a = (struct thread_arg *)p;
    run_bench_internal(a->mm, a->ri, a->n, a->pipeline, 1, a->tid, a->res, a->max_inflight, a->collect_latency, a->collect_cost);
    return NULL;
}

static void free_thread_results(struct bench_result *res, int threads) {
    if (!res) return;
    for (int i = 0; i < threads; i++) {
        free(res[i].set_lat.samples);
        free(res[i].get_lat.samples);
    }
}

static void aggregate_latency_stats(struct latency_stats *dst, struct bench_result *res, int threads, int is_get) {
    int total = 0;
    for (int i = 0; i < threads; i++) {
        total += is_get ? res[i].get_lat.count : res[i].set_lat.count;
    }
    if (total == 0) {
        dst->samples = NULL;
        dst->cap = dst->count = 0;
        dst->sum = 0.0;
        return;
    }
    dst->samples = (double *)malloc(sizeof(double) * total);
    dst->cap = total;
    dst->count = total;
    dst->sum = 0.0;
    int off = 0;
    for (int i = 0; i < threads; i++) {
        struct latency_stats *src = is_get ? &res[i].get_lat : &res[i].set_lat;
        if (src->count == 0) continue;
        memcpy(dst->samples + off, src->samples, sizeof(double) * src->count);
        off += src->count;
        dst->sum += src->sum;
    }
    dst->count = off;
}

static void aggregate_cost(struct cost_stats *dst, struct bench_result *res, int threads, int is_get) {
    memset(dst, 0, sizeof(*dst));
    for (int i = 0; i < threads; i++) {
        struct cost_stats *src = is_get ? &res[i].get_cost : &res[i].set_cost;
        dst->push_retries += src->push_retries;
        dst->sleep_ns += src->sleep_ns;
    }
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
    if (mkdir(path, 0755) == 0) return 0;
    return -1;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void write_csv_row(FILE *f, const char *label, const char *op, int threads, int rings, int n, int pipeline, int max_inflight, double rps, struct agg_latency *lat, struct cost_stats *cs) {
    fprintf(f, "%s,%s,%d,%d,%d,%d,%d,%.0f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%" PRIu64 ",%.3f\n",
            label, op, threads, rings, n, pipeline, max_inflight, rps,
            lat ? lat->avg : 0.0,
            lat ? lat->p50 : 0.0,
            lat ? lat->p75 : 0.0,
            lat ? lat->p90 : 0.0,
            lat ? lat->p99 : 0.0,
            lat ? lat->p999 : 0.0,
            lat ? lat->p9999 : 0.0,
            (uint64_t)(cs ? cs->push_retries : 0),
            cs ? (double)cs->sleep_ns / 1e6 : 0.0);
}

static void run_bench(unsigned char *mm, struct layout *lo, int n, int pipeline, int threads, int max_inflight, int collect_latency, int collect_cost, const char *csv_path, const char *label) {
    int ring_count = lo->ring_count ? lo->ring_count : 1;
    if (threads < 1) threads = 1;
    if (ring_count < threads) use_lock = 1;
    if (collect_latency && use_lock) {
        fprintf(stderr, "warn: latency collection disabled because threads share a ring (lock path)\n");
        collect_latency = 0;
    }

    pthread_t *ths = calloc(threads, sizeof(pthread_t));
    struct bench_result *res = calloc(threads, sizeof(struct bench_result));
    struct thread_arg *args = calloc(threads, sizeof(struct thread_arg));

    for (int i = 0; i < threads; i++) {
        int ring_idx = i % ring_count;
        args[i].mm = mm;
        args[i].ri = &lo->rings[ring_idx];
        args[i].n = n;
        args[i].pipeline = pipeline;
        args[i].tid = i;
        args[i].res = &res[i];
        args[i].max_inflight = max_inflight;
        args[i].collect_latency = collect_latency;
        args[i].collect_cost = collect_cost;
        int rc = pthread_create(&ths[i], NULL, bench_thread, &args[i]);
        if (rc != 0) fprintf(stderr, "warn: create thread %d failed (%d)\n", i, rc);
    }
    for (int i = 0; i < threads; i++) {
        if (ths[i]) pthread_join(ths[i], NULL);
    }

    double max_set = 0.0, max_get = 0.0;
    for (int i = 0; i < threads; i++) {
        if (res[i].set_sec > max_set) max_set = res[i].set_sec;
        if (res[i].get_sec > max_get) max_get = res[i].get_sec;
    }
    double set_rps = (max_set > 0) ? ((double)threads * n) / max_set : 0.0;
    double get_rps = (max_get > 0) ? ((double)threads * n) / max_get : 0.0;
    printf("[threads=%d rings=%d] SET: %.2f req/s\n", threads, ring_count, set_rps);
    printf("[threads=%d rings=%d] GET: %.2f req/s\n", threads, ring_count, get_rps);

    struct agg_latency set_lat_agg = {0}, get_lat_agg = {0};
    struct latency_stats set_lat = {0}, get_lat = {0};
    struct cost_stats set_cost = {0}, get_cost = {0};
    if (collect_latency) {
        aggregate_latency_stats(&set_lat, res, threads, 0);
        aggregate_latency_stats(&get_lat, res, threads, 1);
        compute_agg_latency(&set_lat, &set_lat_agg);
        compute_agg_latency(&get_lat, &get_lat_agg);
    }
    if (collect_cost) {
        aggregate_cost(&set_cost, res, threads, 0);
        aggregate_cost(&get_cost, res, threads, 1);
    }

    if (csv_path) {
        if (ensure_dir("results") != 0) {
            fprintf(stderr, "warn: cannot create results/ directory for csv\n");
        } else {
            int new_file = !file_exists(csv_path);
            FILE *f = fopen(csv_path, "a");
            if (!f) {
                perror("fopen csv");
            } else {
                if (new_file) {
                    fprintf(f, "label,op,threads,rings,requests,pipeline,max_inflight,throughput_rps,avg_us,p50_us,p75_us,p90_us,p99_us,p99.9_us,p99.99_us,push_retries,sleep_ms\n");
                }
                write_csv_row(f, label, "SET", threads, ring_count, n, pipeline, max_inflight, set_rps, collect_latency ? &set_lat_agg : NULL, collect_cost ? &set_cost : NULL);
                write_csv_row(f, label, "GET", threads, ring_count, n, pipeline, max_inflight, get_rps, collect_latency ? &get_lat_agg : NULL, collect_cost ? &get_cost : NULL);
                fclose(f);
                printf("[+] CSV appended to %s\n", csv_path);
            }
        }
    }

    free(set_lat.samples);
    free(get_lat.samples);
    free_thread_results(res, threads);
    free(ths);
    free(res);
    free(args);
}

int main(int argc, char **argv) {
    const char *path = "/sys/bus/pci/devices/0000:00:02.0/resource2";
    size_t map_size = 1024ULL * 1024 * 1024;
    int bench_n = 0;
    int pipeline = 0;
    int threads = 1;
    int ring_idx = 0;
    int max_inflight = 0; /* 0 = auto (slots/4) */
    int collect_latency = 0;
    int collect_cost = 0;
    const char *csv_path = "results/ring_metrics.csv";
    const char *label = "ring";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--path") && i + 1 < argc) path = argv[++i];
        else if (!strcmp(argv[i], "--map-size") && i + 1 < argc) map_size = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--bench") && i + 1 < argc) bench_n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--pipeline")) pipeline = 1;
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ring") && i + 1 < argc) ring_idx = atoi(argv[++i]); /* kept for single ring mode */
        else if (!strcmp(argv[i], "--max-inflight") && i + 1 < argc) max_inflight = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--latency")) collect_latency = 1;
        else if (!strcmp(argv[i], "--cost")) collect_cost = 1;
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--label") && i + 1 < argc) label = argv[++i];
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    unsigned char *mm = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mm == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    struct layout lo;
    if (load_layout(mm, &lo) != 0) {
        fprintf(stderr, "invalid ring layout; start redis with cxl ring (version 2) first\n");
        munmap(mm, map_size);
        close(fd);
        return 1;
    }
    if (ring_idx < 0 || ring_idx >= (int)lo.ring_count) ring_idx = 0;
    printf("[*] ring direct: path=%s map=%zu ring_count=%u using_ring=%d slots=%u\n",
           path, map_size, lo.ring_count, ring_idx, lo.rings[ring_idx].slots);

    if (bench_n > 0) {
        run_bench(mm, &lo, bench_n, pipeline, threads, max_inflight, collect_latency, collect_cost, csv_path, label);
    } else {
        /* simple GET ping */
        push_get(mm, &lo.rings[ring_idx], 99, 0);
        while (running) {
            if (drain_one(mm, &lo.rings[ring_idx], NULL)) {
                printf("PING done\n");
                break;
            }
            struct timespec ts = {0, 1000000};
            nanosleep(&ts, NULL);
        }
    }

    munmap(mm, map_size);
    close(fd);
    return 0;
}
