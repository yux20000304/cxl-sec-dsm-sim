#define _GNU_SOURCE

#include "../tdx_shm/tdx_shm_transport.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
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
#include <fcntl.h>

/* TDX shared-memory ring client matching Redis shared-memory backend (GET/SET binary protocol).
 *
 * Transport: per-ring TDX SHM region (double-queue layout):
 * - server->client: q12
 * - client->server: q21
 *
 * Each request/response message is stored in a 4KiB slot as:
 *   u16 msg_len (bytes after this length field)
 *   16B header: cid,u16 type,u16 flags,u32 len,u32 reserved
 *   payload (len bytes)
 *
 * Request payload:
 *   u8 op (1=GET,2=SET), u8 key_len, u16 val_len (LE), key, val
 * Response payload:
 *   u8 status (0=OK,1=MISS,2=ERR), u16 val_len (LE), u8 reserved, val
 *
 * Notes:
 * - Keep RESP parsing out of the hot path.
 * - Slot payload budget is limited by the TDX SHM framing:
 *     max_payload = (TDX_SHM_SLOT_SIZE - 2) - 16 = 4078 bytes
 */

#define MSG_DATA 1
#define MSG_CLOSE 2

#define OP_GET 1
#define OP_SET 2

#define STATUS_OK 0
#define STATUS_MISS 1
#define STATUS_ERR 2

#define MAX_RINGS 8
#define RING_SLOT_HDR_SIZE 16U
#define RING_MAX_PAYLOAD ((uint32_t)TDX_SHM_MSG_MAX - RING_SLOT_HDR_SIZE)

static int use_lock = 0;
static pthread_mutex_t req_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t resp_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t shm_delay_ns = 0;
static uint64_t shm_pause_iters_per_ns_x1024 = 0;

static volatile int running = 1;
static void handle_sig(int sig) {
    (void)sig;
    running = 0;
}

struct ring_info {
    struct tdx_shm_queue_view req;  /* q21 (client -> server) */
    struct tdx_shm_queue_view resp; /* q12 (server -> client) */
    uint32_t slots;                 /* capacity - 1 (informational) */
    uint32_t ring_idx;
};

struct layout {
    uint32_t ring_count;
    struct ring_info rings[MAX_RINGS];
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

struct ring_slot_hdr {
    uint32_t cid;
    uint16_t type;
    uint16_t flags;
    uint32_t len;
    uint32_t reserved;
};

static inline uint64_t nowns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline size_t align_up(size_t value, size_t align) {
    return (value + align - 1U) & ~(align - 1U);
}

static void shm_delay_calibrate(void) {
    if (shm_pause_iters_per_ns_x1024) return;
    const uint64_t iters = 5000000ULL;
    uint64_t start = nowns();
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
    uint64_t dt = nowns() - start;
    if (dt == 0) dt = 1;
    shm_pause_iters_per_ns_x1024 = (iters * 1024ULL) / dt;
    if (shm_pause_iters_per_ns_x1024 == 0) shm_pause_iters_per_ns_x1024 = 1;
}

static inline void shm_delay(void) {
    uint64_t ns = shm_delay_ns;
    if (!ns) return;
    if (!shm_pause_iters_per_ns_x1024) shm_delay_calibrate();
    uint64_t iters = (ns * shm_pause_iters_per_ns_x1024 + 1023ULL) / 1024ULL;
    if (iters == 0) iters = 1;
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
}

static int parse_size(const char *arg, size_t *out) {
    if (!arg || !out) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(arg, &end, 0);
    if (errno != 0) return -1;

    unsigned long long multiplier = 1ULL;
    if (end && *end != '\0') {
        if (end[1] != '\0') return -1;
        switch (*end) {
            case 'K':
            case 'k':
                multiplier = 1024ULL;
                break;
            case 'M':
            case 'm':
                multiplier = 1024ULL * 1024ULL;
                break;
            case 'G':
            case 'g':
                multiplier = 1024ULL * 1024ULL * 1024ULL;
                break;
            default:
                return -1;
        }
    }
    if (multiplier != 0ULL && value > (ULLONG_MAX / multiplier)) return -1;
    unsigned long long bytes = value * multiplier;
    if (bytes > (unsigned long long)SIZE_MAX) return -1;
    *out = (size_t)bytes;
    return 0;
}

static uint32_t env_u32(const char *key, uint32_t def) {
    const char *v = getenv(key);
    if (!v || !v[0]) return def;
    errno = 0;
    unsigned long long x = strtoull(v, NULL, 0);
    if (errno != 0) return def;
    if (x > 0xffffffffULL) return def;
    return (uint32_t)x;
}

static size_t env_size(const char *key, size_t def) {
    const char *v = getenv(key);
    if (!v || !v[0]) return def;
    size_t out = 0;
    if (parse_size(v, &out) != 0) return def;
    return out;
}

static int tdx_region_attach(void *base, size_t size, struct tdx_shm_region *out) {
    if (!base || !out) return -1;

    struct tdx_shm_header *hdr = (struct tdx_shm_header *)base;
    if (hdr->magic != TDX_SHM_MAGIC) return -1;
    if (hdr->version != TDX_SHM_VERSION) return -1;
    if (hdr->total_size == 0 || hdr->total_size > (uint64_t)size) return -1;

    if (hdr->q12.slot_size != TDX_SHM_SLOT_SIZE || hdr->q21.slot_size != TDX_SHM_SLOT_SIZE) return -1;
    if (hdr->q12.capacity != TDX_SHM_QUEUE_CAPACITY || hdr->q21.capacity != TDX_SHM_QUEUE_CAPACITY) return -1;

    size_t queue_bytes = (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE;
    if ((size_t)hdr->q12.data_offset + queue_bytes > size) return -1;
    if ((size_t)hdr->q21.data_offset + queue_bytes > size) return -1;

    out->hdr = hdr;
    out->q12.q = &hdr->q12;
    out->q12.data = (uint8_t *)base + hdr->q12.data_offset;
    out->q21.q = &hdr->q21;
    out->q21.data = (uint8_t *)base + hdr->q21.data_offset;
    return 0;
}

static int load_layout(unsigned char *mm, size_t map_size, struct layout *lo) {
    if (!mm || !lo) return -1;

    uint32_t ring_count = env_u32("CXL_RING_COUNT", 1);
    if (ring_count == 0 || ring_count > MAX_RINGS) return -1;

    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);

    if ((region_base % 4096) != 0 || (region_size % 4096) != 0) return -1;
    if (region_size < align_up(sizeof(struct tdx_shm_header), 64U) +
                          2U * (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE) {
        return -1;
    }
    if (region_base > map_size) return -1;
    if ((size_t)ring_count > (map_size - region_base) / region_size) return -1;

    memset(lo, 0, sizeof(*lo));
    lo->ring_count = ring_count;
    for (uint32_t i = 0; i < ring_count; i++) {
        size_t off = region_base + (size_t)i * region_size;
        struct tdx_shm_region region;
        if (tdx_region_attach(mm + off, region_size, &region) != 0) return -1;

        lo->rings[i].req = region.q21;
        lo->rings[i].resp = region.q12;
        lo->rings[i].ring_idx = i;
        lo->rings[i].slots = TDX_SHM_QUEUE_CAPACITY > 0 ? (TDX_SHM_QUEUE_CAPACITY - 1U) : 0U;
    }
    return 0;
}

static uint32_t ring_next(uint32_t v, uint32_t cap) {
    return (v + 1U) % cap;
}

static int ring_push(unsigned char *mm, const struct ring_info *ri, uint32_t cid, uint16_t type, const unsigned char *payload, uint32_t len) {
    (void)mm;
    shm_delay();

    if (!ri || !ri->req.q || !ri->req.data || !payload) return -1;
    if (len > RING_MAX_PAYLOAD) return -1;

    struct tdx_shm_queue *q = ri->req.q;
    uint32_t cap = q->capacity;
    uint32_t head = atomic_load_explicit(&q->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint32_t next = ring_next(tail, cap);
    if (next == head) return 0; /* full */

    uint8_t *slot = ri->req.data + ((size_t)tail * q->slot_size);
    uint16_t msg_len = (uint16_t)(RING_SLOT_HDR_SIZE + len);
    memcpy(slot, &msg_len, sizeof(msg_len));

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = 0;
    hdr.len = len;
    hdr.reserved = 0;
    memcpy(slot + sizeof(msg_len), &hdr, sizeof(hdr));
    if (len) memcpy(slot + sizeof(msg_len) + sizeof(hdr), payload, len);

    atomic_store_explicit(&q->tail, next, memory_order_release);
    return 1;
}

static int ring_pop(unsigned char *mm, const struct ring_info *ri, uint32_t *cid, uint16_t *type, unsigned char **payload, uint32_t *len) {
    (void)mm;
    shm_delay();

    if (!ri || !ri->resp.q || !ri->resp.data || !cid || !type || !payload || !len) return -1;

    struct tdx_shm_queue *q = ri->resp.q;
    uint32_t cap = q->capacity;
    uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    if (head == tail) return 0; /* empty */

    uint8_t *slot = ri->resp.data + ((size_t)head * q->slot_size);
    uint16_t msg_len = 0;
    memcpy(&msg_len, slot, sizeof(msg_len));
    if (msg_len < sizeof(struct ring_slot_hdr) || msg_len > TDX_SHM_MSG_MAX) return -1;

    struct ring_slot_hdr hdr;
    memcpy(&hdr, slot + sizeof(msg_len), sizeof(hdr));
    if (hdr.len > (uint32_t)(msg_len - sizeof(hdr))) return -1;
    if (hdr.len > RING_MAX_PAYLOAD) return -1;

    *cid = hdr.cid;
    *type = hdr.type;
    *len = hdr.len;
    *payload = slot + sizeof(msg_len) + sizeof(hdr);

    atomic_store_explicit(&q->head, ring_next(head, cap), memory_order_release);
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

    unsigned char buf[TDX_SHM_SLOT_SIZE];
    size_t need = 4 + klen + vlen;
    if (need > RING_MAX_PAYLOAD) return -1;

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

    unsigned char buf[TDX_SHM_SLOT_SIZE];
    size_t need = 4 + klen;
    if (need > RING_MAX_PAYLOAD) return -1;

    buf[0] = OP_GET;
    buf[1] = klen;
    buf[2] = 0;
    buf[3] = 0;
    memcpy(buf + 4, key, klen);
    return ring_push_safe(mm, ri, cid, MSG_DATA, buf, (uint32_t)need);
}

static int tsq_init(struct ts_queue *q, int cap) {
    if (!q || cap <= 0) return -1;
    q->buf = (uint64_t *)calloc((size_t)cap, sizeof(uint64_t));
    if (!q->buf) return -1;
    q->cap = cap;
    q->head = q->tail = 0;
    return 0;
}

static void tsq_free(struct ts_queue *q) {
    if (!q) return;
    free(q->buf);
    q->buf = NULL;
    q->cap = q->head = q->tail = 0;
}

static int tsq_push(struct ts_queue *q, uint64_t v) {
    int next = (q->tail + 1) % q->cap;
    if (next == q->head) return -1;
    q->buf[q->tail] = v;
    q->tail = next;
    return 0;
}

static int tsq_pop(struct ts_queue *q, uint64_t *out) {
    if (q->head == q->tail) return -1;
    *out = q->buf[q->head];
    q->head = (q->head + 1) % q->cap;
    return 0;
}

static void lat_init(struct latency_stats *ls, int cap) {
    ls->samples = (double *)malloc(sizeof(double) * (size_t)cap);
    ls->cap = cap;
    ls->count = 0;
    ls->sum = 0.0;
}

static void lat_record(struct latency_stats *ls, double us) {
    if (ls->count < ls->cap) {
        ls->samples[ls->count++] = us;
        ls->sum += us;
    }
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a;
    double y = *(const double *)b;
    return (x > y) - (x < y);
}

static double percentile(double *a, int n, double p) {
    if (!a || n <= 0) return 0.0;
    double idx = p * (n - 1);
    int i = (int)idx;
    int j = i + 1;
    if (j >= n) return a[n - 1];
    double frac = idx - i;
    return a[i] * (1.0 - frac) + a[j] * frac;
}

static void compute_agg_latency(struct latency_stats *ls, struct agg_latency *out) {
    if (!ls || !out || ls->count <= 0) {
        memset(out, 0, sizeof(*out));
        return;
    }
    qsort(ls->samples, (size_t)ls->count, sizeof(double), cmp_double);
    out->count = ls->count;
    out->avg = ls->sum / (double)ls->count;
    out->p50 = percentile(ls->samples, ls->count, 0.50);
    out->p75 = percentile(ls->samples, ls->count, 0.75);
    out->p90 = percentile(ls->samples, ls->count, 0.90);
    out->p99 = percentile(ls->samples, ls->count, 0.99);
    out->p999 = percentile(ls->samples, ls->count, 0.999);
    out->p9999 = percentile(ls->samples, ls->count, 0.9999);
}

static void stage_init(struct stage_ctx *stage, int collect_latency, int collect_cost, int cap) {
    memset(stage, 0, sizeof(*stage));
    stage->collect_latency = collect_latency;
    stage->collect_cost = collect_cost;
    tsq_init(&stage->q, cap);
    if (collect_latency) lat_init(&stage->ls, cap);
}

static void stage_free(struct stage_ctx *stage) {
    tsq_free(&stage->q);
    /* NOTE: latency samples ownership is moved into bench_result; don't free here. */
}

static int drain_one(unsigned char *mm, const struct ring_info *ri, struct stage_ctx *stage) {
    uint32_t cid, rlen;
    uint16_t type;
    unsigned char *pl;
    int r = ring_pop_safe(mm, ri, &cid, &type, &pl, &rlen);
    if (r == 0) return 0;
    if (r < 0) return -1;
    if (type != MSG_DATA || rlen < 3) return 1;
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
        int r = drain_one(mm, ri, stage);
        if (r > 0) {
            (*outstanding)--;
        } else if (r < 0) {
            fprintf(stderr, "[!] ring_pop error while draining responses\n");
            running = 0;
            return;
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
        if (!running) break;
        if (pipeline) drain_many(mm, ri, &inflight, max_inflight, &set_stage);
        int pushed = 0;
        while (running) {
            int pr = push_set(mm, ri, cid_set, i);
            if (pr > 0) {
                pushed = 1;
                break;
            }
            if (pr < 0) {
                fprintf(stderr, "[!] push_set failed (ring write error)\n");
                running = 0;
                break;
            }
            struct timespec ts = {0, 500000};
            nanosleep(&ts, NULL);
            if (collect_cost) set_stage.cs.sleep_ns += 500000;
            set_stage.cs.push_retries++;
        }
        if (!running || !pushed) break;
        if (collect_latency) tsq_push(&set_stage.q, nowns());
        if (pipeline) inflight++;
        if (!pipeline) {
            while (running) {
                int dr = drain_one(mm, ri, &set_stage);
                if (dr > 0) break;
                if (dr < 0) {
                    fprintf(stderr, "[!] ring_pop failed while waiting for SET response\n");
                    running = 0;
                    break;
                }
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
        if (!running) break;
        if (pipeline) drain_many(mm, ri, &inflight, max_inflight, &get_stage);
        int pushed = 0;
        while (running) {
            int pr = push_get(mm, ri, cid_get, i);
            if (pr > 0) {
                pushed = 1;
                break;
            }
            if (pr < 0) {
                fprintf(stderr, "[!] push_get failed (ring write error)\n");
                running = 0;
                break;
            }
            struct timespec ts = {0, 500000};
            nanosleep(&ts, NULL);
            if (collect_cost) get_stage.cs.sleep_ns += 500000;
            get_stage.cs.push_retries++;
        }
        if (!running || !pushed) break;
        if (collect_latency) tsq_push(&get_stage.q, nowns());
        if (pipeline) inflight++;
        if (!pipeline) {
            while (running) {
                int dr = drain_one(mm, ri, &get_stage);
                if (dr > 0) break;
                if (dr < 0) {
                    fprintf(stderr, "[!] ring_pop failed while waiting for GET response\n");
                    running = 0;
                    break;
                }
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
    dst->samples = (double *)malloc(sizeof(double) * (size_t)total);
    dst->cap = total;
    dst->count = total;
    dst->sum = 0.0;
    int off = 0;
    for (int i = 0; i < threads; i++) {
        struct latency_stats *src = is_get ? &res[i].get_lat : &res[i].set_lat;
        if (src->count == 0) continue;
        memcpy(dst->samples + off, src->samples, sizeof(double) * (size_t)src->count);
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
    int ring_count = lo->ring_count ? (int)lo->ring_count : 1;
    if (threads < 1) threads = 1;
    if (ring_count < threads) use_lock = 1;
    if (collect_latency && use_lock) {
        fprintf(stderr, "warn: latency collection disabled because threads share a ring (lock path)\n");
        collect_latency = 0;
    }

    pthread_t *ths = calloc((size_t)threads, sizeof(pthread_t));
    struct bench_result *res = calloc((size_t)threads, sizeof(struct bench_result));
    struct thread_arg *args = calloc((size_t)threads, sizeof(struct thread_arg));
    if (!ths || !res || !args) {
        fprintf(stderr, "[!] alloc failed\n");
        free(ths);
        free(res);
        free(args);
        return;
    }

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
    size_t map_offset = 0;
    int bench_n = 0;
    int pipeline = 0;
    int threads = 1;
    int ring_idx = 0;
    int max_inflight = 0;
    int collect_latency = 0;
    int collect_cost = 0;
    const char *csv_path = "results/ring_metrics.csv";
    const char *label = "ring";
    unsigned ping_timeout_ms = 0;

    const char *delay_env = getenv("CXL_SHM_DELAY_NS");
    if (delay_env && delay_env[0]) {
        errno = 0;
        unsigned long long v = strtoull(delay_env, NULL, 0);
        if (errno == 0) shm_delay_ns = (uint64_t)v;
    }
    const char *offset_env = getenv("CXL_RING_OFFSET");
    if (!offset_env || !offset_env[0]) offset_env = getenv("CXL_SHM_OFFSET");
    if (offset_env && offset_env[0]) {
        unsigned long long v = strtoull(offset_env, NULL, 0);
        if (v > 0) map_offset = (size_t)v;
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--path") && i + 1 < argc) path = argv[++i];
        else if (!strcmp(argv[i], "--map-size") && i + 1 < argc) map_size = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--bench") && i + 1 < argc) bench_n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--map-offset") && i + 1 < argc) map_offset = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--pipeline")) pipeline = 1;
        else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--ring") && i + 1 < argc) ring_idx = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--max-inflight") && i + 1 < argc) max_inflight = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--latency")) collect_latency = 1;
        else if (!strcmp(argv[i], "--cost")) collect_cost = 1;
        else if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--label") && i + 1 < argc) label = argv[++i];
        else if (!strcmp(argv[i], "--secure")) {
            fprintf(stderr, "[!] --secure is not supported with the new TDX SHM layout.\n");
            return 1;
        } else if (!strcmp(argv[i], "--ping-timeout-ms") && i + 1 < argc) ping_timeout_ms = (unsigned)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("Usage: %s [--path <bar2|uio>] [--map-size <bytes>] [--map-offset <bytes>] [--bench N] [--pipeline] [--threads N]\n"
                   "          [--max-inflight N] [--latency] [--cost] [--csv <path>] [--label <name>]\n"
                   "          [--ping-timeout-ms <ms>] (ping mode only; 0=wait forever)\n"
                   "Env:\n"
                   "  CXL_RING_COUNT        : number of rings/regions (default: 1)\n"
                   "  CXL_RING_REGION_SIZE  : bytes per ring region (default: 16M)\n"
                   "  CXL_RING_REGION_BASE  : base offset within the mmap (default: 0)\n",
                   argv[0]);
            return 0;
        }
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    long page = sysconf(_SC_PAGESIZE);
    if (page > 0 && (map_offset % (size_t)page) != 0) {
        fprintf(stderr, "[!] map offset %zu is not page-aligned\n", map_offset);
        return 1;
    }

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        if ((size_t)st.st_size <= map_offset) {
            fprintf(stderr, "[!] map offset %zu exceeds file size %zu\n", map_offset, (size_t)st.st_size);
            close(fd);
            return 1;
        }
        if (map_size > (size_t)st.st_size - map_offset) {
            map_size = (size_t)st.st_size - map_offset;
        }
    }
    if (map_size == 0) {
        fprintf(stderr, "[!] map size is zero after clamping\n");
        close(fd);
        return 1;
    }

    unsigned char *mm = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)map_offset);
    if (mm == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    struct layout lo;
    if (load_layout(mm, map_size, &lo) != 0) {
        fprintf(stderr, "[!] TDX SHM layout not ready.\n");
        fprintf(stderr, "    Start ring-enabled redis-server first, and ensure CXL_RING_COUNT/REGION_SIZE match.\n");
        munmap(mm, map_size);
        close(fd);
        return 1;
    }

    if (ring_idx < 0 || ring_idx >= (int)lo.ring_count) ring_idx = 0;
    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);

    printf("[*] tdx shm ring direct: path=%s map=%zu offset=%zu ring_count=%u region_base=%zu region_size=%zu slots=%u shm_delay_ns=%" PRIu64 "\n",
           path, map_size, map_offset, lo.ring_count, region_base, region_size, lo.rings[ring_idx].slots, shm_delay_ns);

    if (bench_n > 0) {
        run_bench(mm, &lo, bench_n, pipeline, threads, max_inflight, collect_latency, collect_cost, csv_path, label);
    } else {
        uint64_t start_ns = nowns();
        int pushed = 0;
        int ok = 0;
        while (running) {
            if (!pushed) {
                int pr = push_get(mm, &lo.rings[ring_idx], 99, 0);
                if (pr > 0) {
                    pushed = 1;
                } else if (pr < 0) {
                    fprintf(stderr, "[!] push_get failed (ring write error)\n");
                    break;
                }
            }

            if (pushed) {
                int dr = drain_one(mm, &lo.rings[ring_idx], NULL);
                if (dr > 0) {
                    ok = 1;
                    break;
                }
                if (dr < 0) {
                    fprintf(stderr, "[!] ring_pop failed while waiting for ping response\n");
                    break;
                }
            }

            if (ping_timeout_ms > 0) {
                uint64_t now_ns = nowns();
                uint64_t waited_ms = (now_ns - start_ns) / 1000000ULL;
                if (waited_ms >= ping_timeout_ms) {
                    fprintf(stderr, "[!] ping timeout after %u ms\n", ping_timeout_ms);
                    break;
                }
            }

            struct timespec ts = {0, 1000000};
            nanosleep(&ts, NULL);
        }

        if (ok) printf("PING done\n");
        else {
            munmap(mm, map_size);
            close(fd);
            return 1;
        }
    }

    munmap(mm, map_size);
    close(fd);
    return 0;
}
