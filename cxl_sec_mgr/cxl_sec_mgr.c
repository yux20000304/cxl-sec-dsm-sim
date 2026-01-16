#define _GNU_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define CXL_RING_MAGIC "CXLSHM1\0"
#define CXL_RING_VERSION 2
#define CXL_RING_MAX_RINGS 8

#define GAPBS_GRAPH_MAGIC 0x4C58434353425041ULL /* "APBSCCXL" (LE) */
#define GAPBS_GRAPH_VERSION 1
#define GAPBS_GRAPH_FLAG_HAS_INVERSE (1u << 1)

#define CXL_SEC_TABLE_OFF 512
#define CXL_SEC_MAGIC "CXLSEC1\0"
#define CXL_SEC_VERSION 1
#define CXL_SEC_MAX_ENTRIES (CXL_RING_MAX_RINGS * 2)
#define CXL_SEC_MAX_PRINCIPALS 16

#define SEC_PROTO_MAGIC 0x43534543u /* 'CSEC' */
#define SEC_PROTO_VERSION 1
#define SEC_REQ_ACCESS 1

#define SEC_STATUS_OK 0
#define SEC_STATUS_BAD_REQ 1
#define SEC_STATUS_NOT_READY 2
#define SEC_STATUS_NO_REGION 3
#define SEC_STATUS_TABLE_FULL 4

typedef struct {
    uint64_t start_off;
    uint64_t end_off;
    unsigned char key[crypto_stream_chacha20_ietf_KEYBYTES];
    uint32_t principal_count;
    uint32_t reserved;
    uint64_t principals[CXL_SEC_MAX_PRINCIPALS];
} CxlSecEntry;

typedef struct {
    char magic[8];
    uint32_t version;
    uint32_t entry_count;
    CxlSecEntry entries[CXL_SEC_MAX_ENTRIES];
} CxlSecTable;

struct layout {
    uint32_t region_count;
    struct {
        uint64_t start_off;
        uint64_t end_off;
    } regions[CXL_SEC_MAX_ENTRIES];
    uint64_t total_size;
};

struct sec_req {
    uint32_t magic_be;
    uint16_t version_be;
    uint16_t type_be;
    uint64_t principal_be;
    uint64_t offset_be;
    uint32_t length_be;
    uint32_t reserved_be;
};

struct sec_resp {
    uint32_t magic_be;
    uint16_t version_be;
    uint16_t status_be;
    uint32_t reserved_be;
};

static volatile sig_atomic_t g_running = 1;
static pthread_mutex_t g_table_lock = PTHREAD_MUTEX_INITIALIZER;

static void on_sig(int sig) {
    (void)sig;
    g_running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s --ring <path> --listen <ip:port> [--map-size <bytes>] [--timeout-ms <ms>]\n"
            "\n"
            "Notes:\n"
            "- Auto-detects the shared-memory layout (Redis ring or GAPBS graph).\n"
            "- Initializes a shared-memory ACL table at offset %u in the mapping.\n"
            "- Table entries are address-range based (offsets in the mapping).\n"
            "- Clients request access via a simple TCP protocol.\n",
            prog,
            (unsigned)CXL_SEC_TABLE_OFF);
}

static int parse_hostport(const char *s, char **host_out, char **port_out) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s || *(colon + 1) == '\0') return -1;
    size_t host_len = (size_t)(colon - s);
    char *host = (char *)calloc(host_len + 1, 1);
    char *port = strdup(colon + 1);
    if (!host || !port) {
        free(host);
        free(port);
        return -1;
    }
    memcpy(host, s, host_len);
    host[host_len] = '\0';
    *host_out = host;
    *port_out = port;
    return 0;
}

static int socket_listen(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "[!] getaddrinfo(listen %s:%s): %s\n", host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            if (listen(fd, 128) == 0) break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static ssize_t read_full(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (unsigned char *)buf + off, n - off);
        if (r == 0) return (ssize_t)off;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return (ssize_t)off;
}

static int write_full(int fd, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const unsigned char *)buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static uint64_t load_u64(const unsigned char *p) {
    uint64_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint32_t load_u32(const unsigned char *p) {
    uint32_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

static int load_layout(const unsigned char *mm, uint64_t total_size, struct layout *lo) {
    /* Redis ring layout (CXLSHM1). */
    if (memcmp(mm, CXL_RING_MAGIC, 8) == 0) {
        uint32_t ver = load_u32(mm + 8);
        if (ver != CXL_RING_VERSION) return -1;
        uint32_t ring_count = load_u32(mm + 12);
        if (ring_count == 0 || ring_count > CXL_RING_MAX_RINGS) return -1;
        if (ring_count * 2 > CXL_SEC_MAX_ENTRIES) return -1;

        uint32_t region_count = 0;
        for (uint32_t i = 0; i < ring_count; i++) {
            uint64_t req_off = load_u64(mm + 24 + i * 32);
            uint64_t req_sz = load_u64(mm + 32 + i * 32);
            uint64_t resp_off = load_u64(mm + 40 + i * 32);
            uint64_t resp_sz = load_u64(mm + 48 + i * 32);
            if (req_off == 0 || resp_off == 0) return -1;
            if (req_sz < 4096 || resp_sz < 4096) return -1;
            if (req_off + req_sz > total_size) return -1;
            if (resp_off + resp_sz > total_size) return -1;

            lo->regions[region_count].start_off = req_off;
            lo->regions[region_count].end_off = req_off + req_sz;
            region_count++;
            lo->regions[region_count].start_off = resp_off;
            lo->regions[region_count].end_off = resp_off + resp_sz;
            region_count++;
        }

        lo->region_count = region_count;
        lo->total_size = total_size;
        return 0;
    }

    /* GAPBS graph layout (APBSCCXL). */
    uint64_t magic = load_u64(mm + 0);
    if (magic != GAPBS_GRAPH_MAGIC) return -1;
    uint32_t ver = load_u32(mm + 8);
    if (ver != GAPBS_GRAPH_VERSION) return -1;

    uint32_t flags = load_u32(mm + 12);
    uint64_t num_nodes = load_u64(mm + 16);
    uint64_t num_edges_directed = load_u64(mm + 24);
    uint32_t dest_bytes = load_u32(mm + 32);

    uint64_t out_offsets_off = load_u64(mm + 40);
    uint64_t out_neigh_off = load_u64(mm + 48);
    uint64_t in_offsets_off = load_u64(mm + 56);
    uint64_t in_neigh_off = load_u64(mm + 64);

    if (dest_bytes == 0 || dest_bytes > 4096) return -1;
    if (num_nodes > (UINT64_MAX / 8ULL) - 1ULL) return -1;
    uint64_t offsets_bytes = (num_nodes + 1ULL) * 8ULL; /* SGOffset = int64_t */
    if (num_edges_directed > UINT64_MAX / (uint64_t)dest_bytes) return -1;
    uint64_t neigh_bytes = num_edges_directed * (uint64_t)dest_bytes;

    if (out_offsets_off == 0 || out_neigh_off == 0) return -1;
    if (out_offsets_off + offsets_bytes > total_size) return -1;
    if (out_neigh_off + neigh_bytes > total_size) return -1;

    uint32_t region_count = 0;
    lo->regions[region_count].start_off = out_offsets_off;
    lo->regions[region_count].end_off = out_offsets_off + offsets_bytes;
    region_count++;
    lo->regions[region_count].start_off = out_neigh_off;
    lo->regions[region_count].end_off = out_neigh_off + neigh_bytes;
    region_count++;

    if ((flags & GAPBS_GRAPH_FLAG_HAS_INVERSE) && in_offsets_off && in_neigh_off) {
        if (region_count + 2 > CXL_SEC_MAX_ENTRIES) return -1;
        if (in_offsets_off + offsets_bytes > total_size) return -1;
        if (in_neigh_off + neigh_bytes > total_size) return -1;
        lo->regions[region_count].start_off = in_offsets_off;
        lo->regions[region_count].end_off = in_offsets_off + offsets_bytes;
        region_count++;
        lo->regions[region_count].start_off = in_neigh_off;
        lo->regions[region_count].end_off = in_neigh_off + neigh_bytes;
        region_count++;
    }

    lo->region_count = region_count;
    lo->total_size = total_size;
    return 0;
}

static void sec_table_init(CxlSecTable *t, const struct layout *lo) {
    CxlSecTable tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.version = CXL_SEC_VERSION;
    tmp.entry_count = lo->region_count;
    if (tmp.entry_count > CXL_SEC_MAX_ENTRIES) tmp.entry_count = CXL_SEC_MAX_ENTRIES;

    for (uint32_t i = 0; i < tmp.entry_count; i++) {
        CxlSecEntry *e = &tmp.entries[i];
        e->start_off = lo->regions[i].start_off;
        e->end_off = lo->regions[i].end_off;
        randombytes_buf(e->key, sizeof(e->key));
    }

    /* Commit: copy everything first, then set magic last so readers can treat magic as readiness. */
    memcpy(t, &tmp, sizeof(tmp));
    memcpy(t->magic, CXL_SEC_MAGIC, 8);
}

static int sec_table_find(CxlSecTable *t, uint64_t off, uint64_t len, uint32_t *idx_out) {
    if (!t || memcmp(t->magic, CXL_SEC_MAGIC, 8) != 0 || t->version != CXL_SEC_VERSION) return -1;
    if (len == 0) return -1;
    uint64_t end = off + len;
    if (end < off) return -1; /* overflow */
    uint32_t n = t->entry_count;
    if (n > CXL_SEC_MAX_ENTRIES) n = CXL_SEC_MAX_ENTRIES;
    for (uint32_t i = 0; i < n; i++) {
        CxlSecEntry *e = &t->entries[i];
        if (off >= e->start_off && end <= e->end_off) {
            *idx_out = i;
            return 0;
        }
    }
    return -1;
}

static int sec_entry_has_principal(const CxlSecEntry *e, uint64_t principal) {
    uint32_t n = e->principal_count;
    if (n > CXL_SEC_MAX_PRINCIPALS) n = CXL_SEC_MAX_PRINCIPALS;
    for (uint32_t i = 0; i < n; i++) {
        if (e->principals[i] == principal) return 1;
    }
    return 0;
}

static int sec_entry_add_principal(CxlSecEntry *e, uint64_t principal) {
    if (sec_entry_has_principal(e, principal)) return 0;
    uint32_t n = e->principal_count;
    if (n >= CXL_SEC_MAX_PRINCIPALS) return -1;
    e->principals[n] = principal;
    e->principal_count = n + 1;
    return 0;
}

struct client_ctx {
    int cfd;
    CxlSecTable *table;
};

static void *client_thread(void *arg) {
    struct client_ctx *c = (struct client_ctx *)arg;
    while (g_running) {
        struct sec_req req;
        ssize_t r = read_full(c->cfd, &req, sizeof(req));
        if (r == 0) break;
        if (r != (ssize_t)sizeof(req)) break;

        uint32_t magic = ntohl(req.magic_be);
        uint16_t ver = ntohs(req.version_be);
        uint16_t type = ntohs(req.type_be);
        uint64_t principal = be64toh(req.principal_be);
        uint64_t off = be64toh(req.offset_be);
        uint32_t len = ntohl(req.length_be);

        uint16_t status = SEC_STATUS_OK;

        if (magic != SEC_PROTO_MAGIC || ver != SEC_PROTO_VERSION || type != SEC_REQ_ACCESS) {
            status = SEC_STATUS_BAD_REQ;
        } else if (memcmp(c->table->magic, CXL_SEC_MAGIC, 8) != 0 || c->table->version != CXL_SEC_VERSION) {
            status = SEC_STATUS_NOT_READY;
        } else {
            uint32_t idx = 0;
            if (sec_table_find(c->table, off, (uint64_t)len, &idx) != 0) {
                status = SEC_STATUS_NO_REGION;
            } else {
                pthread_mutex_lock(&g_table_lock);
                int rc = sec_entry_add_principal(&c->table->entries[idx], principal);
                pthread_mutex_unlock(&g_table_lock);
                if (rc != 0) {
                    status = SEC_STATUS_TABLE_FULL;
                }
            }
        }

        struct sec_resp resp;
        memset(&resp, 0, sizeof(resp));
        resp.magic_be = htonl(SEC_PROTO_MAGIC);
        resp.version_be = htons(SEC_PROTO_VERSION);
        resp.status_be = htons(status);
        if (write_full(c->cfd, &resp, sizeof(resp)) != 0) break;
    }
    close(c->cfd);
    free(c);
    return NULL;
}

static void sleep_ms(unsigned ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000U;
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

int main(int argc, char **argv) {
    const char *ring_path = NULL;
    const char *listen = NULL;
    uint64_t map_size = 0;
    unsigned timeout_ms = 10000;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "--ring") && i + 1 < argc) {
            ring_path = argv[++i];
        } else if (!strcmp(argv[i], "--listen") && i + 1 < argc) {
            listen = argv[++i];
        } else if (!strcmp(argv[i], "--map-size") && i + 1 < argc) {
            map_size = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--timeout-ms") && i + 1 < argc) {
            timeout_ms = (unsigned)strtoul(argv[++i], NULL, 0);
        } else {
            fprintf(stderr, "[!] Unknown/invalid arg: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!ring_path || !listen) {
        usage(argv[0]);
        return 2;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "[!] sodium_init failed\n");
        return 1;
    }

    int fd = open(ring_path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[!] open(%s) failed: %s\n", ring_path, strerror(errno));
        return 1;
    }

    struct stat st;
    memset(&st, 0, sizeof(st));
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "[!] fstat(%s) failed: %s\n", ring_path, strerror(errno));
        close(fd);
        return 1;
    }

    uint64_t total_size = (uint64_t)st.st_size;
    if (map_size) total_size = map_size;
    if (total_size < 4096) {
        fprintf(stderr, "[!] ring mapping size too small (need >= 4096). Provide --map-size if fstat reports 0.\n");
        close(fd);
        return 1;
    }

    size_t map_len = 4096;
    unsigned char *mm = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mm == MAP_FAILED) {
        fprintf(stderr, "[!] mmap(%s, %zu) failed: %s\n", ring_path, map_len, strerror(errno));
        close(fd);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    char *lh = NULL, *lp = NULL;
    if (parse_hostport(listen, &lh, &lp) != 0) {
        fprintf(stderr, "[!] Invalid --listen (expected ip:port)\n");
        munmap(mm, map_len);
        close(fd);
        return 2;
    }

    int lfd = socket_listen(lh, lp);
    if (lfd < 0) {
        fprintf(stderr, "[!] listen failed\n");
        free(lh);
        free(lp);
        munmap(mm, map_len);
        close(fd);
        return 1;
    }

    fprintf(stderr, "[*] cxl_sec_mgr: ring=%s listen=%s:%s map_size=%llu\n",
            ring_path,
            lh,
            lp,
            (unsigned long long)total_size);

    free(lh);
    free(lp);

    struct layout lo;
    memset(&lo, 0, sizeof(lo));

    unsigned waited = 0;
    while (g_running) {
        if (load_layout(mm, total_size, &lo) == 0) break;
        if (waited >= timeout_ms) break;
        sleep_ms(10);
        waited += 10;
    }
    if (lo.region_count == 0) {
        fprintf(stderr, "[!] timeout waiting for shared-memory layout header (magic/version)\n");
        close(lfd);
        munmap(mm, map_len);
        close(fd);
        return 1;
    }

    CxlSecTable *t = (CxlSecTable *)(mm + CXL_SEC_TABLE_OFF);
    if (CXL_SEC_TABLE_OFF + sizeof(*t) > map_len) {
        fprintf(stderr, "[!] CXL_SEC_TABLE_OFF too large for mapped header page\n");
        close(lfd);
        munmap(mm, map_len);
        close(fd);
        return 1;
    }

    sec_table_init(t, &lo);

    fprintf(stderr, "[*] cxl_sec_mgr: table initialized (entries=%u, principals_per_entry=%u)\n",
            t->entry_count,
            (unsigned)CXL_SEC_MAX_PRINCIPALS);

    while (g_running) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int cfd = accept(lfd, (struct sockaddr *)&ss, &slen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        struct client_ctx *ctx = (struct client_ctx *)calloc(1, sizeof(*ctx));
        if (!ctx) {
            close(cfd);
            continue;
        }
        ctx->cfd = cfd;
        ctx->table = t;

        pthread_t th;
        if (pthread_create(&th, NULL, client_thread, ctx) != 0) {
            close(cfd);
            free(ctx);
            continue;
        }
        pthread_detach(th);
    }

    close(lfd);
    munmap(mm, map_len);
    close(fd);
    return 0;
}
