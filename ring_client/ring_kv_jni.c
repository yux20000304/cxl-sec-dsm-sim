#define _GNU_SOURCE

#include "../tdx_shm/tdx_shm_transport.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jni.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <sodium.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MSG_DATA 1
#define MSG_CLOSE 2

#define OP_GET  1
#define OP_SET  2
#define OP_DEL  3
#define OP_SCAN 4

#define STATUS_OK 0
#define STATUS_MISS 1
#define STATUS_ERR 2

#define MAX_RINGS 8
#define RING_SLOT_HDR_SIZE 16U
#define RING_MAX_PAYLOAD ((uint32_t)TDX_SHM_MSG_MAX - RING_SLOT_HDR_SIZE)

/* Shared-memory security table (cxl_sec_mgr). */
#define CXL_SEC_TABLE_OFF 512
#define CXL_SEC_MAGIC "CXLSEC1\0"
#define CXL_SEC_VERSION 1
#define CXL_SEC_MAX_ENTRIES (MAX_RINGS * 2)
#define CXL_SEC_MAX_PRINCIPALS 16

#define SEC_PROTO_MAGIC 0x43534543u /* 'CSEC' */
#define SEC_PROTO_VERSION 1
#define SEC_REQ_ACCESS 1
#define SEC_STATUS_OK 0

/* ring_slot_hdr.flags */
#define RING_FLAG_SECURE 0x0001u

#define SEC_DIR_REQ 1u  /* client->server */
#define SEC_DIR_RESP 2u /* server->client */

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

struct ring_slot_hdr {
    uint32_t cid;
    uint16_t type;
    uint16_t flags;
    uint32_t len;
    uint32_t reserved;
};

struct ring_info {
    struct tdx_shm_queue_view req;  /* q21 (client -> server) */
    struct tdx_shm_queue_view resp; /* q12 (server -> client) */
    uint32_t ring_idx;
};

struct resp_entry {
    int ready;
    unsigned char *payload;
    uint32_t len;
};

struct ring_state {
    pthread_mutex_t lock;
    struct resp_entry *resp;
    size_t resp_cap;
};

struct ring_layout {
    uint32_t ring_count;
    struct ring_info rings[MAX_RINGS];
};

struct ring_ctx {
    int init;
    pthread_mutex_t init_lock;
    int fd;
    unsigned char *mm;
    size_t map_size;
    size_t map_offset;
    struct ring_layout layout;
    struct ring_state ring_state[MAX_RINGS];

    uint64_t shm_delay_ns;
    uint64_t shm_pause_iters_per_ns_x1024;
    uint64_t poll_spin_ns;
    uint64_t poll_sleep_ns;

    int secure;
    int crypto;
    uint64_t sec_node_id;
    unsigned sec_timeout_ms;
    char sec_mgr[256];
    unsigned char sec_key[MAX_RINGS][crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    int sec_key_ok[MAX_RINGS];
    atomic_uint_fast64_t sec_nonce_ctr_req[MAX_RINGS];

    unsigned char crypto_vm_key[crypto_stream_chacha20_ietf_KEYBYTES];
    unsigned char crypto_common_key[crypto_stream_chacha20_ietf_KEYBYTES];
    size_t crypto_priv_region_base;
    size_t crypto_priv_region_size;
    unsigned char *crypto_priv;
    atomic_uint_fast64_t crypto_priv_nonce_ctr[MAX_RINGS];
};

struct client_handle {
    uint32_t cid;
    int ring_idx;
};

static struct ring_ctx g_ctx = {0};
static atomic_uint_fast32_t g_next_cid = 100;

static inline uint64_t nowns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void shm_delay_calibrate(void) {
    if (g_ctx.shm_pause_iters_per_ns_x1024) return;
    const uint64_t iters = 5000000ULL;
    uint64_t start = nowns();
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
    uint64_t dt = nowns() - start;
    if (dt == 0) dt = 1;
    g_ctx.shm_pause_iters_per_ns_x1024 = (iters * 1024ULL) / dt;
    if (g_ctx.shm_pause_iters_per_ns_x1024 == 0) g_ctx.shm_pause_iters_per_ns_x1024 = 1;
}

static inline void shm_delay(void) {
    uint64_t ns = g_ctx.shm_delay_ns;
    if (!ns) return;
    if (!g_ctx.shm_pause_iters_per_ns_x1024) shm_delay_calibrate();
    uint64_t iters = (ns * g_ctx.shm_pause_iters_per_ns_x1024 + 1023ULL) / 1024ULL;
    if (iters == 0) iters = 1;
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
}

static inline void pause_ns(uint64_t ns) {
    if (!ns) return;
    if (!g_ctx.shm_pause_iters_per_ns_x1024) shm_delay_calibrate();
    uint64_t iters = (ns * g_ctx.shm_pause_iters_per_ns_x1024 + 1023ULL) / 1024ULL;
    if (iters == 0) iters = 1;
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
}

static void sleep_ns(uint64_t ns) {
    if (!ns) return;
    struct timespec ts;
    ts.tv_sec = (time_t)(ns / 1000000000ULL);
    ts.tv_nsec = (long)(ns % 1000000000ULL);
    nanosleep(&ts, NULL);
}

static size_t align_up(size_t value, size_t align) {
    return (value + align - 1U) & ~(align - 1U);
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
    if (errno != 0 || x > 0xffffffffULL) return def;
    return (uint32_t)x;
}

static size_t env_size(const char *key, size_t def) {
    const char *v = getenv(key);
    if (!v || !v[0]) return def;
    size_t out = 0;
    if (parse_size(v, &out) != 0) return def;
    return out;
}

static int parse_key_hex(const char *hex, unsigned char *out_key, size_t out_len) {
    if (!hex || !hex[0] || !out_key || out_len == 0) return -1;
    size_t bin_len = 0;
    if (sodium_hex2bin(out_key, out_len, hex, strlen(hex), NULL, &bin_len, NULL) != 0) return -1;
    if (bin_len != out_len) return -1;
    return 0;
}

static uint32_t ring_next(uint32_t v, uint32_t cap) {
    return (v + 1U) % cap;
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

static int load_layout(unsigned char *mm, size_t map_size, struct ring_layout *lo) {
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
    }
    return 0;
}

static int sec_table_ready(const CxlSecTable *t) {
    if (!t) return 0;
    if (memcmp(t->magic, CXL_SEC_MAGIC, 8) != 0) return 0;
    if (t->version != CXL_SEC_VERSION) return 0;
    if (t->entry_count == 0 || t->entry_count > CXL_SEC_MAX_ENTRIES) return 0;
    return 1;
}

static int sec_entry_has_principal(const CxlSecEntry *e, uint64_t principal) {
    if (!e || principal == 0) return 0;
    for (uint32_t i = 0; i < e->principal_count && i < CXL_SEC_MAX_PRINCIPALS; i++) {
        if (e->principals[i] == principal) return 1;
    }
    return 0;
}

static int sec_table_find(const CxlSecTable *t, uint64_t off, uint64_t len, uint32_t *idx_out) {
    if (!t || !idx_out || len == 0) return -1;
    if (!sec_table_ready(t)) return -1;
    for (uint32_t i = 0; i < t->entry_count && i < CXL_SEC_MAX_ENTRIES; i++) {
        const CxlSecEntry *e = &t->entries[i];
        if (off >= e->start_off && (off + len) <= e->end_off) {
            *idx_out = i;
            return 0;
        }
    }
    return -1;
}

static int write_full(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t r = write(fd, p + off, len - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, p + off, len - off);
        if (r == 0) break;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return (off == len) ? 0 : -1;
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

static int sec_mgr_request_access(const char *mgr, uint64_t principal, uint64_t off, uint32_t len) {
    if (!mgr || !mgr[0]) return -1;
    char *host = NULL;
    char *port = NULL;
    if (parse_hostport(mgr, &host, &port) != 0) return -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        free(host);
        free(port);
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        free(host);
        free(port);
        return -1;
    }

    struct sec_req req;
    memset(&req, 0, sizeof(req));
    req.magic_be = htonl(SEC_PROTO_MAGIC);
    req.version_be = htons(SEC_PROTO_VERSION);
    req.type_be = htons(SEC_REQ_ACCESS);
    req.principal_be = htobe64(principal);
    req.offset_be = htobe64(off);
    req.length_be = htonl(len);

    int rc = -1;
    if (write_full(fd, &req, sizeof(req)) != 0) goto out;
    struct sec_resp resp;
    if (read_full(fd, &resp, sizeof(resp)) != 0) goto out;

    uint32_t magic = ntohl(resp.magic_be);
    uint16_t ver = ntohs(resp.version_be);
    uint16_t status = ntohs(resp.status_be);
    if (magic != SEC_PROTO_MAGIC || ver != SEC_PROTO_VERSION) goto out;
    if (status != SEC_STATUS_OK) goto out;
    rc = 0;
out:
    close(fd);
    free(host);
    free(port);
    return rc;
}

static int crypto_priv_init(unsigned char *mm, size_t map_size, const struct ring_layout *lo) {
    if (!g_ctx.crypto) return 0;
    if (!mm || mm == MAP_FAILED || map_size == 0) return -1;
    if (!lo || lo->ring_count == 0 || lo->ring_count > MAX_RINGS) return -1;
    if (g_ctx.sec_node_id == 0) return -1;

    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);

    const size_t slot_stride = (size_t)TDX_SHM_SLOT_SIZE;
    const size_t need_bytes = align_up((size_t)lo->ring_count * slot_stride, 4096U);
    const size_t def_base = align_up(region_base + (size_t)lo->ring_count * region_size, 4096U);
    const size_t base = env_size("CXL_CRYPTO_PRIV_REGION_BASE", def_base);
    const size_t per_node = env_size("CXL_CRYPTO_PRIV_REGION_SIZE", need_bytes);

    if ((base % 4096) != 0 || (per_node % 4096) != 0) return -1;
    if (per_node < need_bytes) return -1;

    uint64_t idx = g_ctx.sec_node_id - 1ULL;
    uint64_t off64 = (uint64_t)base + idx * (uint64_t)per_node;
    if (off64 > (uint64_t)map_size || (uint64_t)per_node > (uint64_t)map_size - off64) return -1;

    g_ctx.crypto_priv_region_base = base;
    g_ctx.crypto_priv_region_size = per_node;
    g_ctx.crypto_priv = mm + (size_t)off64;
    memset(g_ctx.crypto_priv, 0, per_node);
    for (uint32_t i = 0; i < lo->ring_count; i++) {
        atomic_store_explicit(&g_ctx.crypto_priv_nonce_ctr[i], 0, memory_order_relaxed);
    }
    return 0;
}

static int crypto_priv_encrypt_then_decrypt(uint32_t ring_idx,
                                            unsigned dir,
                                            const unsigned char *payload,
                                            uint32_t payload_len,
                                            unsigned char *out,
                                            uint32_t out_cap,
                                            uint32_t *out_len) {
    if (!out || !out_len || !payload) return -1;
    if (!g_ctx.crypto || !g_ctx.crypto_priv) return -1;
    if (ring_idx >= MAX_RINGS) return -1;
    if (payload_len > out_cap) return -1;
    const uint32_t nonce_bytes = crypto_stream_chacha20_ietf_NONCEBYTES;
    if ((size_t)payload_len + (size_t)nonce_bytes > (size_t)TDX_SHM_SLOT_SIZE) return -1;

    unsigned char *slot = g_ctx.crypto_priv + (size_t)ring_idx * (size_t)TDX_SHM_SLOT_SIZE;
    unsigned char *nonce = slot;
    unsigned char *cipher = slot + nonce_bytes;

    shm_delay();
    memset(nonce, 0, nonce_bytes);
    nonce[0] = (unsigned char)(dir & 0xffu);
    nonce[1] = (unsigned char)(ring_idx & 0xffu);
    uint64_t ctr = atomic_fetch_add_explicit(&g_ctx.crypto_priv_nonce_ctr[ring_idx], 1, memory_order_relaxed);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (unsigned char)((ctr >> (8 * i)) & 0xffu);
    }

    memcpy(cipher, payload, payload_len);
    crypto_stream_chacha20_ietf_xor(cipher,
                                    cipher,
                                    (unsigned long long)payload_len,
                                    nonce,
                                    g_ctx.crypto_vm_key);

    shm_delay();
    crypto_stream_chacha20_ietf_xor(out,
                                    cipher,
                                    (unsigned long long)payload_len,
                                    nonce,
                                    g_ctx.crypto_vm_key);
    *out_len = payload_len;
    return 0;
}

static int secure_encrypt(uint32_t ring_idx,
                          uint32_t cid,
                          uint16_t type,
                          uint16_t flags,
                          uint32_t payload_len,
                          const unsigned char *payload,
                          unsigned dir,
                          unsigned char *out,
                          uint32_t out_cap,
                          uint32_t *out_len) {
    if (!out || !out_len || !payload) return -1;
    if (!g_ctx.secure) return -1;
    if (ring_idx >= MAX_RINGS || !g_ctx.sec_key_ok[ring_idx]) return -1;
    if (flags & ~RING_FLAG_SECURE) return -1;

    const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (payload_len > (uint32_t)RING_MAX_PAYLOAD) return -1;
    if (payload_len > (uint32_t)RING_MAX_PAYLOAD - nonce_bytes - tag_bytes) return -1;

    uint32_t clen_total = nonce_bytes + payload_len + tag_bytes;
    if (clen_total > out_cap) return -1;

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = clen_total;
    hdr.reserved = 0;

    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memset(nonce, 0, sizeof(nonce));
    nonce[0] = (unsigned char)(dir & 0xffu);
    nonce[1] = (unsigned char)(ring_idx & 0xffu);
    uint64_t ctr = atomic_fetch_add_explicit(&g_ctx.sec_nonce_ctr_req[ring_idx], 1, memory_order_relaxed);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (unsigned char)((ctr >> (8 * i)) & 0xffu);
    }

    memcpy(out, nonce, nonce_bytes);
    unsigned long long cbytes = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(out + nonce_bytes,
                                                  &cbytes,
                                                  payload,
                                                  (unsigned long long)payload_len,
                                                  (const unsigned char *)&hdr,
                                                  (unsigned long long)sizeof(hdr),
                                                  NULL,
                                                  nonce,
                                                  g_ctx.sec_key[ring_idx]) != 0) {
        return -1;
    }
    if (cbytes != (unsigned long long)(payload_len + tag_bytes)) return -1;
    *out_len = (uint32_t)(nonce_bytes + (uint32_t)cbytes);
    return 0;
}

static int secure_decrypt(uint32_t ring_idx,
                          uint32_t cid,
                          uint16_t type,
                          uint16_t flags,
                          uint32_t payload_len,
                          const unsigned char *payload,
                          unsigned char *out,
                          uint32_t out_cap,
                          uint32_t *out_len) {
    if (!out || !out_len || !payload) return -1;
    if (!g_ctx.secure) return -1;
    if (ring_idx >= MAX_RINGS || !g_ctx.sec_key_ok[ring_idx]) return -1;

    const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (payload_len < nonce_bytes + tag_bytes) return -1;
    uint32_t clen = payload_len - nonce_bytes;
    if (clen > (uint32_t)RING_MAX_PAYLOAD) return -1;
    if (clen < tag_bytes) return -1;
    uint32_t pmax = clen - tag_bytes;
    if (pmax > out_cap) return -1;

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = payload_len;
    hdr.reserved = 0;

    const unsigned char *nonce = payload;
    const unsigned char *cipher = payload + nonce_bytes;
    unsigned long long pbytes = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(out,
                                                  &pbytes,
                                                  NULL,
                                                  cipher,
                                                  (unsigned long long)clen,
                                                  (const unsigned char *)&hdr,
                                                  (unsigned long long)sizeof(hdr),
                                                  nonce,
                                                  g_ctx.sec_key[ring_idx]) != 0) {
        return -1;
    }
    if (pbytes > (unsigned long long)out_cap) return -1;
    *out_len = (uint32_t)pbytes;
    return 0;
}

static int secure_init(unsigned char *mm, size_t map_size, const struct ring_layout *lo) {
    if (!g_ctx.secure) return 0;
    if (g_ctx.sec_node_id == 0) return -1;
    if (sodium_init() < 0) return -1;

    if (!lo || lo->ring_count == 0 || lo->ring_count > MAX_RINGS) return -1;

    memset(g_ctx.sec_key_ok, 0, sizeof(g_ctx.sec_key_ok));

    if (g_ctx.crypto) {
        const char *crypto_key_hex = getenv("CXL_SEC_KEY_HEX");
        const char *crypto_common_hex = getenv("CXL_SEC_COMMON_KEY_HEX");
        if (!crypto_key_hex || !crypto_common_hex) return -1;
        if (parse_key_hex(crypto_key_hex, g_ctx.crypto_vm_key, sizeof(g_ctx.crypto_vm_key)) != 0) return -1;
        if (parse_key_hex(crypto_common_hex, g_ctx.crypto_common_key, sizeof(g_ctx.crypto_common_key)) != 0) return -1;
        for (uint32_t i = 0; i < lo->ring_count; i++) {
            memcpy(g_ctx.sec_key[i], g_ctx.crypto_common_key, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            g_ctx.sec_key_ok[i] = 1;
            atomic_store_explicit(&g_ctx.sec_nonce_ctr_req[i], 0, memory_order_relaxed);
        }
        if (crypto_priv_init(mm, map_size, lo) != 0) return -1;
        return 0;
    }

    if (!g_ctx.sec_mgr[0]) return -1;

    size_t region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    size_t region_base = env_size("CXL_RING_REGION_BASE", 0);
    if (region_base < 4096) return -1;
    if (map_size < CXL_SEC_TABLE_OFF + sizeof(CxlSecTable)) return -1;

    const CxlSecTable *t = (const CxlSecTable *)(mm + CXL_SEC_TABLE_OFF);
    unsigned waited = 0;
    while (1) {
        if (sec_table_ready(t)) break;
        if (waited >= g_ctx.sec_timeout_ms) break;
        sleep_ns(10ULL * 1000000ULL);
        waited += 10;
    }
    if (!sec_table_ready(t)) return -1;

    for (uint32_t i = 0; i < lo->ring_count; i++) {
        uint64_t off = (uint64_t)region_base + (uint64_t)i * (uint64_t)region_size;
        uint32_t idx = 0;
        if (sec_table_find(t, off, 1, &idx) != 0) return -1;

        unsigned waited2 = 0;
        while (1) {
            if (sec_entry_has_principal(&t->entries[idx], g_ctx.sec_node_id)) break;
            (void)sec_mgr_request_access(g_ctx.sec_mgr, g_ctx.sec_node_id, off, 1);
            if (waited2 >= g_ctx.sec_timeout_ms) break;
            sleep_ns(10ULL * 1000000ULL);
            waited2 += 10;
        }
        if (!sec_entry_has_principal(&t->entries[idx], g_ctx.sec_node_id)) return -1;

        memcpy(g_ctx.sec_key[i], t->entries[idx].key, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        g_ctx.sec_key_ok[i] = 1;
        atomic_store_explicit(&g_ctx.sec_nonce_ctr_req[i], 0, memory_order_relaxed);
    }
    return 0;
}

static int ring_push(const struct ring_info *ri, uint32_t cid, uint16_t type, uint16_t flags, const unsigned char *payload, uint32_t len) {
    shm_delay();
    if (!ri || !ri->req.q || !ri->req.data || !payload) return -1;
    if (len > RING_MAX_PAYLOAD) return -1;

    struct tdx_shm_queue *q = ri->req.q;
    uint32_t cap = q->capacity;
    uint32_t head = atomic_load_explicit(&q->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint32_t next = ring_next(tail, cap);
    if (next == head) return 0;

    uint8_t *slot = ri->req.data + ((size_t)tail * q->slot_size);
    uint16_t msg_len = (uint16_t)(RING_SLOT_HDR_SIZE + len);
    memcpy(slot, &msg_len, sizeof(msg_len));

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = len;
    hdr.reserved = 0;
    memcpy(slot + sizeof(msg_len), &hdr, sizeof(hdr));
    if (len) memcpy(slot + sizeof(msg_len) + sizeof(hdr), payload, len);

    atomic_store_explicit(&q->tail, next, memory_order_release);
    return 1;
}

static int ring_pop(const struct ring_info *ri, uint32_t *cid, uint16_t *type, uint16_t *flags, unsigned char **payload, uint32_t *len) {
    shm_delay();
    if (!ri || !ri->resp.q || !ri->resp.data || !cid || !type || !flags || !payload || !len) return -1;

    struct tdx_shm_queue *q = ri->resp.q;
    uint32_t cap = q->capacity;
    uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    if (head == tail) return 0;

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
    *flags = hdr.flags;
    *len = hdr.len;
    *payload = slot + sizeof(msg_len) + sizeof(hdr);

    atomic_store_explicit(&q->head, ring_next(head, cap), memory_order_release);
    return 1;
}

static int resp_map_ensure(struct ring_state *rs, uint32_t cid) {
    if (!rs) return -1;
    if (cid < rs->resp_cap) return 0;
    size_t ncap = rs->resp_cap ? rs->resp_cap : 1024;
    while (cid >= ncap) ncap *= 2;
    struct resp_entry *nr = (struct resp_entry *)realloc(rs->resp, ncap * sizeof(*nr));
    if (!nr) return -1;
    for (size_t i = rs->resp_cap; i < ncap; i++) {
        nr[i].ready = 0;
        nr[i].payload = NULL;
        nr[i].len = 0;
    }
    rs->resp = nr;
    rs->resp_cap = ncap;
    return 0;
}

static void resp_store_raw(struct ring_state *rs, uint32_t cid, const unsigned char *payload, uint32_t len) {
    if (!rs) return;
    if (resp_map_ensure(rs, cid) != 0) return;
    struct resp_entry *e = &rs->resp[cid];
    if (e->payload) {
        free(e->payload);
        e->payload = NULL;
    }
    e->len = 0;
    if (len && payload) {
        e->payload = (unsigned char *)malloc(len);
        if (e->payload) {
            memcpy(e->payload, payload, len);
            e->len = len;
        }
    }
    e->ready = 1;
}

static int resp_take_raw(struct ring_state *rs, uint32_t cid, unsigned char *out, uint32_t out_cap, uint32_t *out_len) {
    if (!rs || cid >= rs->resp_cap) return 0;
    struct resp_entry *e = &rs->resp[cid];
    if (!e->ready) return 0;
    if (out_len) *out_len = e->len;
    if (out && e->payload && e->len <= out_cap) {
        memcpy(out, e->payload, e->len);
    }
    if (e->payload) {
        free(e->payload);
        e->payload = NULL;
    }
    e->ready = 0;
    e->len = 0;
    return 1;
}

static int payload_in_map(const unsigned char *payload, uint32_t len) {
    if (!payload || !g_ctx.mm || g_ctx.map_size == 0) return 0;
    uintptr_t base = (uintptr_t)g_ctx.mm;
    uintptr_t end = base + g_ctx.map_size;
    uintptr_t start = (uintptr_t)payload;
    if (start < base || start >= end) return 0;
    if (len > (uint32_t)(end - start)) return 0;
    return 1;
}

static int ring_send_set(struct ring_state *rs,
                         const struct ring_info *ri,
                         uint32_t cid,
                         const unsigned char *key,
                         uint8_t klen,
                         const unsigned char *val,
                         uint16_t vlen) {
    if (!rs || !ri || !key || klen == 0) return -1;
    size_t need = 4U + (size_t)klen + (size_t)vlen;
    if (need > (size_t)RING_MAX_PAYLOAD) return -1;

    unsigned char buf[TDX_SHM_SLOT_SIZE];
    buf[0] = OP_SET;
    buf[1] = klen;
    buf[2] = (uint8_t)(vlen & 0xff);
    buf[3] = (uint8_t)((vlen >> 8) & 0xff);
    memcpy(buf + 4, key, klen);
    if (vlen && val) memcpy(buf + 4 + klen, val, vlen);

    if (!g_ctx.secure) {
        return ring_push(ri, cid, MSG_DATA, 0, buf, (uint32_t)need);
    }

    unsigned char enc[RING_MAX_PAYLOAD];
    uint32_t enc_len = 0;
    const unsigned char *plain = buf;
    uint32_t plain_len = (uint32_t)need;
    unsigned char staged[RING_MAX_PAYLOAD];
    uint32_t staged_len = 0;

    if (g_ctx.crypto) {
        if (crypto_priv_encrypt_then_decrypt(ri->ring_idx,
                                             SEC_DIR_REQ,
                                             buf,
                                             (uint32_t)need,
                                             staged,
                                             (uint32_t)sizeof(staged),
                                             &staged_len) != 0) {
            return -1;
        }
        plain = staged;
        plain_len = staged_len;
    }
    if (secure_encrypt(ri->ring_idx,
                       cid,
                       MSG_DATA,
                       RING_FLAG_SECURE,
                       plain_len,
                       plain,
                       SEC_DIR_REQ,
                       enc,
                       (uint32_t)sizeof(enc),
                       &enc_len) != 0) {
        return -1;
    }
    return ring_push(ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len);
}

static int ring_send_get(struct ring_state *rs,
                         const struct ring_info *ri,
                         uint32_t cid,
                         const unsigned char *key,
                         uint8_t klen) {
    if (!rs || !ri || !key || klen == 0) return -1;
    size_t need = 4U + (size_t)klen;
    if (need > (size_t)RING_MAX_PAYLOAD) return -1;

    unsigned char buf[TDX_SHM_SLOT_SIZE];
    buf[0] = OP_GET;
    buf[1] = klen;
    buf[2] = 0;
    buf[3] = 0;
    memcpy(buf + 4, key, klen);

    if (!g_ctx.secure) {
        return ring_push(ri, cid, MSG_DATA, 0, buf, (uint32_t)need);
    }

    unsigned char enc[RING_MAX_PAYLOAD];
    uint32_t enc_len = 0;
    const unsigned char *plain = buf;
    uint32_t plain_len = (uint32_t)need;
    unsigned char staged[RING_MAX_PAYLOAD];
    uint32_t staged_len = 0;

    if (g_ctx.crypto) {
        if (crypto_priv_encrypt_then_decrypt(ri->ring_idx,
                                             SEC_DIR_REQ,
                                             buf,
                                             (uint32_t)need,
                                             staged,
                                             (uint32_t)sizeof(staged),
                                             &staged_len) != 0) {
            return -1;
        }
        plain = staged;
        plain_len = staged_len;
    }
    if (secure_encrypt(ri->ring_idx,
                       cid,
                       MSG_DATA,
                       RING_FLAG_SECURE,
                       plain_len,
                       plain,
                       SEC_DIR_REQ,
                       enc,
                       (uint32_t)sizeof(enc),
                       &enc_len) != 0) {
        return -1;
    }
    return ring_push(ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len);
}

static int ring_send_del(struct ring_state *rs,
                         const struct ring_info *ri,
                         uint32_t cid,
                         const unsigned char *key,
                         uint8_t klen) {
    if (!rs || !ri || !key || klen == 0) return -1;
    size_t need = 4U + (size_t)klen;
    if (need > (size_t)RING_MAX_PAYLOAD) return -1;

    unsigned char buf[TDX_SHM_SLOT_SIZE];
    buf[0] = OP_DEL;
    buf[1] = klen;
    buf[2] = 0;
    buf[3] = 0;
    memcpy(buf + 4, key, klen);

    if (!g_ctx.secure) {
        return ring_push(ri, cid, MSG_DATA, 0, buf, (uint32_t)need);
    }

    unsigned char enc[RING_MAX_PAYLOAD];
    uint32_t enc_len = 0;
    const unsigned char *plain = buf;
    uint32_t plain_len = (uint32_t)need;
    unsigned char staged[RING_MAX_PAYLOAD];
    uint32_t staged_len = 0;

    if (g_ctx.crypto) {
        if (crypto_priv_encrypt_then_decrypt(ri->ring_idx,
                                             SEC_DIR_REQ,
                                             buf,
                                             (uint32_t)need,
                                             staged,
                                             (uint32_t)sizeof(staged),
                                             &staged_len) != 0) {
            return -1;
        }
        plain = staged;
        plain_len = staged_len;
    }
    if (secure_encrypt(ri->ring_idx,
                       cid,
                       MSG_DATA,
                       RING_FLAG_SECURE,
                       plain_len,
                       plain,
                       SEC_DIR_REQ,
                       enc,
                       (uint32_t)sizeof(enc),
                       &enc_len) != 0) {
        return -1;
    }
    return ring_push(ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len);
}

static int ring_send_scan(struct ring_state *rs,
                          const struct ring_info *ri,
                          uint32_t cid,
                          const unsigned char *key,
                          uint8_t klen,
                          uint64_t cursor,
                          uint16_t count) {
    if (!rs || !ri) return -1;
    size_t need = 4U + (size_t)klen + 10U;
    if (need > (size_t)RING_MAX_PAYLOAD) return -1;

    unsigned char buf[TDX_SHM_SLOT_SIZE];
    buf[0] = OP_SCAN;
    buf[1] = klen;
    buf[2] = 10;
    buf[3] = 0;
    if (klen && key) memcpy(buf + 4, key, klen);
    unsigned char *p = buf + 4 + klen;
    p[0] = (uint8_t)(cursor & 0xff);
    p[1] = (uint8_t)((cursor >> 8) & 0xff);
    p[2] = (uint8_t)((cursor >> 16) & 0xff);
    p[3] = (uint8_t)((cursor >> 24) & 0xff);
    p[4] = (uint8_t)((cursor >> 32) & 0xff);
    p[5] = (uint8_t)((cursor >> 40) & 0xff);
    p[6] = (uint8_t)((cursor >> 48) & 0xff);
    p[7] = (uint8_t)((cursor >> 56) & 0xff);
    p[8] = (uint8_t)(count & 0xff);
    p[9] = (uint8_t)((count >> 8) & 0xff);

    if (!g_ctx.secure) {
        return ring_push(ri, cid, MSG_DATA, 0, buf, (uint32_t)need);
    }

    unsigned char enc[RING_MAX_PAYLOAD];
    uint32_t enc_len = 0;
    const unsigned char *plain = buf;
    uint32_t plain_len = (uint32_t)need;
    unsigned char staged[RING_MAX_PAYLOAD];
    uint32_t staged_len = 0;

    if (g_ctx.crypto) {
        if (crypto_priv_encrypt_then_decrypt(ri->ring_idx,
                                             SEC_DIR_REQ,
                                             buf,
                                             (uint32_t)need,
                                             staged,
                                             (uint32_t)sizeof(staged),
                                             &staged_len) != 0) {
            return -1;
        }
        plain = staged;
        plain_len = staged_len;
    }
    if (secure_encrypt(ri->ring_idx,
                       cid,
                       MSG_DATA,
                       RING_FLAG_SECURE,
                       plain_len,
                       plain,
                       SEC_DIR_REQ,
                       enc,
                       (uint32_t)sizeof(enc),
                       &enc_len) != 0) {
        return -1;
    }
    return ring_push(ri, cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len);
}

static int ring_wait_response_raw(struct ring_state *rs,
                                  const struct ring_info *ri,
                                  uint32_t expect_cid,
                                  unsigned char *out,
                                  uint32_t out_cap,
                                  uint32_t *out_len) {
    if (!rs || !ri) return -1;
    for (;;) {
        pthread_mutex_lock(&rs->lock);
        if (resp_take_raw(rs, expect_cid, out, out_cap, out_len)) {
            pthread_mutex_unlock(&rs->lock);
            return 0;
        }

        uint32_t cid = 0;
        uint16_t type = 0;
        uint16_t flags = 0;
        unsigned char *payload = NULL;
        uint32_t len = 0;
        int r = ring_pop(ri, &cid, &type, &flags, &payload, &len);
        if (r == 0) {
            pthread_mutex_unlock(&rs->lock);
            pause_ns(g_ctx.poll_spin_ns);
            sleep_ns(g_ctx.poll_sleep_ns);
            continue;
        }
        if (r < 0) {
            pthread_mutex_unlock(&rs->lock);
            return -1;
        }

        if (type != MSG_DATA || len == 0) {
            pthread_mutex_unlock(&rs->lock);
            continue;
        }

        unsigned char local[RING_MAX_PAYLOAD];
        if (!payload_in_map(payload, len) || len > sizeof(local)) {
            pthread_mutex_unlock(&rs->lock);
            return -1;
        }
        memcpy(local, payload, len);

        unsigned char dec[RING_MAX_PAYLOAD];
        unsigned char *plain = local;
        uint32_t plain_len = len;
        if (g_ctx.secure) {
            if ((flags & RING_FLAG_SECURE) == 0) {
                pthread_mutex_unlock(&rs->lock);
                continue;
            }
            uint32_t dl = 0;
            if (secure_decrypt(ri->ring_idx, cid, type, flags, len, local, dec, (uint32_t)sizeof(dec), &dl) != 0) {
                pthread_mutex_unlock(&rs->lock);
                return -1;
            }
            plain = dec;
            plain_len = dl;
        }

        if (cid == expect_cid) {
            if (out_len) *out_len = plain_len;
            if (out && plain_len <= out_cap) memcpy(out, plain, plain_len);
            pthread_mutex_unlock(&rs->lock);
            return 0;
        }
        resp_store_raw(rs, cid, plain, plain_len);
        pthread_mutex_unlock(&rs->lock);
    }
}

static int parse_kv_response(const unsigned char *payload,
                             uint32_t payload_len,
                             uint8_t *out_status,
                             unsigned char *out,
                             uint32_t out_cap,
                             uint32_t *out_len) {
    if (!payload || payload_len < 4) return -1;
    uint8_t status = payload[0];
    uint16_t vlen = (uint16_t)payload[1] | ((uint16_t)payload[2] << 8);
    if (4U + vlen > payload_len) return -1;
    if (out_status) *out_status = status;
    if (out_len) *out_len = vlen;
    if (out && vlen <= out_cap) {
        memcpy(out, payload + 4, vlen);
    }
    return 0;
}

static int ring_wait_response_getset(struct ring_state *rs,
                                     const struct ring_info *ri,
                                     uint32_t expect_cid,
                                     uint8_t *out_status,
                                     unsigned char *out,
                                     uint32_t out_cap,
                                     uint32_t *out_len) {
    unsigned char tmp[RING_MAX_PAYLOAD];
    uint32_t plen = 0;
    if (ring_wait_response_raw(rs, ri, expect_cid, tmp, sizeof(tmp), &plen) != 0) {
        return -1;
    }
    return parse_kv_response(tmp, plen, out_status, out, out_cap, out_len);
}

static int ring_global_init(void) {
    pthread_mutex_lock(&g_ctx.init_lock);
    if (g_ctx.init) {
        pthread_mutex_unlock(&g_ctx.init_lock);
        return 0;
    }

    const char *path = getenv("CXL_RING_PATH");
    if (!path || !path[0]) {
        pthread_mutex_unlock(&g_ctx.init_lock);
        return -1;
    }

    size_t map_size = env_size("CXL_RING_MAP_SIZE", 0);
    size_t map_offset = 0;
    const char *mo = getenv("CXL_RING_OFFSET");
    if (!mo || !mo[0]) mo = getenv("CXL_SHM_OFFSET");
    if (mo && mo[0]) {
        size_t v = 0;
        if (parse_size(mo, &v) == 0 && v > 0) map_offset = v;
    }

    g_ctx.fd = open(path, O_RDWR);
    if (g_ctx.fd < 0) {
        pthread_mutex_unlock(&g_ctx.init_lock);
        return -1;
    }

    struct stat st;
    if (fstat(g_ctx.fd, &st) != 0) {
        close(g_ctx.fd);
        g_ctx.fd = -1;
        pthread_mutex_unlock(&g_ctx.init_lock);
        return -1;
    }
    g_ctx.map_size = map_size ? map_size : (size_t)st.st_size;
    g_ctx.map_offset = map_offset;

    long page = sysconf(_SC_PAGESIZE);
    if (page > 0 && (g_ctx.map_offset % (size_t)page) != 0) {
        close(g_ctx.fd);
        g_ctx.fd = -1;
        pthread_mutex_unlock(&g_ctx.init_lock);
        return -1;
    }

    if ((size_t)st.st_size <= g_ctx.map_offset) {
        close(g_ctx.fd);
        g_ctx.fd = -1;
        pthread_mutex_unlock(&g_ctx.init_lock);
        return -1;
    }
    if (g_ctx.map_size > (size_t)st.st_size - g_ctx.map_offset) {
        g_ctx.map_size = (size_t)st.st_size - g_ctx.map_offset;
    }

    g_ctx.mm = mmap(NULL, g_ctx.map_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_ctx.fd, (off_t)g_ctx.map_offset);
    if (g_ctx.mm == MAP_FAILED) {
        close(g_ctx.fd);
        g_ctx.fd = -1;
        pthread_mutex_unlock(&g_ctx.init_lock);
        return -1;
    }

    if (load_layout(g_ctx.mm, g_ctx.map_size, &g_ctx.layout) != 0) {
        munmap(g_ctx.mm, g_ctx.map_size);
        close(g_ctx.fd);
        g_ctx.fd = -1;
        pthread_mutex_unlock(&g_ctx.init_lock);
        return -1;
    }

    for (uint32_t i = 0; i < g_ctx.layout.ring_count; i++) {
        pthread_mutex_init(&g_ctx.ring_state[i].lock, NULL);
        g_ctx.ring_state[i].resp = NULL;
        g_ctx.ring_state[i].resp_cap = 0;
    }

    g_ctx.shm_delay_ns = 0;
    const char *delay_ns = getenv("CXL_SHM_DELAY_NS");
    if (delay_ns && delay_ns[0]) {
        errno = 0;
        unsigned long long v = strtoull(delay_ns, NULL, 0);
        if (errno == 0) g_ctx.shm_delay_ns = (uint64_t)v;
    }
    g_ctx.poll_spin_ns = env_size("CXL_RING_POLL_SPIN_NS", 5000);
    g_ctx.poll_sleep_ns = env_size("CXL_RING_POLL_SLEEP_NS", 50000);

    g_ctx.secure = 0;
    g_ctx.crypto = 0;
    g_ctx.sec_node_id = 0;
    g_ctx.sec_timeout_ms = 10000;
    g_ctx.sec_mgr[0] = '\0';

    const char *sec_enable = getenv("CXL_SEC_ENABLE");
    if (sec_enable && sec_enable[0] && strtoull(sec_enable, NULL, 0) != 0) g_ctx.secure = 1;
    const char *sid = getenv("CXL_SEC_NODE_ID");
    if (sid && sid[0]) g_ctx.sec_node_id = strtoull(sid, NULL, 0);
    const char *stm = getenv("CXL_SEC_TIMEOUT_MS");
    if (stm && stm[0]) g_ctx.sec_timeout_ms = (unsigned)strtoul(stm, NULL, 0);
    const char *mgr = getenv("CXL_SEC_MGR");
    if (mgr && mgr[0]) {
        snprintf(g_ctx.sec_mgr, sizeof(g_ctx.sec_mgr), "%s", mgr);
    }
    if (g_ctx.secure) {
        const char *crypto_key = getenv("CXL_SEC_KEY_HEX");
        const char *crypto_common = getenv("CXL_SEC_COMMON_KEY_HEX");
        if (crypto_key && crypto_key[0] && crypto_common && crypto_common[0]) g_ctx.crypto = 1;
    }

    if (secure_init(g_ctx.mm, g_ctx.map_size, &g_ctx.layout) != 0) {
        munmap(g_ctx.mm, g_ctx.map_size);
        close(g_ctx.fd);
        g_ctx.fd = -1;
        pthread_mutex_unlock(&g_ctx.init_lock);
        return -1;
    }

    g_ctx.init = 1;
    pthread_mutex_unlock(&g_ctx.init_lock);
    return 0;
}

JNIEXPORT jlong JNICALL Java_site_ycsb_db_RingKVClient_nativeOpen(JNIEnv *env, jclass cls, jint ring_idx) {
    (void)env;
    (void)cls;
    if (ring_global_init() != 0) return 0;
    if (g_ctx.layout.ring_count == 0) return 0;
    int idx = (int)ring_idx;
    if (idx < 0 || idx >= (int)g_ctx.layout.ring_count) idx = 0;
    struct client_handle *h = (struct client_handle *)calloc(1, sizeof(*h));
    if (!h) return 0;
    h->ring_idx = idx;
    h->cid = (uint32_t)atomic_fetch_add_explicit(&g_next_cid, 1, memory_order_relaxed);
    if (h->cid == 0) h->cid = 1;
    return (jlong)(uintptr_t)h;
}

JNIEXPORT void JNICALL Java_site_ycsb_db_RingKVClient_nativeClose(JNIEnv *env, jclass cls, jlong handle) {
    (void)env;
    (void)cls;
    struct client_handle *h = (struct client_handle *)(uintptr_t)handle;
    if (!h) return;
    free(h);
}

JNIEXPORT jlong JNICALL Java_site_ycsb_db_RingKVClient_nativeSet(JNIEnv *env, jclass cls, jlong handle, jbyteArray key, jint key_len, jbyteArray val, jint val_len) {
    (void)cls;
    struct client_handle *h = (struct client_handle *)(uintptr_t)handle;
    if (!h || !key || key_len <= 0) return ((jlong)STATUS_ERR << 32);
    if (val_len < 0) return ((jlong)STATUS_ERR << 32);
    if ((uint32_t)h->ring_idx >= g_ctx.layout.ring_count) return ((jlong)STATUS_ERR << 32);

    jbyte *kbuf = (*env)->GetByteArrayElements(env, key, NULL);
    if (!kbuf) return ((jlong)STATUS_ERR << 32);
    jbyte *vbuf = NULL;
    if (val_len > 0 && val) {
        vbuf = (*env)->GetByteArrayElements(env, val, NULL);
        if (!vbuf) {
            (*env)->ReleaseByteArrayElements(env, key, kbuf, JNI_ABORT);
            return ((jlong)STATUS_ERR << 32);
        }
    }

    struct ring_state *rs = &g_ctx.ring_state[h->ring_idx];
    const struct ring_info *ri = &g_ctx.layout.rings[h->ring_idx];

    int status = STATUS_ERR;
    int sent = 0;
    for (;;) {
        pthread_mutex_lock(&rs->lock);
        int pr = ring_send_set(rs,
                               ri,
                               h->cid,
                               (const unsigned char *)kbuf,
                               (uint8_t)key_len,
                               (const unsigned char *)vbuf,
                               (uint16_t)val_len);
        pthread_mutex_unlock(&rs->lock);
        if (pr > 0) {
            sent = 1;
            break;
        }
        if (pr < 0) break;
        pause_ns(g_ctx.poll_spin_ns);
        sleep_ns(g_ctx.poll_sleep_ns);
    }

    if (sent) {
        uint8_t resp_status = STATUS_ERR;
        if (ring_wait_response_getset(rs, ri, h->cid, &resp_status, NULL, 0, NULL) == 0) {
            status = (int)resp_status;
        }
    }

    if (vbuf) (*env)->ReleaseByteArrayElements(env, val, vbuf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, kbuf, JNI_ABORT);
    return ((jlong)status << 32);
}

JNIEXPORT jlong JNICALL Java_site_ycsb_db_RingKVClient_nativeGet(JNIEnv *env, jclass cls, jlong handle, jbyteArray key, jint key_len, jbyteArray out) {
    (void)cls;
    struct client_handle *h = (struct client_handle *)(uintptr_t)handle;
    if (!h || !key || key_len <= 0) return ((jlong)STATUS_ERR << 32);
    if ((uint32_t)h->ring_idx >= g_ctx.layout.ring_count) return ((jlong)STATUS_ERR << 32);

    jbyte *kbuf = (*env)->GetByteArrayElements(env, key, NULL);
    if (!kbuf) return ((jlong)STATUS_ERR << 32);

    unsigned char *out_buf = NULL;
    jsize out_cap = 0;
    if (out) {
        out_cap = (*env)->GetArrayLength(env, out);
        if (out_cap > 0) {
            out_buf = (unsigned char *)(*env)->GetByteArrayElements(env, out, NULL);
        }
    }

    struct ring_state *rs = &g_ctx.ring_state[h->ring_idx];
    const struct ring_info *ri = &g_ctx.layout.rings[h->ring_idx];

    int status = STATUS_ERR;
    uint32_t val_len = 0;
    int sent = 0;
    for (;;) {
        pthread_mutex_lock(&rs->lock);
        int pr = ring_send_get(rs,
                               ri,
                               h->cid,
                               (const unsigned char *)kbuf,
                               (uint8_t)key_len);
        pthread_mutex_unlock(&rs->lock);
        if (pr > 0) {
            sent = 1;
            break;
        }
        if (pr < 0) break;
        pause_ns(g_ctx.poll_spin_ns);
        sleep_ns(g_ctx.poll_sleep_ns);
    }

    if (sent) {
        uint8_t resp_status = STATUS_ERR;
        if (ring_wait_response_getset(rs, ri, h->cid, &resp_status, out_buf, (uint32_t)out_cap, &val_len) == 0) {
            status = (int)resp_status;
        }
    }

    if (out_buf) (*env)->ReleaseByteArrayElements(env, out, (jbyte *)out_buf, 0);
    (*env)->ReleaseByteArrayElements(env, key, kbuf, JNI_ABORT);
    return ((jlong)status << 32) | (jlong)val_len;
}

JNIEXPORT jlong JNICALL Java_site_ycsb_db_RingKVClient_nativeDelete(JNIEnv *env, jclass cls, jlong handle, jbyteArray key, jint key_len) {
    (void)cls;
    struct client_handle *h = (struct client_handle *)(uintptr_t)handle;
    if (!h || !key || key_len <= 0) return ((jlong)STATUS_ERR << 32);
    if ((uint32_t)h->ring_idx >= g_ctx.layout.ring_count) return ((jlong)STATUS_ERR << 32);

    jbyte *kbuf = (*env)->GetByteArrayElements(env, key, NULL);
    if (!kbuf) return ((jlong)STATUS_ERR << 32);

    struct ring_state *rs = &g_ctx.ring_state[h->ring_idx];
    const struct ring_info *ri = &g_ctx.layout.rings[h->ring_idx];

    int status = STATUS_ERR;
    int sent = 0;
    for (;;) {
        pthread_mutex_lock(&rs->lock);
        int pr = ring_send_del(rs,
                               ri,
                               h->cid,
                               (const unsigned char *)kbuf,
                               (uint8_t)key_len);
        pthread_mutex_unlock(&rs->lock);
        if (pr > 0) {
            sent = 1;
            break;
        }
        if (pr < 0) break;
        pause_ns(g_ctx.poll_spin_ns);
        sleep_ns(g_ctx.poll_sleep_ns);
    }

    if (sent) {
        uint8_t resp_status = STATUS_ERR;
        if (ring_wait_response_getset(rs, ri, h->cid, &resp_status, NULL, 0, NULL) == 0) {
            status = (int)resp_status;
        }
    }

    (*env)->ReleaseByteArrayElements(env, key, kbuf, JNI_ABORT);
    return ((jlong)status << 32);
}

JNIEXPORT jlong JNICALL Java_site_ycsb_db_RingKVClient_nativeScan(JNIEnv *env, jclass cls, jlong handle, jbyteArray key, jint key_len, jlong cursor, jint count, jbyteArray out) {
    (void)cls;
    struct client_handle *h = (struct client_handle *)(uintptr_t)handle;
    if (!h) return ((jlong)STATUS_ERR << 32);
    if ((uint32_t)h->ring_idx >= g_ctx.layout.ring_count) return ((jlong)STATUS_ERR << 32);

    jbyte *kbuf = NULL;
    if (key && key_len > 0) {
        kbuf = (*env)->GetByteArrayElements(env, key, NULL);
        if (!kbuf) return ((jlong)STATUS_ERR << 32);
    }

    unsigned char *out_buf = NULL;
    jsize out_cap = 0;
    if (out) {
        out_cap = (*env)->GetArrayLength(env, out);
        if (out_cap > 0) {
            out_buf = (unsigned char *)(*env)->GetByteArrayElements(env, out, NULL);
        }
    }

    struct ring_state *rs = &g_ctx.ring_state[h->ring_idx];
    const struct ring_info *ri = &g_ctx.layout.rings[h->ring_idx];

    int status = STATUS_ERR;
    uint32_t payload_len = 0;
    int sent = 0;
    for (;;) {
        pthread_mutex_lock(&rs->lock);
        int pr = ring_send_scan(rs,
                                ri,
                                h->cid,
                                (const unsigned char *)kbuf,
                                (uint8_t)((key_len > 0) ? key_len : 0),
                                (uint64_t)cursor,
                                (uint16_t)count);
        pthread_mutex_unlock(&rs->lock);
        if (pr > 0) {
            sent = 1;
            break;
        }
        if (pr < 0) break;
        pause_ns(g_ctx.poll_spin_ns);
        sleep_ns(g_ctx.poll_sleep_ns);
    }

    if (sent) {
        unsigned char tmp[RING_MAX_PAYLOAD];
        uint32_t tmp_len = 0;
        if (ring_wait_response_raw(rs, ri, h->cid, tmp, sizeof(tmp), &tmp_len) == 0) {
            if (tmp_len >= 1) {
                status = (int)tmp[0];
            }
            if (out_buf && out_cap > 0) {
                uint32_t copy_len = (tmp_len > (uint32_t)out_cap) ? (uint32_t)out_cap : tmp_len;
                memcpy(out_buf, tmp, copy_len);
                payload_len = copy_len;
            } else {
                payload_len = tmp_len;
            }
        }
    }

    if (out_buf) (*env)->ReleaseByteArrayElements(env, out, (jbyte *)out_buf, 0);
    if (kbuf) (*env)->ReleaseByteArrayElements(env, key, kbuf, JNI_ABORT);
    return ((jlong)status << 32) | (jlong)payload_len;
}
