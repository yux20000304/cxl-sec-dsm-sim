#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "site_ycsb_db_CxlRingClient.h"

#define MAGIC "CXLSHM1\0"
#define VERSION 2
#define MSG_DATA 1

#define SLOT_SIZE 4096

#define OP_GET 1
#define OP_SET 2
#define OP_DEL 3

#define STATUS_OK 0
#define STATUS_MISS 1
#define STATUS_ERR 2

#define CXL_SEC_TABLE_OFF 512
#define CXL_SEC_MAGIC "CXLSEC1\0"
#define CXL_SEC_VERSION 1
#define CXL_SEC_MAX_ENTRIES 16
#define CXL_SEC_MAX_PRINCIPALS 16

#define SEC_PROTO_MAGIC 0x43534543u /* 'CSEC' */
#define SEC_PROTO_VERSION 1
#define SEC_REQ_ACCESS 1

#define SEC_STATUS_OK 0

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

struct ring_info {
    size_t req_off, req_sz;
    size_t resp_off, resp_sz;
    uint32_t slots;
    uint32_t ring_idx;
};

struct layout {
    uint32_t ring_count;
    struct ring_info rings[8];
};

struct ring_handle {
    int fd;
    unsigned char *mm;
    size_t map_size;
    struct layout lo;
    struct ring_info ri;
    uint32_t cid;
    int timeout_ms;

    int secure;
    int sec_fd;
    uint32_t sec_node_id;
    uint64_t sec_principal;
};

static void throw_runtime(JNIEnv *env, const char *msg) {
    jclass ex = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (ex) (*env)->ThrowNew(env, ex, msg);
}

static inline uint64_t nowns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_ms(unsigned ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000U;
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
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

static int socket_connect(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) return -1;

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
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
        lo->rings[i].ring_idx = i;
    }
    return 0;
}

static CxlSecTable *sec_table(unsigned char *mm) {
    return (CxlSecTable *)(mm + CXL_SEC_TABLE_OFF);
}

static const CxlSecEntry *sec_find_entry(unsigned char *mm, uint64_t off, uint64_t len) {
    if (!mm || len == 0) return NULL;
    uint64_t end = off + len;
    if (end < off) return NULL;
    CxlSecTable *t = sec_table(mm);
    if (memcmp(t->magic, CXL_SEC_MAGIC, 8) != 0 || t->version != CXL_SEC_VERSION) return NULL;
    uint32_t n = t->entry_count;
    if (n > CXL_SEC_MAX_ENTRIES) n = CXL_SEC_MAX_ENTRIES;
    for (uint32_t i = 0; i < n; i++) {
        const CxlSecEntry *e = &t->entries[i];
        if (off >= e->start_off && end <= e->end_off) return e;
    }
    return NULL;
}

static int sec_entry_has_principal(const CxlSecEntry *e, uint64_t principal) {
    if (!e) return 0;
    uint32_t n = e->principal_count;
    if (n > CXL_SEC_MAX_PRINCIPALS) n = CXL_SEC_MAX_PRINCIPALS;
    for (uint32_t i = 0; i < n; i++) {
        if (e->principals[i] == principal) return 1;
    }
    return 0;
}

static int sec_wait_table_ready(unsigned char *mm, unsigned timeout_ms) {
    unsigned waited = 0;
    while (waited < timeout_ms) {
        CxlSecTable *t = sec_table(mm);
        if (memcmp(t->magic, CXL_SEC_MAGIC, 8) == 0 && t->version == CXL_SEC_VERSION) return 0;
        sleep_ms(10);
        waited += 10;
    }
    return -1;
}

static int sec_request_access(struct ring_handle *h, uint64_t off, uint32_t len) {
    if (h->sec_fd < 0) return -1;
    struct sec_req req;
    memset(&req, 0, sizeof(req));
    req.magic_be = htonl(SEC_PROTO_MAGIC);
    req.version_be = htons(SEC_PROTO_VERSION);
    req.type_be = htons(SEC_REQ_ACCESS);
    req.principal_be = htobe64(h->sec_principal);
    req.offset_be = htobe64(off);
    req.length_be = htonl(len);

    if (write_full(h->sec_fd, &req, sizeof(req)) != 0) return -1;
    struct sec_resp resp;
    ssize_t r = read_full(h->sec_fd, &resp, sizeof(resp));
    if (r != (ssize_t)sizeof(resp)) return -1;
    uint32_t magic = ntohl(resp.magic_be);
    uint16_t ver = ntohs(resp.version_be);
    uint16_t status = ntohs(resp.status_be);
    if (magic != SEC_PROTO_MAGIC || ver != SEC_PROTO_VERSION || status != SEC_STATUS_OK) return -1;
    return 0;
}

static int sec_ensure_access(struct ring_handle *h, uint64_t off, uint64_t len) {
    if (!h->secure) return 0;
    for (int tries = 0; tries < 3; tries++) {
        const CxlSecEntry *e = sec_find_entry(h->mm, off, len);
        if (!e) return -1;
        if (sec_entry_has_principal(e, h->sec_principal)) return 0;
        if (sec_request_access(h, off, (uint32_t)(len > 0xffffffffu ? 0xffffffffu : len)) != 0) return -1;
        sleep_ms(1);
    }
    return -1;
}

static void sec_crypt(unsigned char *buf,
                      size_t len,
                      uint8_t direction,
                      uint8_t ring_idx,
                      uint64_t seq,
                      const unsigned char key[crypto_stream_chacha20_ietf_KEYBYTES]) {
    unsigned char nonce[crypto_stream_chacha20_ietf_NONCEBYTES];
    memset(nonce, 0, sizeof(nonce));
    nonce[0] = direction;
    nonce[1] = ring_idx;
    memcpy(nonce + 4, &seq, sizeof(seq));
    crypto_stream_chacha20_ietf_xor(buf, buf, (unsigned long long)len, nonce, key);
}

static int ring_push(struct ring_handle *h, const unsigned char *payload, uint32_t len) {
    uint64_t head = 0, tail = 0;
    memcpy(&head, h->mm + h->ri.req_off, 8);
    memcpy(&tail, h->mm + h->ri.req_off + 8, 8);
    if (head - tail >= h->ri.slots) return 0; /* full */
    if (len > SLOT_SIZE - 16) return -1;
    uint64_t idx = head % h->ri.slots;
    size_t slot_off = h->ri.req_off + 16 + idx * SLOT_SIZE;
    uint16_t type = MSG_DATA;
    uint32_t flags = 0, reserved = 0;
    memcpy(h->mm + slot_off, &h->cid, 4);
    memcpy(h->mm + slot_off + 4, &type, 2);
    memcpy(h->mm + slot_off + 6, &flags, 2);
    memcpy(h->mm + slot_off + 8, &len, 4);
    memcpy(h->mm + slot_off + 12, &reserved, 4);
    memcpy(h->mm + slot_off + 16, payload, len);
    if (SLOT_SIZE > 16 + len) memset(h->mm + slot_off + 16 + len, 0, SLOT_SIZE - 16 - len);
    if (h->secure) {
        uint64_t payload_off = (uint64_t)(slot_off + 16);
        size_t crypt_len = SLOT_SIZE - 16;
        if (sec_ensure_access(h, payload_off, crypt_len) != 0) return -1;
        const CxlSecEntry *e = sec_find_entry(h->mm, payload_off, crypt_len);
        if (!e || !sec_entry_has_principal(e, h->sec_principal)) return -1;
        sec_crypt(h->mm + payload_off, crypt_len, 1 /* REQ */, (uint8_t)h->ri.ring_idx, head, e->key);
    }
    head++;
    memcpy(h->mm + h->ri.req_off, &head, 8);
    return 1;
}

static int ring_pop(struct ring_handle *h, unsigned char **payload, uint32_t *len) {
    uint64_t head = 0, tail = 0;
    memcpy(&head, h->mm + h->ri.resp_off, 8);
    memcpy(&tail, h->mm + h->ri.resp_off + 8, 8);
    if (tail == head) return 0;
    uint64_t idx = tail % h->ri.slots;
    size_t slot_off = h->ri.resp_off + 16 + idx * SLOT_SIZE;
    uint32_t cid = 0;
    uint32_t msg_len = 0;
    memcpy(&cid, h->mm + slot_off, 4);
    memcpy(&msg_len, h->mm + slot_off + 8, 4);
    if (h->secure) {
        uint64_t payload_off = (uint64_t)(slot_off + 16);
        size_t crypt_len = SLOT_SIZE - 16;
        if (sec_ensure_access(h, payload_off, crypt_len) != 0) return -1;
        const CxlSecEntry *e = sec_find_entry(h->mm, payload_off, crypt_len);
        if (!e || !sec_entry_has_principal(e, h->sec_principal)) return -1;
        sec_crypt(h->mm + payload_off, crypt_len, 2 /* RESP */, (uint8_t)h->ri.ring_idx, tail, e->key);
    }
    if (msg_len > SLOT_SIZE - 16) msg_len = SLOT_SIZE - 16;
    *payload = h->mm + slot_off + 16;
    *len = msg_len;
    (void)cid; /* single client per ring in YCSB path */
    tail++;
    memcpy(h->mm + h->ri.resp_off + 8, &tail, 8);
    return 1;
}

static int send_req_wait_resp(struct ring_handle *h,
                              const unsigned char *req,
                              uint32_t req_len,
                              unsigned char **resp,
                              uint32_t *resp_len) {
    uint64_t deadline = nowns() + (uint64_t)h->timeout_ms * 1000000ULL;
    while (nowns() < deadline) {
        int r = ring_push(h, req, req_len);
        if (r < 0) return -1;
        if (r == 1) break;
        sleep_ms(1);
    }
    if (nowns() >= deadline) return -1;

    while (nowns() < deadline) {
        int r = ring_pop(h, resp, resp_len);
        if (r < 0) return -1;
        if (r == 1) return 0;
        sleep_ms(1);
    }
    return -1;
}

JNIEXPORT jlong JNICALL Java_site_ycsb_db_CxlRingClient_nativeOpen(JNIEnv *env,
                                                                  jclass cls,
                                                                  jstring jpath,
                                                                  jlong mapSize,
                                                                  jint ringIdx,
                                                                  jboolean secure,
                                                                  jstring jsecMgr,
                                                                  jint secNodeId,
                                                                  jint timeoutMs) {
    (void)cls;
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path) return 0;

    struct ring_handle *h = (struct ring_handle *)calloc(1, sizeof(*h));
    if (!h) {
        (*env)->ReleaseStringUTFChars(env, jpath, path);
        throw_runtime(env, "alloc ring_handle failed");
        return 0;
    }

    h->timeout_ms = timeoutMs > 0 ? timeoutMs : 5000;
    h->fd = open(path, O_RDWR);
    if (h->fd < 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "open(%s) failed: %s", path, strerror(errno));
        (*env)->ReleaseStringUTFChars(env, jpath, path);
        free(h);
        throw_runtime(env, buf);
        return 0;
    }

    struct stat st;
    if (fstat(h->fd, &st) != 0) {
        close(h->fd);
        (*env)->ReleaseStringUTFChars(env, jpath, path);
        free(h);
        throw_runtime(env, "fstat failed");
        return 0;
    }
    size_t ms = (size_t)mapSize;
    if (ms == 0) ms = (size_t)st.st_size;
    if (ms == 0) {
        close(h->fd);
        (*env)->ReleaseStringUTFChars(env, jpath, path);
        free(h);
        throw_runtime(env, "mapSize is 0 (pass cxl.ring.map_size)");
        return 0;
    }
    h->map_size = ms;
    h->mm = mmap(NULL, h->map_size, PROT_READ | PROT_WRITE, MAP_SHARED, h->fd, 0);
    if (h->mm == MAP_FAILED) {
        close(h->fd);
        (*env)->ReleaseStringUTFChars(env, jpath, path);
        free(h);
        throw_runtime(env, "mmap failed");
        return 0;
    }

    if (load_layout(h->mm, &h->lo) != 0) {
        munmap(h->mm, h->map_size);
        close(h->fd);
        (*env)->ReleaseStringUTFChars(env, jpath, path);
        free(h);
        throw_runtime(env, "invalid ring layout (server not ready?)");
        return 0;
    }

    if (ringIdx < 0 || (uint32_t)ringIdx >= h->lo.ring_count) {
        munmap(h->mm, h->map_size);
        close(h->fd);
        (*env)->ReleaseStringUTFChars(env, jpath, path);
        free(h);
        throw_runtime(env, "ringIdx out of range");
        return 0;
    }

    h->ri = h->lo.rings[(uint32_t)ringIdx];
    h->cid = (uint32_t)getpid();

    h->secure = (secure == JNI_TRUE) ? 1 : 0;
    h->sec_fd = -1;
    if (h->secure) {
        const char *secMgr = NULL;
        if (jsecMgr) secMgr = (*env)->GetStringUTFChars(env, jsecMgr, NULL);
        if (!secMgr || !secMgr[0]) {
            if (secMgr) (*env)->ReleaseStringUTFChars(env, jsecMgr, secMgr);
            munmap(h->mm, h->map_size);
            close(h->fd);
            (*env)->ReleaseStringUTFChars(env, jpath, path);
            free(h);
            throw_runtime(env, "secure mode requires secMgr");
            return 0;
        }

        if (sodium_init() < 0) {
            (*env)->ReleaseStringUTFChars(env, jsecMgr, secMgr);
            munmap(h->mm, h->map_size);
            close(h->fd);
            (*env)->ReleaseStringUTFChars(env, jpath, path);
            free(h);
            throw_runtime(env, "sodium_init failed");
            return 0;
        }

        h->sec_node_id = (uint32_t)secNodeId;
        h->sec_principal = ((uint64_t)h->sec_node_id << 32) | (uint32_t)getpid();

        char *host = NULL, *port = NULL;
        if (parse_hostport(secMgr, &host, &port) != 0) {
            (*env)->ReleaseStringUTFChars(env, jsecMgr, secMgr);
            munmap(h->mm, h->map_size);
            close(h->fd);
            (*env)->ReleaseStringUTFChars(env, jpath, path);
            free(h);
            throw_runtime(env, "invalid secMgr host:port");
            return 0;
        }
        int sfd = socket_connect(host, port);
        free(host);
        free(port);
        if (sfd < 0) {
            (*env)->ReleaseStringUTFChars(env, jsecMgr, secMgr);
            munmap(h->mm, h->map_size);
            close(h->fd);
            (*env)->ReleaseStringUTFChars(env, jpath, path);
            free(h);
            throw_runtime(env, "connect secMgr failed");
            return 0;
        }
        int one = 1;
        setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        h->sec_fd = sfd;

        if (sec_wait_table_ready(h->mm, (unsigned)h->timeout_ms) != 0) {
            close(h->sec_fd);
            h->sec_fd = -1;
            (*env)->ReleaseStringUTFChars(env, jsecMgr, secMgr);
            munmap(h->mm, h->map_size);
            close(h->fd);
            (*env)->ReleaseStringUTFChars(env, jpath, path);
            free(h);
            throw_runtime(env, "timeout waiting for sec table");
            return 0;
        }
        (*env)->ReleaseStringUTFChars(env, jsecMgr, secMgr);
    }

    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return (jlong)(uintptr_t)h;
}

JNIEXPORT void JNICALL Java_site_ycsb_db_CxlRingClient_nativeClose(JNIEnv *env, jclass cls, jlong handle) {
    (void)env;
    (void)cls;
    struct ring_handle *h = (struct ring_handle *)(uintptr_t)handle;
    if (!h) return;
    if (h->secure && h->sec_fd >= 0) close(h->sec_fd);
    if (h->mm && h->mm != MAP_FAILED) munmap(h->mm, h->map_size);
    if (h->fd >= 0) close(h->fd);
    free(h);
}

static int do_kv_raw(JNIEnv *env,
                     struct ring_handle *h,
                     uint8_t op,
                     jbyteArray jkey,
                     jbyteArray jval,
                     unsigned char **resp,
                     uint32_t *resp_len) {
    if (!h) {
        throw_runtime(env, "handle is null");
        return -1;
    }
    jsize klen = (*env)->GetArrayLength(env, jkey);
    if (klen <= 0 || klen > 255) {
        throw_runtime(env, "invalid key length");
        return -1;
    }
    jsize vlen = 0;
    if (jval) vlen = (*env)->GetArrayLength(env, jval);
    if (vlen < 0 || vlen > 65535) {
        throw_runtime(env, "invalid value length");
        return -1;
    }
    if ((uint32_t)(4 + klen + vlen) > (SLOT_SIZE - 16)) {
        throw_runtime(env, "request too large for ring slot");
        return -1;
    }

    unsigned char req[SLOT_SIZE];
    req[0] = op;
    req[1] = (uint8_t)klen;
    req[2] = (uint8_t)(vlen & 0xff);
    req[3] = (uint8_t)((vlen >> 8) & 0xff);
    (*env)->GetByteArrayRegion(env, jkey, 0, klen, (jbyte *)(req + 4));
    if (jval && vlen) {
        (*env)->GetByteArrayRegion(env, jval, 0, vlen, (jbyte *)(req + 4 + klen));
    }

    if (send_req_wait_resp(h, req, (uint32_t)(4 + klen + vlen), resp, resp_len) != 0) {
        throw_runtime(env, "ring request timed out");
        return -1;
    }
    return 0;
}

static int parse_status_resp(JNIEnv *env, unsigned char *resp, uint32_t resp_len) {
    if (resp_len < 4) {
        throw_runtime(env, "short ring response");
        return -1;
    }
    uint8_t status = resp[0];
    uint16_t out_len = (uint16_t)resp[1] | ((uint16_t)resp[2] << 8);
    if ((uint32_t)(4 + out_len) > resp_len) {
        throw_runtime(env, "malformed ring response");
        return -1;
    }
    if (out_len != 0) {
        throw_runtime(env, "unexpected payload in status-only response");
        return -1;
    }
    return (int)status;
}

static jbyteArray parse_get_resp(JNIEnv *env, unsigned char *resp, uint32_t resp_len) {
    if (resp_len < 4) {
        throw_runtime(env, "short ring response");
        return NULL;
    }
    uint8_t status = resp[0];
    uint16_t out_len = (uint16_t)resp[1] | ((uint16_t)resp[2] << 8);
    if ((uint32_t)(4 + out_len) > resp_len) {
        throw_runtime(env, "malformed ring response");
        return NULL;
    }
    if (status == STATUS_MISS) return NULL;
    if (status != STATUS_OK) {
        throw_runtime(env, "ring op failed");
        return NULL;
    }
    jbyteArray out = (*env)->NewByteArray(env, (jsize)out_len);
    if (!out) return NULL;
    if (out_len) (*env)->SetByteArrayRegion(env, out, 0, (jsize)out_len, (jbyte *)(resp + 4));
    return out;
}

JNIEXPORT jbyteArray JNICALL Java_site_ycsb_db_CxlRingClient_nativeGet(JNIEnv *env,
                                                                      jclass cls,
                                                                      jlong handle,
                                                                      jbyteArray key,
                                                                      jint timeoutMs) {
    (void)cls;
    struct ring_handle *h = (struct ring_handle *)(uintptr_t)handle;
    if (h) h->timeout_ms = timeoutMs > 0 ? timeoutMs : h->timeout_ms;
    unsigned char *resp = NULL;
    uint32_t resp_len = 0;
    if (do_kv_raw(env, h, OP_GET, key, NULL, &resp, &resp_len) != 0) return NULL;
    return parse_get_resp(env, resp, resp_len);
}

JNIEXPORT jint JNICALL Java_site_ycsb_db_CxlRingClient_nativeSet(JNIEnv *env,
                                                                 jclass cls,
                                                                 jlong handle,
                                                                 jbyteArray key,
                                                                 jbyteArray value,
                                                                 jint timeoutMs) {
    (void)cls;
    struct ring_handle *h = (struct ring_handle *)(uintptr_t)handle;
    if (h) h->timeout_ms = timeoutMs > 0 ? timeoutMs : h->timeout_ms;
    unsigned char *resp = NULL;
    uint32_t resp_len = 0;
    if (do_kv_raw(env, h, OP_SET, key, value, &resp, &resp_len) != 0) return STATUS_ERR;
    int st = parse_status_resp(env, resp, resp_len);
    return st < 0 ? STATUS_ERR : st;
}

JNIEXPORT jint JNICALL Java_site_ycsb_db_CxlRingClient_nativeDel(JNIEnv *env,
                                                                 jclass cls,
                                                                 jlong handle,
                                                                 jbyteArray key,
                                                                 jint timeoutMs) {
    (void)cls;
    struct ring_handle *h = (struct ring_handle *)(uintptr_t)handle;
    if (h) h->timeout_ms = timeoutMs > 0 ? timeoutMs : h->timeout_ms;
    unsigned char *resp = NULL;
    uint32_t resp_len = 0;
    if (do_kv_raw(env, h, OP_DEL, key, NULL, &resp, &resp_len) != 0) return STATUS_ERR;
    int st = parse_status_resp(env, resp, resp_len);
    return st < 0 ? STATUS_ERR : st;
}
