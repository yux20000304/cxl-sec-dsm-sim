#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAGIC "CXLSHM1\0"
#define VERSION 1
#define MSG_DATA 1
#define MSG_CLOSE 2

#define DEFAULT_SLOT_SIZE 1024
#define DEFAULT_SLOTS (4096 * 104) /* 425,984 slots */

static volatile int running = 1;

static void handle_sig(int sig) {
    (void)sig;
    running = 0;
}

static size_t align_up(size_t x, size_t a) { return (x + a - 1) / a * a; }

struct ring_cfg {
    uint32_t slot_size;
    uint32_t slots;
    size_t offset;
    size_t size;
};

struct ring {
    volatile uint64_t *head;
    volatile uint64_t *tail;
    unsigned char *slots_base;
    struct ring_cfg cfg;
};

struct conn {
    int fd;
    uint32_t id;
    unsigned char *out_buf;
    size_t out_len;
    size_t out_off;
    struct conn *next;
};

struct ctx {
    int shm_fd;
    unsigned char *mm;
    size_t map_size;
    size_t file_size;
    struct ring req;
    struct ring resp;
    int listen_fd;
    int epfd;
    uint32_t next_id;
    struct conn *conns;
} g;

static void ring_setup(struct ring *r, unsigned char *base, const struct ring_cfg *cfg) {
    r->cfg = *cfg;
    r->head = (uint64_t *)(base + cfg->offset);
    r->tail = (uint64_t *)(base + cfg->offset + sizeof(uint64_t));
    size_t slots_base_off = cfg->offset + align_up(sizeof(uint64_t) * 2, 16);
    r->slots_base = base + slots_base_off;
}

static int ring_push(struct ring *r, uint32_t cid, uint16_t type, const unsigned char *payload, uint32_t len) {
    uint64_t head = *r->head;
    uint64_t tail = *r->tail;
    if (head - tail >= r->cfg.slots) return 0; /* full */
    if (len > r->cfg.slot_size - 16) return -1;
    uint64_t idx = head % r->cfg.slots;
    unsigned char *ptr = r->slots_base + idx * r->cfg.slot_size;
    uint32_t flags = 0, reserved = 0;
    memcpy(ptr, &cid, 4);
    memcpy(ptr + 4, &type, 2);
    memcpy(ptr + 6, &flags, 2);
    memcpy(ptr + 8, &len, 4);
    memcpy(ptr + 12, &reserved, 4);
    memcpy(ptr + 16, payload, len);
    if (r->cfg.slot_size > 16 + len) memset(ptr + 16 + len, 0, r->cfg.slot_size - 16 - len);
    *r->head = head + 1;
    return 1;
}

static int ring_pop(struct ring *r, uint32_t *cid, uint16_t *type, unsigned char **payload, uint32_t *len) {
    uint64_t head = *r->head;
    uint64_t tail = *r->tail;
    if (tail == head) return 0;
    uint64_t idx = tail % r->cfg.slots;
    unsigned char *ptr = r->slots_base + idx * r->cfg.slot_size;
    memcpy(cid, ptr, 4);
    memcpy(type, ptr + 4, 2);
    memcpy(len, ptr + 8, 4);
    if (*len > r->cfg.slot_size - 16) *len = r->cfg.slot_size - 16;
    *payload = ptr + 16;
    *r->tail = tail + 1;
    return 1;
}

static int init_layout(size_t map_size) {
    unsigned char *p = g.mm;
    uint32_t ver = 0, resv = 0;
    uint64_t fsize = 0, req_off = 0, req_sz = 0, resp_off = 0, resp_sz = 0;
    memcpy(&ver, p + 8, 4);
    memcpy(&fsize, p + 16, 8);
    memcpy(&req_off, p + 24, 8);
    memcpy(&req_sz, p + 32, 8);
    memcpy(&resp_off, p + 40, 8);
    memcpy(&resp_sz, p + 48, 8);
    if (memcmp(p, MAGIC, 8) != 0 || ver != VERSION) {
        size_t header_size = 8 + 4 + 4 + 8 * 5;
        size_t header_aligned = align_up(header_size, 4096);
        size_t slots = DEFAULT_SLOTS;
        size_t slot_size = DEFAULT_SLOT_SIZE;
        size_t ring_sz = align_up(16 + slot_size * slots, 4096);
        while (slots > 1 && header_aligned + 2 * ring_sz > map_size) {
            slots /= 2;
            ring_sz = align_up(16 + slot_size * slots, 4096);
        }
        req_off = header_aligned;
        req_sz = ring_sz;
        resp_off = align_up(req_off + req_sz, 4096);
        resp_sz = ring_sz;
        memcpy(p, MAGIC, 8);
        ver = VERSION;
        memcpy(p + 8, &ver, 4);
        memcpy(p + 12, &resv, 4);
        memcpy(p + 16, &g.file_size, 8);
        memcpy(p + 24, &req_off, 8);
        memcpy(p + 32, &req_sz, 8);
        memcpy(p + 40, &resp_off, 8);
        memcpy(p + 48, &resp_sz, 8);
        memset(p + header_aligned, 0, 16);
        memset(p + resp_off, 0, 16);
    }
    struct ring_cfg rcfg = {.slot_size = DEFAULT_SLOT_SIZE, .slots = (req_sz > 16 ? (req_sz - 16) / DEFAULT_SLOT_SIZE : 1), .offset = req_off, .size = req_sz};
    struct ring_cfg wcfg = {.slot_size = DEFAULT_SLOT_SIZE, .slots = (resp_sz > 16 ? (resp_sz - 16) / DEFAULT_SLOT_SIZE : 1), .offset = resp_off, .size = resp_sz};
    ring_setup(&g.req, g.mm, &rcfg);
    ring_setup(&g.resp, g.mm, &wcfg);
    /* Reset ring positions on each attach to avoid stale data between runs. */
    *g.req.head = *g.req.tail = 0;
    *g.resp.head = *g.resp.tail = 0;
    return 0;
}

static int shm_init(const char *path, size_t map_size, size_t map_offset) {
    long page = sysconf(_SC_PAGESIZE);
    if (page > 0 && (map_offset % (size_t)page) != 0) {
        fprintf(stderr, "map offset %zu is not page-aligned\n", map_offset);
        return -1;
    }
    g.shm_fd = open(path, O_RDWR);
    if (g.shm_fd < 0) {
        fprintf(stderr, "open %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(g.shm_fd, &st) != 0) {
        fprintf(stderr, "fstat failed: %s\n", strerror(errno));
        return -1;
    }
    g.file_size = st.st_size;
    if (S_ISREG(st.st_mode)) {
        if ((size_t)st.st_size <= map_offset) {
            fprintf(stderr, "map offset %zu exceeds file size %zu\n",
                    map_offset, (size_t)st.st_size);
            return -1;
        }
        if (map_size > (size_t)st.st_size - map_offset) {
            map_size = (size_t)st.st_size - map_offset;
        }
    }
    g.map_size = map_size;
    g.mm = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, g.shm_fd, (off_t)map_offset);
    if (g.mm == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return -1;
    }
    return init_layout(map_size);
}

static int make_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl == -1) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static struct conn *conn_add(int fd) {
    struct conn *c = calloc(1, sizeof(*c));
    c->fd = fd;
    c->id = g.next_id++;
    c->next = g.conns;
    g.conns = c;
    return c;
}

static struct conn *conn_find(uint32_t id) {
    for (struct conn *c = g.conns; c; c = c->next) if (c->id == id) return c;
    return NULL;
}

static void conn_remove(struct conn *c) {
    if (!c) return;
    epoll_ctl(g.epfd, EPOLL_CTL_DEL, c->fd, NULL);
    struct conn *prev = NULL, *cur = g.conns;
    while (cur && cur != c) { prev = cur; cur = cur->next; }
    if (cur) {
        if (prev) prev->next = cur->next;
        else g.conns = cur->next;
    }
    if (c->fd >= 0) close(c->fd);
    free(c->out_buf);
    free(c);
}

static int setup_listener(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return -1;
    if (listen(fd, 128) != 0) return -1;
    make_nonblock(fd);
    return fd;
}

static void epoll_add(int fd, uint32_t events, void *ptr) {
    struct epoll_event ev = {.events = events, .data.ptr = ptr};
    epoll_ctl(g.epfd, EPOLL_CTL_ADD, fd, &ev);
}

static void epoll_mod(int fd, uint32_t events, void *ptr) {
    struct epoll_event ev = {.events = events, .data.ptr = ptr};
    epoll_ctl(g.epfd, EPOLL_CTL_MOD, fd, &ev);
}

static void handle_accept(void) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int fd = accept(g.listen_fd, (struct sockaddr *)&addr, &len);
    if (fd < 0) return;
    make_nonblock(fd);
    struct conn *c = conn_add(fd);
    epoll_add(fd, EPOLLIN, c);
    fprintf(stderr, "[+] client fd=%d id=%u\n", fd, c->id);
}

static void flush_out(struct conn *c) {
    while (c->out_buf && c->out_off < c->out_len) {
        ssize_t n = send(c->fd, c->out_buf + c->out_off, c->out_len - c->out_off, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                epoll_mod(c->fd, EPOLLIN | EPOLLOUT, c);
                return;
            }
            fprintf(stderr, "send failed cid=%u err=%s\n", c->id, strerror(errno));
            c->out_off = c->out_len = 0;
            conn_remove(c);
            return;
        }
        c->out_off += (size_t)n;
    }
    free(c->out_buf);
    c->out_buf = NULL;
    c->out_off = c->out_len = 0;
    epoll_mod(c->fd, EPOLLIN, c);
}

static void queue_out(struct conn *c, const unsigned char *data, size_t len) {
    if (!len) return;
    unsigned char *buf = malloc(c->out_len - c->out_off + len);
    size_t existing = c->out_len - c->out_off;
    if (existing && c->out_buf) memcpy(buf, c->out_buf + c->out_off, existing);
    memcpy(buf + existing, data, len);
    free(c->out_buf);
    c->out_buf = buf;
    c->out_len = existing + len;
    c->out_off = 0;
    flush_out(c);
}

static void handle_read(struct conn *c) {
    unsigned char buf[8192];
    static int read_logs = 0;
    static int push_logs = 0;
    while (1) {
        ssize_t n = recv(c->fd, buf, sizeof(buf), 0);
        if (n == 0) { /* client closed */
            ring_push(&g.req, c->id, MSG_CLOSE, NULL, 0);
            conn_remove(c);
            return;
        } else if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            ring_push(&g.req, c->id, MSG_CLOSE, NULL, 0);
            conn_remove(c);
            return;
        }
        if (read_logs < 10) {
            fprintf(stderr, "read cid=%u n=%zd\n", c->id, n);
            read_logs++;
        }
        /* Basic RESP sanity: first byte should be one of RESP prefixes. */
        if (n > 0) {
            unsigned char ch = buf[0];
            if (!(ch == '*' || ch == '+' || ch == '-' || ch == ':' || ch == '$')) {
                fprintf(stderr, "drop cid=%u bad prefix=0x%02x len=%zd\n", c->id, ch, n);
                ring_push(&g.req, c->id, MSG_CLOSE, NULL, 0);
                conn_remove(c);
                return;
            }
        }
        /* push to ring (may split) */
        size_t off = 0;
        while (off < (size_t)n) {
            uint32_t chunk = (uint32_t)((size_t)n - off);
            if (chunk > g.req.cfg.slot_size - 16) chunk = g.req.cfg.slot_size - 16;
            int tries = 0, rc;
            while ((rc = ring_push(&g.req, c->id, MSG_DATA, buf + off, chunk)) == 0 && tries < 100) {
                /* ring full; brief backoff */
                usleep(1000);
                tries++;
            }
            if (rc <= 0) {
                fprintf(stderr, "ring push failed cid=%u rc=%d head=%llu tail=%llu diff=%llu\n",
                        c->id, rc,
                        (unsigned long long)(*g.req.head),
                        (unsigned long long)(*g.req.tail),
                        (unsigned long long)(*g.req.head - *g.req.tail));
                ring_push(&g.req, c->id, MSG_CLOSE, NULL, 0);
                conn_remove(c);
                return; /* full or error; drop */
            }
            if (push_logs < 10) {
                fprintf(stderr, "push cid=%u len=%u head=%llu tail=%llu diff=%llu\n",
                        c->id, chunk,
                        (unsigned long long)(*g.req.head),
                        (unsigned long long)(*g.req.tail),
                        (unsigned long long)(*g.req.head - *g.req.tail));
                push_logs++;
            }
            off += chunk;
        }
    }
}

static void handle_resp(void) {
    uint32_t cid, len;
    uint16_t type;
    unsigned char *payload;
    int iter = 0;
    while (iter < 1024 && ring_pop(&g.resp, &cid, &type, &payload, &len)) {
        struct conn *c = conn_find(cid);
        if (!c) { iter++; continue; }
        if (type == MSG_CLOSE) {
            ring_push(&g.req, cid, MSG_CLOSE, NULL, 0);
            conn_remove(c);
        } else if (type == MSG_DATA) {
            queue_out(c, payload, len);
            fprintf(stderr, "resp cid=%u len=%u\n", cid, len);
        }
        iter++;
    }
}

int main(int argc, char **argv) {
    const char *path = "/sys/bus/pci/devices/0000:00:02.0/resource2";
    size_t map_size = 1024ULL * 1024 * 1024; /* 1GB default */
    size_t map_offset = 0;
    const char *listen = "0.0.0.0";
    int port = 6380;
    int opt;
    while ((opt = getopt(argc, argv, "")) != -1) {}
    const char *offset_env = getenv("CXL_RING_OFFSET");
    if (!offset_env || !offset_env[0]) offset_env = getenv("CXL_SHM_OFFSET");
    if (offset_env && offset_env[0]) {
        unsigned long long v = strtoull(offset_env, NULL, 0);
        if (v > 0) map_offset = (size_t)v;
    }
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--path") && i + 1 < argc) path = argv[++i];
        else if (!strcmp(argv[i], "--map-size") && i + 1 < argc) map_size = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--map-offset") && i + 1 < argc) map_offset = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--listen") && i + 1 < argc) {
            listen = argv[++i];
            char *colon = strrchr(listen, ':');
            if (colon) { *colon = '\0'; port = atoi(colon + 1); }
        }
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    if (shm_init(path, map_size, map_offset) != 0) {
        fprintf(stderr, "failed to init shm\n");
        return 1;
    }
    g.listen_fd = setup_listener(listen, port);
    if (g.listen_fd < 0) {
        fprintf(stderr, "listen failed\n");
        return 1;
    }
    g.epfd = epoll_create1(0);
    epoll_add(g.listen_fd, EPOLLIN, NULL);
    g.next_id = 1;

    fprintf(stderr, "[*] ring client: path=%s map=%zu offset=%zu listen=%s:%d\n",
            path, map_size, map_offset, listen, port);
    struct epoll_event evs[64];
    while (running) {
        handle_resp();
        int n = epoll_wait(g.epfd, evs, 64, 1);
        for (int i = 0; i < n; i++) {
            if (evs[i].data.ptr == NULL) {
                handle_accept();
            } else {
                struct conn *c = evs[i].data.ptr;
                if (evs[i].events & EPOLLIN) handle_read(c);
                if (evs[i].events & EPOLLOUT) flush_out(c);
            }
        }
    }
    return 0;
}
