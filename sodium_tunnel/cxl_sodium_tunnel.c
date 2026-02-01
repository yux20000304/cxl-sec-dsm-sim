#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define CHUNK_SIZE 16384
#define MAX_RECORD (1U << 20) /* 1MB safety cap */

/*
 * Lightweight instrumentation to attribute time spent on:
 * - crypto (secretstream push/pull)
 * - read()/write() syscalls
 *
 * When SODIUM_STATS_OUT is set to a writable path, the process will dump
 * a JSON line with aggregated counters at exit or on SIGTERM/SIGINT/SIGHUP.
 * Counters are approximate but cheap and thread-safe.
 */
static const char *g_stats_path = NULL;
static int g_stats_enabled = 0;

static inline unsigned long long nsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

static volatile sig_atomic_t g_running = 1;

/* Global accumulators (ns / bytes). Use atomic adds for cross-thread updates. */
static unsigned long long g_crypto_push_ns = 0;
static unsigned long long g_crypto_pull_ns = 0;
static unsigned long long g_read_ns = 0;
static unsigned long long g_write_ns = 0;
static unsigned long long g_read_bytes = 0;
static unsigned long long g_write_bytes = 0;
static unsigned long long g_crypto_in_bytes = 0;  /* plaintext bytes encrypted */
static unsigned long long g_crypto_out_bytes = 0; /* plaintext bytes decrypted */

static void stats_add(volatile unsigned long long *dst, unsigned long long v) {
    __atomic_fetch_add((unsigned long long *)dst, v, __ATOMIC_RELAXED);
}

static void write_stats_json(void) {
    if (!g_stats_path) return;
    FILE *f = fopen(g_stats_path, "w");
    if (!f) return;
    fprintf(f,
            "{\n"
            "  \"pid\": %d,\n"
            "  \"crypto_push_ns\": %llu,\n"
            "  \"crypto_pull_ns\": %llu,\n"
            "  \"read_ns\": %llu,\n"
            "  \"write_ns\": %llu,\n"
            "  \"read_bytes\": %llu,\n"
            "  \"write_bytes\": %llu,\n"
            "  \"crypto_in_bytes\": %llu,\n"
            "  \"crypto_out_bytes\": %llu\n"
            "}\n",
            (int)getpid(),
            (unsigned long long)g_crypto_push_ns,
            (unsigned long long)g_crypto_pull_ns,
            (unsigned long long)g_read_ns,
            (unsigned long long)g_write_ns,
            (unsigned long long)g_read_bytes,
            (unsigned long long)g_write_bytes,
            (unsigned long long)g_crypto_in_bytes,
            (unsigned long long)g_crypto_out_bytes);
    fclose(f);
}

static void on_exit_dump(void) {
    write_stats_json();
}

static void on_sig(int sig) {
    (void)sig;
    g_running = 0;
    /* Dump promptly so stats are not lost on termination. */
    write_stats_json();
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s --mode client --listen <ip:port> --connect <ip:port> --key <hex64>\n"
            "  %s --mode server --listen <ip:port> --backend <ip:port> --key <hex64>\n"
            "\n"
            "Notes:\n"
            "- This is a simple encrypted TCP tunnel intended for benchmarking.\n"
            "- Uses libsodium secretstream (XChaCha20-Poly1305) with a pre-shared key.\n",
            prog, prog);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_key_hex(const char *hex, unsigned char *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval(hex[i * 2]);
        int lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
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

static int set_nodelay(int fd) {
    int one = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
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

static int socket_connect(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "[!] getaddrinfo(connect %s:%s): %s\n", host, port, gai_strerror(rc));
        return -1;
    }

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
        unsigned long long t0 = 0;
        if (g_stats_enabled) t0 = nsec_now();
        ssize_t w = write(fd, (const unsigned char *)buf + off, n - off);
        if (g_stats_enabled) {
            unsigned long long t1 = nsec_now();
            stats_add(&g_write_ns, (t1 - t0));
            if (w > 0) {
                stats_add(&g_write_bytes, (unsigned long long)w);
            }
        }
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int handshake_client(int fd_enc,
                            const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
                            crypto_secretstream_xchacha20poly1305_state *st_push,
                            crypto_secretstream_xchacha20poly1305_state *st_pull) {
    unsigned char header_push[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (crypto_secretstream_xchacha20poly1305_init_push(st_push, header_push, key) != 0) return -1;
    if (write_full(fd_enc, header_push, sizeof(header_push)) != 0) return -1;

    unsigned char header_pull[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    ssize_t r = read_full(fd_enc, header_pull, sizeof(header_pull));
    if (r != (ssize_t)sizeof(header_pull)) return -1;
    if (crypto_secretstream_xchacha20poly1305_init_pull(st_pull, header_pull, key) != 0) return -1;
    return 0;
}

static int handshake_server(int fd_enc,
                            const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
                            crypto_secretstream_xchacha20poly1305_state *st_push,
                            crypto_secretstream_xchacha20poly1305_state *st_pull) {
    unsigned char header_pull[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    ssize_t r = read_full(fd_enc, header_pull, sizeof(header_pull));
    if (r != (ssize_t)sizeof(header_pull)) return -1;
    if (crypto_secretstream_xchacha20poly1305_init_pull(st_pull, header_pull, key) != 0) return -1;

    unsigned char header_push[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (crypto_secretstream_xchacha20poly1305_init_push(st_push, header_push, key) != 0) return -1;
    if (write_full(fd_enc, header_push, sizeof(header_push)) != 0) return -1;
    return 0;
}

struct conn_ctx {
    int fd_plain;
    int fd_enc;
    crypto_secretstream_xchacha20poly1305_state st_push;
    crypto_secretstream_xchacha20poly1305_state st_pull;
};

static void shutdown_pair(struct conn_ctx *c) {
    if (!c) return;
    if (c->fd_plain >= 0) shutdown(c->fd_plain, SHUT_RDWR);
    if (c->fd_enc >= 0) shutdown(c->fd_enc, SHUT_RDWR);
}

static void *plain_to_enc(void *arg) {
    struct conn_ctx *c = (struct conn_ctx *)arg;
    unsigned char inbuf[CHUNK_SIZE];
    unsigned char cbuf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char tag = 0;

    while (1) {
        unsigned long long t0r = 0;
        if (g_stats_enabled) t0r = nsec_now();
        ssize_t r = read(c->fd_plain, inbuf, sizeof(inbuf));
        if (g_stats_enabled) {
            unsigned long long t1r = nsec_now();
            stats_add(&g_read_ns, (t1r - t0r));
            if (r > 0) {
                stats_add(&g_read_bytes, (unsigned long long)r);
            }
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) {
            tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        } else {
            tag = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
        }

        unsigned long long clen = 0;
        unsigned long long t0c = 0;
        if (g_stats_enabled) t0c = nsec_now();
        if (crypto_secretstream_xchacha20poly1305_push(&c->st_push, cbuf, &clen, inbuf, (unsigned long long)r, NULL, 0,
                                                       tag) != 0) {
            break;
        }
        if (g_stats_enabled) {
            unsigned long long t1c = nsec_now();
            stats_add(&g_crypto_push_ns, (t1c - t0c));
            if (r > 0) stats_add(&g_crypto_in_bytes, (unsigned long long)r);
        }
        if (clen > MAX_RECORD) break;

        uint32_t be = htonl((uint32_t)clen);
        if (write_full(c->fd_enc, &be, sizeof(be)) != 0) break;
        if (write_full(c->fd_enc, cbuf, (size_t)clen) != 0) break;

        if (r == 0) break;
    }

    shutdown_pair(c);
    return NULL;
}

static int enc_to_plain(struct conn_ctx *c) {
    unsigned char cbuf[MAX_RECORD];
    unsigned char pbuf[MAX_RECORD];

    while (1) {
        uint32_t be_len = 0;
        unsigned long long t0r = 0;
        if (g_stats_enabled) t0r = nsec_now();
        ssize_t r = read_full(c->fd_enc, &be_len, sizeof(be_len));
        if (g_stats_enabled) {
            unsigned long long t1r = nsec_now();
            stats_add(&g_read_ns, (t1r - t0r));
            if (r > 0) stats_add(&g_read_bytes, (unsigned long long)r);
        }
        if (r == 0) break; /* EOF */
        if (r != (ssize_t)sizeof(be_len)) return -1;
        uint32_t clen = ntohl(be_len);
        if (clen == 0 || clen > MAX_RECORD) return -1;

        t0r = 0;
        if (g_stats_enabled) t0r = nsec_now();
        ssize_t rr = read_full(c->fd_enc, cbuf, clen);
        if (g_stats_enabled) {
            unsigned long long t1r = nsec_now();
            stats_add(&g_read_ns, (t1r - t0r));
            if (rr > 0) {
                stats_add(&g_read_bytes, (unsigned long long)rr);
            }
        }
        if (rr != (ssize_t)clen) return -1;

        unsigned long long plen = 0;
        unsigned char tag = 0;
        unsigned long long t0c = 0;
        if (g_stats_enabled) t0c = nsec_now();
        if (crypto_secretstream_xchacha20poly1305_pull(&c->st_pull, pbuf, &plen, &tag, cbuf, clen, NULL, 0) != 0) {
            return -1;
        }
        if (g_stats_enabled) {
            unsigned long long t1c = nsec_now();
            stats_add(&g_crypto_pull_ns, (t1c - t0c));
            if (plen > 0) stats_add(&g_crypto_out_bytes, (unsigned long long)plen);
        }

        if (plen) {
            if (write_full(c->fd_plain, pbuf, (size_t)plen) != 0) return -1;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) break;
    }

    return 0;
}

static void *handle_conn_client(void *arg) {
    struct conn_ctx *c = (struct conn_ctx *)arg;

    pthread_t th;
    if (pthread_create(&th, NULL, plain_to_enc, c) != 0) {
        shutdown_pair(c);
        close(c->fd_plain);
        close(c->fd_enc);
        free(c);
        return NULL;
    }

    (void)enc_to_plain(c);
    shutdown_pair(c);
    pthread_join(th, NULL);

    close(c->fd_plain);
    close(c->fd_enc);
    free(c);
    return NULL;
}

static int run_client(const char *listen_host,
                      const char *listen_port,
                      const char *connect_host,
                      const char *connect_port,
                      const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    int lfd = socket_listen(listen_host, listen_port);
    if (lfd < 0) return 1;
    fprintf(stderr, "[*] client: listen %s:%s, connect %s:%s\n", listen_host, listen_port, connect_host, connect_port);

    while (g_running) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int cfd = accept(lfd, (struct sockaddr *)&ss, &slen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        int efd = socket_connect(connect_host, connect_port);
        if (efd < 0) {
            close(cfd);
            continue;
        }
        set_nodelay(cfd);
        set_nodelay(efd);

        struct conn_ctx *c = (struct conn_ctx *)calloc(1, sizeof(*c));
        if (!c) {
            close(cfd);
            close(efd);
            continue;
        }
        c->fd_plain = cfd;
        c->fd_enc = efd;

        if (handshake_client(c->fd_enc, key, &c->st_push, &c->st_pull) != 0) {
            shutdown_pair(c);
            close(cfd);
            close(efd);
            free(c);
            continue;
        }

        pthread_t th;
        if (pthread_create(&th, NULL, handle_conn_client, c) != 0) {
            shutdown_pair(c);
            close(cfd);
            close(efd);
            free(c);
            continue;
        }
        pthread_detach(th);
    }

    close(lfd);
    return 0;
}

struct server_conn_args {
    int fd_enc;
    char *backend_host;
    char *backend_port;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
};

static void *handle_conn_server(void *arg) {
    struct server_conn_args *a = (struct server_conn_args *)arg;
    int efd = a->fd_enc;

    int pfd = socket_connect(a->backend_host, a->backend_port);
    if (pfd < 0) {
        close(efd);
        free(a->backend_host);
        free(a->backend_port);
        free(a);
        return NULL;
    }
    set_nodelay(pfd);
    set_nodelay(efd);

    struct conn_ctx *c = (struct conn_ctx *)calloc(1, sizeof(*c));
    if (!c) {
        close(pfd);
        close(efd);
        free(a->backend_host);
        free(a->backend_port);
        free(a);
        return NULL;
    }
    c->fd_plain = pfd;
    c->fd_enc = efd;

    if (handshake_server(c->fd_enc, a->key, &c->st_push, &c->st_pull) != 0) {
        shutdown_pair(c);
        close(pfd);
        close(efd);
        free(c);
        free(a->backend_host);
        free(a->backend_port);
        free(a);
        return NULL;
    }

    pthread_t th;
    if (pthread_create(&th, NULL, plain_to_enc, c) != 0) {
        shutdown_pair(c);
        close(pfd);
        close(efd);
        free(c);
        free(a->backend_host);
        free(a->backend_port);
        free(a);
        return NULL;
    }

    (void)enc_to_plain(c);
    shutdown_pair(c);
    pthread_join(th, NULL);

    close(c->fd_plain);
    close(c->fd_enc);
    free(c);

    free(a->backend_host);
    free(a->backend_port);
    free(a);
    return NULL;
}

static int run_server(const char *listen_host,
                      const char *listen_port,
                      const char *backend_host,
                      const char *backend_port,
                      const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    int lfd = socket_listen(listen_host, listen_port);
    if (lfd < 0) return 1;
    fprintf(stderr, "[*] server: listen %s:%s, backend %s:%s\n", listen_host, listen_port, backend_host, backend_port);

    while (g_running) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int efd = accept(lfd, (struct sockaddr *)&ss, &slen);
        if (efd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        struct server_conn_args *a = (struct server_conn_args *)calloc(1, sizeof(*a));
        if (!a) {
            close(efd);
            continue;
        }
        a->fd_enc = efd;
        a->backend_host = strdup(backend_host);
        a->backend_port = strdup(backend_port);
        memcpy(a->key, key, sizeof(a->key));
        if (!a->backend_host || !a->backend_port) {
            close(efd);
            free(a->backend_host);
            free(a->backend_port);
            free(a);
            continue;
        }

        pthread_t th;
        if (pthread_create(&th, NULL, handle_conn_server, a) != 0) {
            close(efd);
            free(a->backend_host);
            free(a->backend_port);
            free(a);
            continue;
        }
        pthread_detach(th);
    }

    close(lfd);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = NULL;
    const char *listen = NULL;
    const char *connect = NULL;
    const char *backend = NULL;
    const char *key_hex = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            mode = argv[++i];
        } else if (!strcmp(argv[i], "--listen") && i + 1 < argc) {
            listen = argv[++i];
        } else if (!strcmp(argv[i], "--connect") && i + 1 < argc) {
            connect = argv[++i];
        } else if (!strcmp(argv[i], "--backend") && i + 1 < argc) {
            backend = argv[++i];
        } else if (!strcmp(argv[i], "--key") && i + 1 < argc) {
            key_hex = argv[++i];
        } else {
            fprintf(stderr, "[!] Unknown/invalid arg: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (!mode || !listen || !key_hex) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(mode, "client") && strcmp(mode, "server")) {
        fprintf(stderr, "[!] --mode must be client or server\n");
        return 2;
    }
    if (!strcmp(mode, "client") && !connect) {
        fprintf(stderr, "[!] client mode requires --connect\n");
        return 2;
    }
    if (!strcmp(mode, "server") && !backend) {
        fprintf(stderr, "[!] server mode requires --backend\n");
        return 2;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "[!] sodium_init failed\n");
        return 1;
    }

    g_stats_path = getenv("SODIUM_STATS_OUT");
    if (g_stats_path && g_stats_path[0] != '\0') {
        g_stats_enabled = 1;
        atexit(on_exit_dump);
    } else {
        g_stats_path = NULL;
    }

    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    if (parse_key_hex(key_hex, key, sizeof(key)) != 0) {
        fprintf(stderr, "[!] Invalid --key (expected hex64 for 32 bytes)\n");
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    char *lh = NULL, *lp = NULL;
    if (parse_hostport(listen, &lh, &lp) != 0) {
        fprintf(stderr, "[!] Invalid --listen (expected ip:port)\n");
        return 2;
    }

    int rc = 0;
    if (!strcmp(mode, "client")) {
        char *ch = NULL, *cp = NULL;
        if (parse_hostport(connect, &ch, &cp) != 0) {
            fprintf(stderr, "[!] Invalid --connect (expected ip:port)\n");
            free(lh);
            free(lp);
            return 2;
        }
        rc = run_client(lh, lp, ch, cp, key);
        free(ch);
        free(cp);
    } else {
        char *bh = NULL, *bp = NULL;
        if (parse_hostport(backend, &bh, &bp) != 0) {
            fprintf(stderr, "[!] Invalid --backend (expected ip:port)\n");
            free(lh);
            free(lp);
            return 2;
        }
        rc = run_server(lh, lp, bh, bp, key);
        free(bh);
        free(bp);
    }

    free(lh);
    free(lp);
    return rc;
}
