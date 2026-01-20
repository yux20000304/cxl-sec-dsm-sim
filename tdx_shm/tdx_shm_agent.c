#include "tdx_shm_map.h"
#include "tdx_shm_transport.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct agent_ctx {
    struct tdx_shm_queue_view rx;
    struct tdx_shm_queue_view tx;
};

static volatile sig_atomic_t g_stop = 0;

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s --id {1|2} [--uio /dev/uio0 | --path /dev/shm/tdx_shm] [--send MSG]\n"
            "       %s --id {1|2} [--uio /dev/uio0 | --path /dev/shm/tdx_shm] --recv-once [--timeout-ms N]\n"
            "Default mapping (when neither --uio nor --path is provided): auto-detect ivshmem and mmap PCI resource2.\n",
            prog, prog);
}

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static void sleep_us(long usec) {
    struct timespec ts;
    ts.tv_sec = usec / 1000000L;
    ts.tv_nsec = (usec % 1000000L) * 1000L;
    nanosleep(&ts, NULL);
}

static int recv_once(struct tdx_shm_queue_view *rx, long timeout_ms) {
    char buf[TDX_SHM_MSG_MAX + 1U];
    long waited_ms = 0;

    while (!g_stop && waited_ms < timeout_ms) {
        size_t len = 0U;
        int rc = tdx_shm_queue_recv(rx, buf, TDX_SHM_MSG_MAX, &len);
        if (rc == 0) {
            buf[len] = '\0';
            printf("[rx] %s\n", buf);
            fflush(stdout);
            return 0;
        }
        if (rc == -EAGAIN) {
            sleep_us(1000);
            waited_ms += 1;
            continue;
        }
        fprintf(stderr, "recv error: %s\n", strerror(-rc));
        sleep_us(10000);
        waited_ms += 10;
    }

    fprintf(stderr, "recv timeout after %ld ms\n", timeout_ms);
    return -ETIMEDOUT;
}

static void *rx_thread(void *arg) {
    struct agent_ctx *ctx = (struct agent_ctx *)arg;
    char buf[TDX_SHM_MSG_MAX + 1U];

    while (!g_stop) {
        size_t len = 0U;
        int rc = tdx_shm_queue_recv(&ctx->rx, buf, TDX_SHM_MSG_MAX, &len);
        if (rc == 0) {
            buf[len] = '\0';
            printf("[rx] %s\n", buf);
            fflush(stdout);
        } else if (rc == -EAGAIN) {
            sleep_us(1000);
        } else {
            fprintf(stderr, "recv error: %s\n", strerror(-rc));
            sleep_us(10000);
        }
    }

    return NULL;
}

static int send_line(struct tdx_shm_queue_view *tx, const char *line) {
    size_t len = strlen(line);
    while (len > 0U && (line[len - 1U] == '\n' || line[len - 1U] == '\r')) {
        len--;
    }
    if (len == 0U) {
        return 0;
    }

    while (1) {
        int rc = tdx_shm_queue_send(tx, line, len);
        if (rc == 0) {
            return 0;
        }
        if (rc == -EAGAIN) {
            sleep_us(1000);
            continue;
        }
        fprintf(stderr, "send error: %s\n", strerror(-rc));
        return rc;
    }
}

int main(int argc, char **argv) {
    int id = 0;
    const char *uio_dev = NULL;
    const char *path = NULL;
    const char *send_once = NULL;
    int do_recv_once = 0;
    long timeout_ms = 5000;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            id = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--uio") == 0 && i + 1 < argc) {
            uio_dev = argv[++i];
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--send") == 0 && i + 1 < argc) {
            send_once = argv[++i];
        } else if (strcmp(argv[i], "--recv-once") == 0) {
            do_recv_once = 1;
        } else if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            timeout_ms = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (id != 1 && id != 2) {
        usage(argv[0]);
        return 1;
    }

    if (send_once && do_recv_once) {
        fprintf(stderr, "--send and --recv-once are mutually exclusive\n");
        return 1;
    }
    if (timeout_ms <= 0) {
        fprintf(stderr, "--timeout-ms must be > 0\n");
        return 1;
    }

    struct tdx_shm_mapping mapping;
    int rc = 0;
    if (uio_dev) {
        rc = tdx_shm_map_uio(uio_dev, &mapping);
    } else if (path) {
        rc = tdx_shm_map_file(path, 0U, 0, &mapping);
    } else {
        rc = tdx_shm_map_ivshmem_resource2(&mapping);
    }
    if (rc != 0) {
        fprintf(stderr, "tdx shm map failed: %s\n", strerror(-rc));
        return 1;
    }

    struct tdx_shm_region region;
    rc = tdx_shm_region_attach(mapping.addr, mapping.size, &region);
    if (rc != 0) {
        fprintf(stderr, "tdx shm attach failed: %s\n", strerror(-rc));
        tdx_shm_unmap(&mapping);
        return 1;
    }

    struct agent_ctx ctx;
    if (id == 1) {
        ctx.tx = region.q12;
        ctx.rx = region.q21;
    } else {
        ctx.tx = region.q21;
        ctx.rx = region.q12;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (send_once) {
        rc = send_line(&ctx.tx, send_once);
        tdx_shm_unmap(&mapping);
        return rc == 0 ? 0 : 1;
    }

    if (do_recv_once) {
        rc = recv_once(&ctx.rx, timeout_ms);
        tdx_shm_unmap(&mapping);
        return rc == 0 ? 0 : 2;
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, rx_thread, &ctx) != 0) {
        fprintf(stderr, "failed to start rx thread\n");
        tdx_shm_unmap(&mapping);
        return 1;
    }

    char line[512];
    while (!g_stop && fgets(line, sizeof(line), stdin)) {
        if (send_line(&ctx.tx, line) != 0) {
            break;
        }
    }

    g_stop = 1;
    pthread_join(tid, NULL);
    tdx_shm_unmap(&mapping);
    return 0;
}

