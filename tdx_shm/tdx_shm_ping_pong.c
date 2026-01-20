#include "tdx_shm_map.h"
#include "tdx_shm_transport.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t g_stop = 0;

struct bench_hdr {
    uint32_t magic;
    uint32_t seq;
};

#define BENCH_MAGIC 0x50494E47U /* 'PING' */

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_us(long usec) {
    struct timespec ts;
    ts.tv_sec = usec / 1000000L;
    ts.tv_nsec = (usec % 1000000L) * 1000L;
    nanosleep(&ts, NULL);
}

static int send_blocking(struct tdx_shm_queue_view *tx, const void *data, size_t len, long sleep_us_val) {
    while (!g_stop) {
        int rc = tdx_shm_queue_send(tx, data, len);
        if (rc == 0) return 0;
        if (rc == -EAGAIN) {
            sleep_us(sleep_us_val);
            continue;
        }
        return rc;
    }
    return -EINTR;
}

static int recv_blocking(struct tdx_shm_queue_view *rx, void *buf, size_t cap, size_t *out_len, long timeout_ms, long sleep_us_val) {
    uint64_t deadline = 0;
    if (timeout_ms > 0) {
        deadline = now_ns() + (uint64_t)timeout_ms * 1000000ULL;
    }

    while (!g_stop) {
        int rc = tdx_shm_queue_recv(rx, buf, cap, out_len);
        if (rc == 0) return 0;
        if (rc != -EAGAIN) return rc;
        if (timeout_ms > 0 && now_ns() > deadline) return -ETIMEDOUT;
        sleep_us(sleep_us_val);
    }
    return -EINTR;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s --id {1|2} --role {server|client} [--count N] [--timeout-ms N] [--sleep-us N]\n"
            "          [--bench --duration-s N --msg-size N --warmup N --no-verify]\n"
            "          [--uio /dev/uio0 | --path /dev/shm/tdx_shm]\n"
            "Mapping default: auto-detect ivshmem and mmap PCI resource2.\n",
            prog);
}

int main(int argc, char **argv) {
    int id = 0;
    const char *role = NULL;
    const char *uio_dev = NULL;
    const char *path = NULL;
    int count = 10;
    long timeout_ms = 5000;
    long sleep_us_val = 500;
    int bench = 0;
    long duration_s = 0;
    int msg_size = 64;
    int warmup = 0;
    int verify = 1;
    int quiet = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            id = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            role = argv[++i];
        } else if (strcmp(argv[i], "--uio") == 0 && i + 1 < argc) {
            uio_dev = argv[++i];
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--bench") == 0) {
            bench = 1;
        } else if (strcmp(argv[i], "--duration-s") == 0 && i + 1 < argc) {
            duration_s = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--msg-size") == 0 && i + 1 < argc) {
            msg_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
            warmup = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-verify") == 0) {
            verify = 0;
        } else if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            timeout_ms = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--sleep-us") == 0 && i + 1 < argc) {
            sleep_us_val = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--quiet") == 0) {
            quiet = 1;
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
    if (!role || (strcmp(role, "server") != 0 && strcmp(role, "client") != 0)) {
        usage(argv[0]);
        return 1;
    }
    if (count <= 0) count = 1;
    if (sleep_us_val < 0) sleep_us_val = 0;
    if (duration_s < 0) duration_s = 0;
    if (warmup < 0) warmup = 0;
    if (msg_size < 1) msg_size = 1;
    if (msg_size > (int)TDX_SHM_MSG_MAX) msg_size = (int)TDX_SHM_MSG_MAX;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

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
        fprintf(stderr, "map failed: %s\n", strerror(-rc));
        return 1;
    }

    struct tdx_shm_region region;
    rc = tdx_shm_region_attach(mapping.addr, mapping.size, &region);
    if (rc != 0) {
        fprintf(stderr, "attach failed: %s\n", strerror(-rc));
        tdx_shm_unmap(&mapping);
        return 1;
    }

    struct tdx_shm_queue_view tx, rx;
    if (id == 1) {
        tx = region.q12;
        rx = region.q21;
    } else {
        tx = region.q21;
        rx = region.q12;
    }

    if (strcmp(role, "server") == 0) {
        uint8_t buf[TDX_SHM_MSG_MAX];
        if (!quiet) {
            fprintf(stdout, bench ? "[server] ready (bench, id=%d)\n" : "[server] ready (id=%d)\n", id);
            fflush(stdout);
        }
        while (!g_stop) {
            size_t len = 0U;
            rc = recv_blocking(&rx, buf, sizeof(buf), &len, timeout_ms, sleep_us_val);
            if (rc == -ETIMEDOUT) {
                continue;
            }
            if (rc != 0) break;

            if (len == 5U && memcmp(buf, "CLOSE", 5U) == 0) {
                if (!quiet) {
                    fprintf(stdout, "[server] close\n");
                }
                break;
            }

            if (bench) {
                rc = send_blocking(&tx, buf, len, sleep_us_val);
            } else {
                char reply[TDX_SHM_MSG_MAX];
                int n = snprintf(reply, sizeof(reply), "PONG %.*s", (int)len, (const char *)buf);
                if (n < 0) {
                    rc = -EINVAL;
                    break;
                }
                if ((size_t)n > sizeof(reply)) n = (int)sizeof(reply);
                rc = send_blocking(&tx, reply, (size_t)n, sleep_us_val);
            }
            if (rc != 0) break;
        }

        if (rc != 0 && rc != -EINTR) {
            fprintf(stderr, "[server] error: %s\n", strerror(-rc));
            tdx_shm_unmap(&mapping);
            return 2;
        }
        tdx_shm_unmap(&mapping);
        return 0;
    }

    if (bench) {
        uint8_t *msg = (uint8_t *)malloc((size_t)msg_size);
        uint8_t *reply = (uint8_t *)malloc((size_t)msg_size);
        if (!msg || !reply) {
            fprintf(stderr, "[client] alloc failed\n");
            free(msg);
            free(reply);
            tdx_shm_unmap(&mapping);
            return 2;
        }

        if ((size_t)msg_size >= sizeof(struct bench_hdr)) {
            struct bench_hdr *hdr = (struct bench_hdr *)msg;
            hdr->magic = BENCH_MAGIC;
            hdr->seq = 0U;
        }
        for (int i = (int)sizeof(struct bench_hdr); i < msg_size; ++i) {
            msg[i] = (uint8_t)(i & 0xff);
        }

        int warm_ok = 0;
        for (int i = 0; i < warmup && !g_stop; ++i) {
            if ((size_t)msg_size >= sizeof(struct bench_hdr)) {
                struct bench_hdr *hdr = (struct bench_hdr *)msg;
                hdr->seq = (uint32_t)i;
            }
            rc = send_blocking(&tx, msg, (size_t)msg_size, sleep_us_val);
            if (rc != 0) break;
            size_t len = 0U;
            rc = recv_blocking(&rx, reply, (size_t)msg_size, &len, timeout_ms, sleep_us_val);
            if (rc != 0) break;
            if (verify && len == (size_t)msg_size && (size_t)msg_size >= sizeof(struct bench_hdr)) {
                struct bench_hdr *rh = (struct bench_hdr *)reply;
                if (rh->magic != BENCH_MAGIC || rh->seq != (uint32_t)i) {
                    rc = -EINVAL;
                    break;
                }
            }
            warm_ok += 1;
        }

        if (rc != 0 && rc != -EINTR) {
            fprintf(stderr, "[client] warmup error: %s\n", strerror(-rc));
            (void)send_blocking(&tx, "CLOSE", 5, sleep_us_val);
            free(msg);
            free(reply);
            tdx_shm_unmap(&mapping);
            return 2;
        }

        uint64_t bench_start = now_ns();
        uint64_t deadline = 0;
        if (duration_s > 0) {
            deadline = bench_start + (uint64_t)duration_s * 1000000000ULL;
        }

        uint64_t rounds = 0;
        uint32_t seq = 0;
        while (!g_stop) {
            if (deadline && now_ns() >= deadline) break;
            if (!deadline && (int)rounds >= count) break;

            if ((size_t)msg_size >= sizeof(struct bench_hdr)) {
                struct bench_hdr *hdr = (struct bench_hdr *)msg;
                hdr->seq = seq;
            }

            rc = send_blocking(&tx, msg, (size_t)msg_size, sleep_us_val);
            if (rc != 0) break;

            size_t len = 0U;
            rc = recv_blocking(&rx, reply, (size_t)msg_size, &len, timeout_ms, sleep_us_val);
            if (rc != 0) break;

            if (verify) {
                if (len != (size_t)msg_size) {
                    rc = -EMSGSIZE;
                    break;
                }
                if ((size_t)msg_size >= sizeof(struct bench_hdr)) {
                    struct bench_hdr *rh = (struct bench_hdr *)reply;
                    if (rh->magic != BENCH_MAGIC || rh->seq != seq) {
                        rc = -EINVAL;
                        break;
                    }
                }
            }

            rounds += 1U;
            seq += 1U;
        }
        uint64_t bench_end = now_ns();

        (void)send_blocking(&tx, "CLOSE", 5, sleep_us_val);

        double elapsed_s = (double)(bench_end - bench_start) / 1e9;
        if (elapsed_s <= 0.0) elapsed_s = 1e-9;
        double rps = (double)rounds / elapsed_s;
        double avg_rtt_us = (rounds > 0) ? ((double)(bench_end - bench_start) / (double)rounds / 1e3) : 0.0;
        double bw_mib_s = (rps * (double)(2.0 * (double)msg_size)) / (1024.0 * 1024.0);

        fprintf(stdout,
                "[bench] warmup=%d/%d msg=%dB rounds=%llu elapsed=%.3fs rps=%.1f avg_rtt=%.2fus bw=%.2f MiB/s\n",
                warm_ok, warmup, msg_size, (unsigned long long)rounds, elapsed_s, rps, avg_rtt_us, bw_mib_s);

        if (rc != 0 && rc != -EINTR) {
            fprintf(stderr, "[client] bench error: %s\n", strerror(-rc));
        }

        free(msg);
        free(reply);
        tdx_shm_unmap(&mapping);
        return (rc == 0 || rc == -EINTR) ? 0 : 2;
    }

    uint64_t rtt_sum_ns = 0;
    int ok = 0;
    for (int i = 0; i < count && !g_stop; ++i) {
        char msg[64];
        int n = snprintf(msg, sizeof(msg), "PING %d", i);
        if (n <= 0) {
            rc = -EINVAL;
            break;
        }

        rc = send_blocking(&tx, msg, (size_t)n, sleep_us_val);
        if (rc != 0) break;

        uint64_t start = now_ns();
        char buf[TDX_SHM_MSG_MAX + 1U];
        size_t len = 0U;
        rc = recv_blocking(&rx, buf, TDX_SHM_MSG_MAX, &len, timeout_ms, sleep_us_val);
        if (rc != 0) {
            fprintf(stderr, "[client] timeout waiting reply %d\n", i);
            break;
        }
        uint64_t dt = now_ns() - start;
        rtt_sum_ns += dt;
        ok += 1;
        buf[len] = '\0';
        if (!quiet) {
            fprintf(stdout, "[client] %d: %s (%.3f ms)\n", i, buf, (double)dt / 1e6);
            fflush(stdout);
        }
    }

    (void)send_blocking(&tx, "CLOSE", 5, sleep_us_val);

    if (ok > 0) {
        fprintf(stdout, "[client] %d/%d ok, avg RTT = %.3f ms\n", ok, count, (double)rtt_sum_ns / (double)ok / 1e6);
    } else {
        fprintf(stdout, "[client] 0/%d ok\n", count);
    }

    tdx_shm_unmap(&mapping);
    return ok == count ? 0 : 2;
}
