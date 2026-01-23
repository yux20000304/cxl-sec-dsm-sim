#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [--mode private|shm] [options]\n"
            "\n"
            "Options:\n"
            "  --mode private|shm      Test normal RAM (private) or a shm mapping\n"
            "  --path PATH             shm: path to mmap (e.g., .../resource2 or /dev/uio0)\n"
            "  --map-size BYTES|K|M|G  shm: mmap length (required for /dev/uioX)\n"
            "  --map-offset BYTES      shm: mmap file offset (default: 0)\n"
            "  --region-off BYTES      shm: start offset within mapping (default: 64M)\n"
            "  --size BYTES|K|M|G      working set size (default: 256M)\n"
            "  --stride BYTES          bytes between dereferences (default: 64)\n"
            "  --iters N               pointer deref iterations (0=auto, default: 0)\n"
            "  --seed N                shuffle seed (default: 1)\n"
            "  --cpu N                 pin to CPU N (-1 disables pinning, default: -1)\n"
            "  --csv                   print one CSV row (no extra text)\n",
            prog);
}

static int parse_size_bytes(const char *arg, size_t *out) {
    if (!arg || !out) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(arg, &end, 0);
    if (errno != 0 || end == arg) return -1;

    unsigned long long mul = 1ULL;
    if (end && *end) {
        if (end[1] != '\0') return -1;
        switch (*end) {
            case 'K':
            case 'k':
                mul = 1024ULL;
                break;
            case 'M':
            case 'm':
                mul = 1024ULL * 1024ULL;
                break;
            case 'G':
            case 'g':
                mul = 1024ULL * 1024ULL * 1024ULL;
                break;
            default:
                return -1;
        }
    }

    if (mul != 0ULL && value > (ULLONG_MAX / mul)) return -1;
    unsigned long long bytes = value * mul;
    if (bytes > (unsigned long long)SIZE_MAX) return -1;
    *out = (size_t)bytes;
    return 0;
}

static int parse_u64(const char *arg, uint64_t *out) {
    if (!arg || !out) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(arg, &end, 0);
    if (errno != 0 || end == arg || (end && *end)) return -1;
    *out = (uint64_t)v;
    return 0;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void pin_cpu_or_die(int cpu) {
    if (cpu < 0) return;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "[!] sched_setaffinity(cpu=%d) failed: %s\n", cpu, strerror(errno));
        exit(2);
    }
}

static uint64_t xorshift64(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void shuffle_u32(uint32_t *a, uint32_t n, uint64_t seed) {
    if (!a || n <= 1) return;
    uint64_t st = seed ? seed : 1;
    for (uint32_t i = n - 1; i > 0; --i) {
        uint32_t j = (uint32_t)(xorshift64(&st) % (uint64_t)(i + 1));
        uint32_t tmp = a[i];
        a[i] = a[j];
        a[j] = tmp;
    }
}

static void *must_alloc_aligned(size_t align, size_t size) {
    void *p = NULL;
    if (posix_memalign(&p, align, size) != 0 || !p) {
        fprintf(stderr, "[!] posix_memalign(%zu,%zu) failed\n", align, size);
        exit(2);
    }
    memset(p, 0, size);
    return p;
}

struct mapping {
    int fd;
    void *base;
    size_t len;
};

static void mapping_close(struct mapping *m) {
    if (!m) return;
    if (m->base && m->len) munmap(m->base, m->len);
    if (m->fd >= 0) close(m->fd);
    m->fd = -1;
    m->base = NULL;
    m->len = 0;
}

static int mapping_open(const char *path, size_t map_size, size_t map_offset, struct mapping *out) {
    if (!path || !out) return -1;
    memset(out, 0, sizeof(*out));
    out->fd = -1;

    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    if ((map_offset % (size_t)page) != 0) {
        fprintf(stderr, "[!] map-offset must be page-aligned (offset=%zu page=%ld)\n", map_offset, page);
        return -1;
    }

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[!] open(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }

    if (map_size == 0) {
        struct stat st;
        if (fstat(fd, &st) != 0) {
            fprintf(stderr, "[!] fstat(%s) failed: %s\n", path, strerror(errno));
            close(fd);
            return -1;
        }
        if (st.st_size <= 0) {
            fprintf(stderr, "[!] fstat(%s): st_size=%lld; please pass --map-size\n", path, (long long)st.st_size);
            close(fd);
            return -1;
        }
        map_size = (size_t)st.st_size;
    }

    void *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)map_offset);
    if (base == MAP_FAILED) {
        fprintf(stderr, "[!] mmap(%s, size=%zu, off=%zu) failed: %s\n", path, map_size, map_offset, strerror(errno));
        close(fd);
        return -1;
    }

    out->fd = fd;
    out->base = base;
    out->len = map_size;
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = "private";
    const char *path = NULL;
    size_t map_size = 0;
    size_t map_offset = 0;
    size_t region_off = 64ULL * 1024ULL * 1024ULL; /* keep away from small headers */
    size_t size = 256ULL * 1024ULL * 1024ULL;
    size_t stride = 64;
    uint64_t iters = 0;
    uint64_t seed = 1;
    int cpu = -1;
    int csv = 0;

    static const struct option opts[] = {
        {"mode", required_argument, NULL, 'm'},
        {"path", required_argument, NULL, 'p'},
        {"map-size", required_argument, NULL, 's'},
        {"map-offset", required_argument, NULL, 'o'},
        {"region-off", required_argument, NULL, 'r'},
        {"size", required_argument, NULL, 'z'},
        {"stride", required_argument, NULL, 't'},
        {"iters", required_argument, NULL, 'i'},
        {"seed", required_argument, NULL, 'S'},
        {"cpu", required_argument, NULL, 'c'},
        {"csv", no_argument, NULL, 'C'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:p:s:o:r:z:t:i:S:c:Ch", opts, NULL)) != -1) {
        switch (opt) {
            case 'm':
                mode = optarg;
                break;
            case 'p':
                path = optarg;
                break;
            case 's':
                if (parse_size_bytes(optarg, &map_size) != 0) {
                    fprintf(stderr, "[!] invalid --map-size: %s\n", optarg);
                    return 2;
                }
                break;
            case 'o':
                if (parse_size_bytes(optarg, &map_offset) != 0) {
                    fprintf(stderr, "[!] invalid --map-offset: %s\n", optarg);
                    return 2;
                }
                break;
            case 'r':
                if (parse_size_bytes(optarg, &region_off) != 0) {
                    fprintf(stderr, "[!] invalid --region-off: %s\n", optarg);
                    return 2;
                }
                break;
            case 'z':
                if (parse_size_bytes(optarg, &size) != 0) {
                    fprintf(stderr, "[!] invalid --size: %s\n", optarg);
                    return 2;
                }
                break;
            case 't':
                if (parse_size_bytes(optarg, &stride) != 0) {
                    fprintf(stderr, "[!] invalid --stride: %s\n", optarg);
                    return 2;
                }
                break;
            case 'i':
                if (parse_u64(optarg, &iters) != 0) {
                    fprintf(stderr, "[!] invalid --iters: %s\n", optarg);
                    return 2;
                }
                break;
            case 'S':
                if (parse_u64(optarg, &seed) != 0) {
                    fprintf(stderr, "[!] invalid --seed: %s\n", optarg);
                    return 2;
                }
                break;
            case 'c':
                cpu = atoi(optarg);
                break;
            case 'C':
                csv = 1;
                break;
            case 'h':
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (stride < sizeof(uintptr_t)) {
        fprintf(stderr, "[!] --stride must be >= %zu\n", sizeof(uintptr_t));
        return 2;
    }
    if (size < stride * 2) {
        fprintf(stderr, "[!] --size too small for pointer chase (need >= 2*stride)\n");
        return 2;
    }

    pin_cpu_or_die(cpu);

    struct mapping shm = {.fd = -1, .base = NULL, .len = 0};
    uint8_t *base = NULL;
    size_t avail = 0;
    const char *kind = NULL;

    if (strcmp(mode, "private") == 0) {
        kind = "private";
        base = (uint8_t *)must_alloc_aligned(4096, size);
        avail = size;
        region_off = 0;
    } else if (strcmp(mode, "shm") == 0) {
        kind = "shm";
        if (!path) {
            fprintf(stderr, "[!] --path is required for --mode shm\n");
            return 2;
        }
        if (mapping_open(path, map_size, map_offset, &shm) != 0) {
            return 2;
        }
        base = (uint8_t *)shm.base;
        avail = shm.len;
        if (region_off >= avail || size > (avail - region_off)) {
            fprintf(stderr, "[!] region range out of mapping: region_off=%zu size=%zu map_len=%zu\n",
                    region_off, size, avail);
            mapping_close(&shm);
            return 2;
        }
    } else {
        fprintf(stderr, "[!] invalid --mode: %s\n", mode);
        usage(argv[0]);
        return 2;
    }

    uint8_t *work = base + region_off;
    uint32_t nlines = (uint32_t)(size / stride);
    if (nlines < 2) nlines = 2;

    uint32_t *perm = (uint32_t *)must_alloc_aligned(64, (size_t)nlines * sizeof(uint32_t));
    for (uint32_t i = 0; i < nlines; i++) perm[i] = i;
    shuffle_u32(perm, nlines, seed);

    /* Build a random single-cycle pointer chain (one pointer per stride). */
    for (uint32_t i = 0; i < nlines; i++) {
        uint32_t cur = perm[i];
        uint32_t nxt = perm[(i + 1) % nlines];
        uintptr_t *slot = (uintptr_t *)(work + (size_t)cur * stride);
        *slot = (uintptr_t)(work + (size_t)nxt * stride);
    }

    if (iters == 0) {
        /* Default to a few full traversals. */
        iters = (uint64_t)nlines * 8ULL;
    }

    volatile uintptr_t p = (uintptr_t)(work + (size_t)perm[0] * stride);

    /* Warmup: small bounded run. */
    uint64_t warm = iters / 16ULL;
    if (warm > 1000000ULL) warm = 1000000ULL;
    for (uint64_t i = 0; i < warm; i++) {
        p = *(uintptr_t *)p;
    }

    uint64_t t0 = now_ns();
    for (uint64_t i = 0; i < iters; i++) {
        p = *(uintptr_t *)p;
    }
    uint64_t t1 = now_ns();

    uint64_t dt = (t1 - t0);
    double ns_per = (iters == 0) ? 0.0 : ((double)dt / (double)iters);

    if (csv) {
        /* kind,path,map_offset,map_size,region_off,size,stride,iters,ns_total,ns_per */
        printf("%s,%s,%zu,%zu,%zu,%zu,%zu,%" PRIu64 ",%" PRIu64 ",%.3f\n",
               kind,
               path ? path : "",
               map_offset,
               (kind && strcmp(kind, "shm") == 0) ? avail : 0,
               region_off,
               size,
               stride,
               iters,
               dt,
               ns_per);
    } else {
        printf("[*] kind=%s\n", kind);
        if (path) printf("[*] path=%s\n", path);
        if (strcmp(kind, "shm") == 0) {
            printf("[*] map_offset=%zu map_len=%zu region_off=%zu\n", map_offset, avail, region_off);
        }
        printf("[*] size=%zu stride=%zu nlines=%u iters=%" PRIu64 "\n", size, stride, nlines, iters);
        printf("[+] total_ns=%" PRIu64 " ns_per_access=%.3f (sink=%" PRIuPTR ")\n", dt, ns_per, (uintptr_t)p);
        printf("[CSV] ");
        printf("%s,%s,%zu,%zu,%zu,%zu,%zu,%" PRIu64 ",%" PRIu64 ",%.3f\n",
               kind,
               path ? path : "",
               map_offset,
               (kind && strcmp(kind, "shm") == 0) ? avail : 0,
               region_off,
               size,
               stride,
               iters,
               dt,
               ns_per);
    }

    free(perm);
    if (strcmp(kind, "private") == 0) {
        free((void *)base);
    } else {
        mapping_close(&shm);
    }
    return 0;
}

