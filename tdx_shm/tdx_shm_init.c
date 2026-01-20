#include "tdx_shm_map.h"
#include "tdx_shm_transport.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--path PATH] [--size BYTES|2M|4G]\n", prog);
}

static int parse_size(const char *arg, size_t *out) {
    if (!arg || !out) {
        return -EINVAL;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(arg, &end, 0);
    if (errno != 0) {
        return -errno;
    }

    unsigned long long multiplier = 1ULL;
    if (end && *end != '\0') {
        if (end[1] != '\0') {
            return -EINVAL;
        }
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
                return -EINVAL;
        }
    }

    if (multiplier != 0ULL && value > (ULLONG_MAX / multiplier)) {
        return -EOVERFLOW;
    }
    unsigned long long bytes = value * multiplier;
    if (bytes > (unsigned long long)SIZE_MAX) {
        return -EOVERFLOW;
    }

    *out = (size_t)bytes;
    return 0;
}

int main(int argc, char **argv) {
    const char *path = "/dev/shm/tdx_shm";
    size_t size = TDX_SHM_DEFAULT_TOTAL_SIZE;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            int rc = parse_size(argv[++i], &size);
            if (rc != 0) {
                fprintf(stderr, "invalid --size: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    struct tdx_shm_mapping mapping;
    int rc = tdx_shm_map_file(path, size, 1, &mapping);
    if (rc != 0) {
        fprintf(stderr, "tdx_shm_map_file failed: %s\n", strerror(-rc));
        return 1;
    }

    rc = tdx_shm_region_init(mapping.addr, mapping.size);
    if (rc != 0) {
        fprintf(stderr, "tdx_shm_region_init failed: %s\n", strerror(-rc));
        tdx_shm_unmap(&mapping);
        return 1;
    }

    printf("Initialized TDX shared memory at %s (%zu bytes).\n", path, mapping.size);
    tdx_shm_unmap(&mapping);
    return 0;
}

