#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <path> <size-bytes>\n", prog);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        usage(argv[0]);
        return 2;
    }

    const char *path = argv[1];
    errno = 0;
    unsigned long long size_ull = strtoull(argv[2], NULL, 0);
    if (errno != 0 || size_ull == 0) {
        fprintf(stderr, "[!] invalid size: %s\n", argv[2]);
        return 2;
    }

    if (size_ull > (unsigned long long)SIZE_MAX) {
        fprintf(stderr, "[!] size too large for this platform: %llu\n", size_ull);
        return 2;
    }
    size_t size = (size_t)size_ull;

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[!] open(%s) failed: %s\n", path, strerror(errno));
        return 1;
    }

    if (ftruncate(fd, (off_t)size) != 0) {
        fprintf(stderr, "[!] ftruncate(%s, %zu) failed: %s\n", path, size, strerror(errno));
        close(fd);
        return 1;
    }

    unsigned char *mm = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mm == MAP_FAILED) {
        fprintf(stderr, "[!] mmap(%s, %zu) failed: %s\n", path, size, strerror(errno));
        close(fd);
        return 1;
    }

    const size_t page = 4096;
    for (size_t off = 0; off < size; off += page) {
        mm[off] = 0;
    }
    if (size > 0) mm[size - 1] = 0;

    munmap(mm, size);
    close(fd);
    return 0;
}

