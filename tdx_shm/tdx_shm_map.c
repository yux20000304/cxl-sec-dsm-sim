#define _POSIX_C_SOURCE 200809L

#include "tdx_shm_map.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int read_hex_u32_file(const char *path, unsigned *out_value) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -errno;
    }

    char buf[64];
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return -EIO;
    }
    fclose(fp);

    errno = 0;
    unsigned long value = strtoul(buf, NULL, 0);
    if (errno != 0) {
        return -errno;
    }

    *out_value = (unsigned)value;
    return 0;
}

static int read_uio_map_size(const char *uio_dev, int map_index, size_t *out_size) {
    const char *base = strrchr(uio_dev, '/');
    const char *uio_name = base ? base + 1 : uio_dev;
    char sysfs_path[256];

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/uio/%s/maps/map%d/size", uio_name, map_index);
    FILE *fp = fopen(sysfs_path, "r");
    if (!fp) {
        return -errno;
    }

    char buf[64];
    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return -EIO;
    }
    fclose(fp);

    errno = 0;
    unsigned long long value = strtoull(buf, NULL, 0);
    if (errno != 0) {
        return -errno;
    }

    *out_size = (size_t)value;
    return 0;
}

int tdx_shm_map_file(const char *path, size_t size, int create, struct tdx_shm_mapping *out) {
    if (!path || !out) {
        return -EINVAL;
    }

    if (create && size == 0U) {
        return -EINVAL;
    }

    int flags = O_RDWR;
    if (create) {
        flags |= O_CREAT;
    }

    int fd = open(path, flags, 0600);
    if (fd < 0) {
        return -errno;
    }

    size_t map_size = size;
    if (create) {
        if (ftruncate(fd, (off_t)size) != 0) {
            int err = errno;
            close(fd);
            return -err;
        }
    } else {
        struct stat st;
        if (fstat(fd, &st) != 0) {
            int err = errno;
            close(fd);
            return -err;
        }
        if (st.st_size <= 0) {
            close(fd);
            return -EINVAL;
        }
        map_size = (size_t)st.st_size;
    }

    void *addr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        int err = errno;
        close(fd);
        return -err;
    }

    out->addr = addr;
    out->size = map_size;
    out->fd = fd;
    return 0;
}

int tdx_shm_map_uio(const char *uio_dev, struct tdx_shm_mapping *out) {
    if (!uio_dev || !out) {
        return -EINVAL;
    }

    int best_map = -1;
    size_t best_size = 0U;
    for (int map_index = 0; map_index < 8; ++map_index) {
        size_t map_size = 0U;
        int rc = read_uio_map_size(uio_dev, map_index, &map_size);
        if (rc != 0) {
            continue;
        }
        if (map_size > best_size) {
            best_size = map_size;
            best_map = map_index;
        }
    }
    if (best_map < 0 || best_size == 0U) {
        return -ENOENT;
    }

    int fd = open(uio_dev, O_RDWR);
    if (fd < 0) {
        return -errno;
    }

    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size <= 0) {
        int err = errno ? errno : EINVAL;
        close(fd);
        return -err;
    }

    off_t offset = (off_t)best_map * (off_t)page_size;
    void *addr = mmap(NULL, best_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    if (addr == MAP_FAILED) {
        int err = errno;
        close(fd);
        return -err;
    }

    out->addr = addr;
    out->size = best_size;
    out->fd = fd;
    return 0;
}

int tdx_shm_map_pci_resource(const char *bdf, int resource_index, struct tdx_shm_mapping *out) {
    if (!bdf || !out || resource_index < 0) {
        return -EINVAL;
    }

    char path[256];
    snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/resource%d", bdf, resource_index);

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        return -errno;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int err = errno;
        close(fd);
        return -err;
    }
    if (st.st_size <= 0) {
        close(fd);
        return -EINVAL;
    }

    size_t map_size = (size_t)st.st_size;
    void *addr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        int err = errno;
        close(fd);
        return -err;
    }

    out->addr = addr;
    out->size = map_size;
    out->fd = fd;
    return 0;
}

int tdx_shm_map_pci_resource_by_id(unsigned vendor_id, unsigned device_id, int resource_index, struct tdx_shm_mapping *out) {
    if (!out) {
        return -EINVAL;
    }

    DIR *dir = opendir("/sys/bus/pci/devices");
    if (!dir) {
        return -errno;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }

        char vendor_path[512];
        char device_path[512];
        snprintf(vendor_path, sizeof(vendor_path), "/sys/bus/pci/devices/%s/vendor", entry->d_name);
        snprintf(device_path, sizeof(device_path), "/sys/bus/pci/devices/%s/device", entry->d_name);

        unsigned found_vendor = 0U;
        unsigned found_device = 0U;
        if (read_hex_u32_file(vendor_path, &found_vendor) != 0) {
            continue;
        }
        if (read_hex_u32_file(device_path, &found_device) != 0) {
            continue;
        }

        if (found_vendor == vendor_id && found_device == device_id) {
            int rc = tdx_shm_map_pci_resource(entry->d_name, resource_index, out);
            closedir(dir);
            return rc;
        }
    }

    closedir(dir);
    return -ENOENT;
}

int tdx_shm_map_ivshmem_resource2(struct tdx_shm_mapping *out) {
    return tdx_shm_map_pci_resource_by_id(0x1af4U, 0x1110U, 2, out);
}

void tdx_shm_unmap(struct tdx_shm_mapping *mapping) {
    if (!mapping || !mapping->addr) {
        return;
    }

    munmap(mapping->addr, mapping->size);
    close(mapping->fd);
    mapping->addr = NULL;
    mapping->size = 0U;
    mapping->fd = -1;
}

