#ifndef TDX_SHM_MAP_H
#define TDX_SHM_MAP_H

#include <stddef.h>

struct tdx_shm_mapping {
    void *addr;
    size_t size;
    int fd;
};

int tdx_shm_map_file(const char *path, size_t size, int create, struct tdx_shm_mapping *out);
int tdx_shm_map_uio(const char *uio_dev, struct tdx_shm_mapping *out);
int tdx_shm_map_pci_resource(const char *bdf, int resource_index, struct tdx_shm_mapping *out);
int tdx_shm_map_pci_resource_by_id(unsigned vendor_id, unsigned device_id, int resource_index, struct tdx_shm_mapping *out);
int tdx_shm_map_ivshmem_resource2(struct tdx_shm_mapping *out);
void tdx_shm_unmap(struct tdx_shm_mapping *mapping);

#endif

