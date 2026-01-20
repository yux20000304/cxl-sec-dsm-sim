#ifndef TDX_SHM_TRANSPORT_H
#define TDX_SHM_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

// Shared-memory transport designed for TDX guests using ivshmem-plain BAR2.
// Layout: header + queue(1->2) + queue(2->1). Each queue is SPSC with fixed slots.

#define TDX_SHM_MAGIC 0x5444584dU /* 'TDXM' */
#define TDX_SHM_VERSION 2U

#define TDX_SHM_SLOT_SIZE 4096U
#define TDX_SHM_QUEUE_CAPACITY 1024U
#define TDX_SHM_DEFAULT_TOTAL_SIZE (16U * 1024U * 1024U)
#define TDX_SHM_MSG_MAX (TDX_SHM_SLOT_SIZE - 2U) /* u16 length prefix */

struct tdx_shm_queue {
    atomic_uint head;
    atomic_uint tail;
    uint32_t capacity;
    uint32_t slot_size;
    uint32_t data_offset;
    uint32_t reserved;
};

struct tdx_shm_header {
    uint32_t magic;
    uint32_t version;
    uint64_t total_size;
    uint32_t flags;
    uint32_t reserved0;
    struct tdx_shm_queue q12;
    struct tdx_shm_queue q21;
    uint8_t padding[64];
};

struct tdx_shm_queue_view {
    struct tdx_shm_queue *q;
    uint8_t *data;
};

struct tdx_shm_region {
    struct tdx_shm_header *hdr;
    struct tdx_shm_queue_view q12;
    struct tdx_shm_queue_view q21;
};

int tdx_shm_region_init(void *base, size_t size);
int tdx_shm_region_attach(void *base, size_t size, struct tdx_shm_region *out);
int tdx_shm_queue_send(struct tdx_shm_queue_view *view, const void *data, size_t len);
int tdx_shm_queue_recv(struct tdx_shm_queue_view *view, void *out, size_t out_cap, size_t *out_len);

#endif
