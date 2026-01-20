#include "tdx_shm_transport.h"

#include <errno.h>
#include <string.h>

static size_t align_up(size_t value, size_t align) {
    return (value + align - 1U) & ~(align - 1U);
}

static uint32_t ring_next(uint32_t value, uint32_t capacity) {
    return (value + 1U) % capacity;
}

int tdx_shm_region_init(void *base, size_t size) {
    size_t header_size = align_up(sizeof(struct tdx_shm_header), 64U);
    size_t queue_bytes = (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE;
    size_t needed = header_size + (2U * queue_bytes);

    if (!base || size < needed) {
        return -EINVAL;
    }

    memset(base, 0, needed);

    struct tdx_shm_header *hdr = (struct tdx_shm_header *)base;
    hdr->magic = TDX_SHM_MAGIC;
    hdr->version = TDX_SHM_VERSION;
    hdr->total_size = (uint64_t)size;
    hdr->flags = 0U;

    hdr->q12.capacity = TDX_SHM_QUEUE_CAPACITY;
    hdr->q12.slot_size = TDX_SHM_SLOT_SIZE;
    hdr->q12.data_offset = (uint32_t)header_size;

    hdr->q21.capacity = TDX_SHM_QUEUE_CAPACITY;
    hdr->q21.slot_size = TDX_SHM_SLOT_SIZE;
    hdr->q21.data_offset = (uint32_t)(header_size + queue_bytes);

    atomic_store_explicit(&hdr->q12.head, 0U, memory_order_relaxed);
    atomic_store_explicit(&hdr->q12.tail, 0U, memory_order_relaxed);
    atomic_store_explicit(&hdr->q21.head, 0U, memory_order_relaxed);
    atomic_store_explicit(&hdr->q21.tail, 0U, memory_order_relaxed);

    return 0;
}

int tdx_shm_region_attach(void *base, size_t size, struct tdx_shm_region *out) {
    if (!base || !out) {
        return -EINVAL;
    }

    struct tdx_shm_header *hdr = (struct tdx_shm_header *)base;
    if (hdr->magic != TDX_SHM_MAGIC || hdr->version != TDX_SHM_VERSION) {
        return -EINVAL;
    }
    if (hdr->total_size > (uint64_t)size) {
        return -EINVAL;
    }
    if (hdr->q12.slot_size != TDX_SHM_SLOT_SIZE || hdr->q21.slot_size != TDX_SHM_SLOT_SIZE) {
        return -EINVAL;
    }
    if (hdr->q12.capacity != TDX_SHM_QUEUE_CAPACITY || hdr->q21.capacity != TDX_SHM_QUEUE_CAPACITY) {
        return -EINVAL;
    }

    size_t queue_bytes = (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE;
    if ((size_t)hdr->q12.data_offset + queue_bytes > size) {
        return -EINVAL;
    }
    if ((size_t)hdr->q21.data_offset + queue_bytes > size) {
        return -EINVAL;
    }

    out->hdr = hdr;
    out->q12.q = &hdr->q12;
    out->q12.data = (uint8_t *)base + hdr->q12.data_offset;
    out->q21.q = &hdr->q21;
    out->q21.data = (uint8_t *)base + hdr->q21.data_offset;
    return 0;
}

int tdx_shm_queue_send(struct tdx_shm_queue_view *view, const void *data, size_t len) {
    if (!view || !view->q || !view->data || !data) {
        return -EINVAL;
    }
    if (len > TDX_SHM_MSG_MAX) {
        return -EMSGSIZE;
    }

    struct tdx_shm_queue *q = view->q;
    uint32_t cap = q->capacity;
    if (cap == 0U || q->slot_size < 2U) {
        return -EINVAL;
    }

    uint32_t head = (uint32_t)atomic_load_explicit(&q->head, memory_order_acquire);
    uint32_t tail = (uint32_t)atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint32_t next = ring_next(tail, cap);

    if (next == head) {
        return -EAGAIN;
    }

    uint8_t *slot = view->data + ((size_t)tail * q->slot_size);
    uint16_t msg_len = (uint16_t)len;
    memcpy(slot, &msg_len, sizeof(msg_len));
    if (len > 0) {
        memcpy(slot + sizeof(msg_len), data, len);
    }

    atomic_store_explicit(&q->tail, (unsigned)next, memory_order_release);
    return 0;
}

int tdx_shm_queue_recv(struct tdx_shm_queue_view *view, void *out, size_t out_cap, size_t *out_len) {
    if (!view || !view->q || !view->data || !out || !out_len) {
        return -EINVAL;
    }

    struct tdx_shm_queue *q = view->q;
    uint32_t cap = q->capacity;
    if (cap == 0U || q->slot_size < 2U) {
        return -EINVAL;
    }

    uint32_t head = (uint32_t)atomic_load_explicit(&q->head, memory_order_relaxed);
    uint32_t tail = (uint32_t)atomic_load_explicit(&q->tail, memory_order_acquire);

    if (head == tail) {
        return -EAGAIN;
    }

    uint8_t *slot = view->data + ((size_t)head * q->slot_size);
    uint16_t msg_len = 0U;
    memcpy(&msg_len, slot, sizeof(msg_len));
    if ((size_t)msg_len > out_cap) {
        return -EMSGSIZE;
    }

    if (msg_len > 0) {
        memcpy(out, slot + sizeof(msg_len), msg_len);
    }
    *out_len = (size_t)msg_len;

    atomic_store_explicit(&q->head, (unsigned)ring_next(head, cap), memory_order_release);
    return 0;
}

