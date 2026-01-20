CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?=

COMMON_SRCS = tdx_shm_transport.c tdx_shm_map.c
BIN ?= tdx_shm_init tdx_shm_agent tdx_shm_ping_pong

all: $(BIN)

tdx_shm_init: tdx_shm_init.c $(COMMON_SRCS) tdx_shm_transport.h tdx_shm_map.h
	$(CC) $(CFLAGS) -o $@ tdx_shm_init.c $(COMMON_SRCS) $(LDFLAGS)

tdx_shm_agent: tdx_shm_agent.c $(COMMON_SRCS) tdx_shm_transport.h tdx_shm_map.h
	$(CC) $(CFLAGS) -pthread -o $@ tdx_shm_agent.c $(COMMON_SRCS) $(LDFLAGS)

tdx_shm_ping_pong: tdx_shm_ping_pong.c $(COMMON_SRCS) tdx_shm_transport.h tdx_shm_map.h
	$(CC) $(CFLAGS) -o $@ tdx_shm_ping_pong.c $(COMMON_SRCS) $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean

