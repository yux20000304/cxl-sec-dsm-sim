CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?=

BIN ?= cxl_ring_client cxl_ring_direct

all: $(BIN)

cxl_ring_client: cxl_ring_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

cxl_ring_direct: cxl_ring_direct.c
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
