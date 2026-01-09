CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?= -pthread -lsodium

BIN ?= cxl_sodium_tunnel

all: $(BIN)

$(BIN): cxl_sodium_tunnel.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
