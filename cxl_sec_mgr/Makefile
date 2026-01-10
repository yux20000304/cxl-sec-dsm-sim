CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?= -pthread -lsodium

BIN ?= cxl_sec_mgr

all: $(BIN)

$(BIN): cxl_sec_mgr.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
