SGX_SIGNER_KEY ?= redis-signer-key.pem
SGX_SIZE ?= 1024M
SGX_THREADS ?= 64
LOG_LEVEL ?= warning

# Ring device defaults (ivshmem BAR2 via sysfs).
# - CXL_RING_PATH: host/guest kernel path to the BAR2 resource file
CXL_RING_PATH ?= /sys/bus/pci/devices/0000:00:02.0/resource2
CXL_RING_COUNT ?= 4
CXL_RING_MAP_SIZE ?= 134217728

# 0 = use guest system libc (recommended for direct mode)
# 1 = use Gramine runtime glibc (closer to SGX mode)
USE_RUNTIME_GLIBC ?= 0

MANIFEST_COMMON_DEFS = -Dsgx_size=$(SGX_SIZE) -Dsgx_threads=$(SGX_THREADS) -Dlog_level=$(LOG_LEVEL)
MANIFEST_RING_DEFS = -Dcxl_ring_path="$(CXL_RING_PATH)" -Dcxl_ring_count="$(CXL_RING_COUNT)" -Dcxl_ring_map_size="$(CXL_RING_MAP_SIZE)"

all: native ring

native: redis-native.manifest
ring: redis-ring.manifest

links:
	ln -sfn /usr/bin/redis-server redis-native
	ln -sfn ../redis/src/redis-server redis-ring

redis-native.manifest: redis-native.manifest.template redis.conf
	USE_RUNTIME_GLIBC="$(USE_RUNTIME_GLIBC)" gramine-manifest $(MANIFEST_COMMON_DEFS) $< $@

redis-ring.manifest: redis-ring.manifest.template redis.conf
	USE_RUNTIME_GLIBC="$(USE_RUNTIME_GLIBC)" gramine-manifest $(MANIFEST_COMMON_DEFS) $(MANIFEST_RING_DEFS) $< $@

$(SGX_SIGNER_KEY):
	openssl genrsa -out $@ 3072

# Optional SGX artifacts (not needed for `gramine-direct`).
sgx: redis-native.manifest.sgx redis-ring.manifest.sgx

redis-native.manifest.sgx: redis-native.manifest $(SGX_SIGNER_KEY)
	gramine-sgx-sign --manifest $< --output $@ --key $(SGX_SIGNER_KEY)

redis-ring.manifest.sgx: redis-ring.manifest $(SGX_SIGNER_KEY)
	gramine-sgx-sign --manifest $< --output $@ --key $(SGX_SIGNER_KEY)

clean:
	rm -f *.manifest *.manifest.sgx *.sig *.token $(SGX_SIGNER_KEY)

.PHONY: all native ring links sgx clean
