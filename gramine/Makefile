SGX_SIGNER_KEY ?= redis-signer-key.pem
SGX_SIZE ?= 1024M
SGX_THREADS ?= 64
SGX_DEBUG ?= 0
LOG_LEVEL ?= warning

# Ring device defaults (ivshmem BAR2 via sysfs).
# - CXL_RING_PATH: host/guest kernel path to the BAR2 resource file
CXL_RING_PATH ?= /sys/bus/pci/devices/0000:00:02.0/resource2
CXL_RING_COUNT ?= 4
CXL_RING_MAP_SIZE ?= 134217728

# GAPBS defaults.
GAPBS_KERNEL ?= bfs

# 0 = use guest system libc (recommended for direct mode)
# 1 = use Gramine runtime glibc (closer to SGX mode)
USE_RUNTIME_GLIBC ?= 0

MANIFEST_COMMON_DEFS = -Dsgx_size=$(SGX_SIZE) -Dsgx_threads=$(SGX_THREADS) -Dlog_level=$(LOG_LEVEL) -Dsgx_debug=$(SGX_DEBUG)
MANIFEST_RING_DEFS = -Dcxl_ring_path="$(CXL_RING_PATH)" -Dcxl_ring_count="$(CXL_RING_COUNT)" -Dcxl_ring_map_size="$(CXL_RING_MAP_SIZE)"
MANIFEST_GAPBS_DEFS = -Dgapbs_kernel="$(GAPBS_KERNEL)" -Dgapbs_cxl_path="$(CXL_RING_PATH)" -Dgapbs_cxl_map_size="$(CXL_RING_MAP_SIZE)"

all: native ring

native: redis-native.manifest
ring: redis-ring.manifest

links:
	ln -sfn /usr/bin/redis-server redis-native
	ln -sfn ../redis/src/redis-server redis-ring
	ln -sfn ../gapbs/$(GAPBS_KERNEL) gapbs-native
	ln -sfn ../gapbs/$(GAPBS_KERNEL)-ring gapbs-ring
	ln -sfn ../gapbs/$(GAPBS_KERNEL)-ring-secure gapbs-ring-secure

gapbs-native.manifest: gapbs-native.manifest.template
	USE_RUNTIME_GLIBC="$(USE_RUNTIME_GLIBC)" gramine-manifest $(MANIFEST_COMMON_DEFS) -Dgapbs_kernel="$(GAPBS_KERNEL)" $< $@

gapbs-ring.manifest: gapbs-ring.manifest.template
	USE_RUNTIME_GLIBC="$(USE_RUNTIME_GLIBC)" gramine-manifest $(MANIFEST_COMMON_DEFS) $(MANIFEST_GAPBS_DEFS) $< $@

gapbs-ring-secure.manifest: gapbs-ring-secure.manifest.template
	USE_RUNTIME_GLIBC="$(USE_RUNTIME_GLIBC)" gramine-manifest $(MANIFEST_COMMON_DEFS) $(MANIFEST_GAPBS_DEFS) $< $@

redis-native.manifest: redis-native.manifest.template redis.conf
	USE_RUNTIME_GLIBC="$(USE_RUNTIME_GLIBC)" gramine-manifest $(MANIFEST_COMMON_DEFS) $< $@

redis-ring.manifest: redis-ring.manifest.template redis.conf
	USE_RUNTIME_GLIBC="$(USE_RUNTIME_GLIBC)" gramine-manifest $(MANIFEST_COMMON_DEFS) $(MANIFEST_RING_DEFS) $< $@

$(SGX_SIGNER_KEY):
	# Gramine SGX signing requires RSA public exponent 3.
	openssl genrsa -3 -out $@ 3072

# Optional SGX artifacts (not needed for `gramine-direct`).
sgx: sgx-sign

# Sign manifests (does not require SGX hardware).
sgx-sign: redis-native.manifest.sgx redis-ring.manifest.sgx

# Fetch launch tokens (requires SGX driver + AESM on the machine).
sgx-token: redis-native.token redis-ring.token

# GAPBS SGX artifacts (separate targets so Redis-only scripts don't require GAPBS binaries).
sgx-gapbs: sgx-sign-gapbs
sgx-sign-gapbs: gapbs-native.manifest.sgx gapbs-ring.manifest.sgx gapbs-ring-secure.manifest.sgx
sgx-token-gapbs: gapbs-native.token gapbs-ring.token gapbs-ring-secure.token

redis-native.manifest.sgx redis-native.sig: redis-native.manifest $(SGX_SIGNER_KEY)
	gramine-sgx-sign --manifest $< --output redis-native.manifest.sgx --key $(SGX_SIGNER_KEY)

redis-ring.manifest.sgx redis-ring.sig: redis-ring.manifest $(SGX_SIGNER_KEY)
	gramine-sgx-sign --manifest $< --output redis-ring.manifest.sgx --key $(SGX_SIGNER_KEY)

redis-native.token: redis-native.sig
	gramine-sgx-get-token --output $@ --sig $<

redis-ring.token: redis-ring.sig
	gramine-sgx-get-token --output $@ --sig $<

gapbs-native.manifest.sgx gapbs-native.sig: gapbs-native.manifest $(SGX_SIGNER_KEY)
	gramine-sgx-sign --manifest $< --output gapbs-native.manifest.sgx --key $(SGX_SIGNER_KEY)

gapbs-ring.manifest.sgx gapbs-ring.sig: gapbs-ring.manifest $(SGX_SIGNER_KEY)
	gramine-sgx-sign --manifest $< --output gapbs-ring.manifest.sgx --key $(SGX_SIGNER_KEY)

gapbs-ring-secure.manifest.sgx gapbs-ring-secure.sig: gapbs-ring-secure.manifest $(SGX_SIGNER_KEY)
	gramine-sgx-sign --manifest $< --output gapbs-ring-secure.manifest.sgx --key $(SGX_SIGNER_KEY)

gapbs-native.token: gapbs-native.sig
	gramine-sgx-get-token --output $@ --sig $<

gapbs-ring.token: gapbs-ring.sig
	gramine-sgx-get-token --output $@ --sig $<

gapbs-ring-secure.token: gapbs-ring-secure.sig
	gramine-sgx-get-token --output $@ --sig $<

clean:
	rm -f *.manifest *.manifest.sgx *.sig *.token $(SGX_SIGNER_KEY)

.PHONY: all native ring links sgx sgx-sign sgx-token sgx-gapbs sgx-sign-gapbs sgx-token-gapbs clean
