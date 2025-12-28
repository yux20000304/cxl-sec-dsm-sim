SGX_SIGNER_KEY ?= redis-signer-key.pem
SGX_SIZE ?= 1024M
SGX_THREADS ?= 64
LOG_LEVEL ?= warning

all: redis.manifest redis.manifest.sgx redis.token

redis.manifest: redis.manifest.template redis.conf
	gramine-manifest -Dsgx_size=$(SGX_SIZE) -Dsgx_threads=$(SGX_THREADS) -Dlog_level=$(LOG_LEVEL) $< $@

$(SGX_SIGNER_KEY):
	openssl genrsa -out $@ 3072

redis.manifest.sgx redis.sig: redis.manifest $(SGX_SIGNER_KEY)
	gramine-sgx-sign --manifest $< --output $@ --key $(SGX_SIGNER_KEY)

redis.token: redis.sig
	gramine-sgx-get-token --sig redis.sig --output $@

clean:
	rm -f redis.manifest redis.manifest.sgx redis.sig redis.token

.PHONY: all clean
