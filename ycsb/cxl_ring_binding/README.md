## CXL ring YCSB binding (JNI)

This binding lets YCSB run on the project’s Redis **ring/secure-ring** path (shared ivshmem BAR2) by using the same binary ring protocol as `ring_client/cxl_ring_direct.c`.

It stores each YCSB record as a single Redis **string value** (encoded field map) and implements:
- insert/update/read/delete via ring `SET/GET/DEL`
- scan by generating sequential keys starting from `startkey` (expects keys with a numeric suffix, e.g. `user0000001234`)

### Build (inside VM2)
Prereqs:
- JDK (for JNI headers): `sudo apt-get install -y default-jdk`
- libsodium: `sudo apt-get install -y libsodium-dev`

Download/unpack YCSB (example: `/tmp/ycsb-0.17.0`), then:
```bash
OUT_DIR=/tmp/cxl-ycsb \
YCSB_HOME=/tmp/ycsb-0.17.0 \
bash /mnt/hostshare/ycsb/cxl_ring_binding/build.sh
```
Outputs:
- `/tmp/cxl-ycsb/cxl-ycsb-binding.jar`
- `/tmp/cxl-ycsb/libcxlringjni.so`

