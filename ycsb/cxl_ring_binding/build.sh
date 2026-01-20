#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-${SRC_DIR}/build}"
YCSB_HOME="${YCSB_HOME:-}"

if [[ -z "${YCSB_HOME}" ]]; then
  echo "[!] YCSB_HOME is required (path to unpacked YCSB distribution)" >&2
  exit 1
fi
if [[ ! -d "${YCSB_HOME}/lib" ]]; then
  echo "[!] YCSB_HOME does not look like a YCSB distribution: ${YCSB_HOME}" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}/classes" "${OUT_DIR}/jni"

JAVA_HOME="${JAVA_HOME:-}"
if [[ -z "${JAVA_HOME}" ]]; then
  javac_path="$(command -v javac || true)"
  if [[ -z "${javac_path}" ]]; then
    echo "[!] javac not found; install a JDK (e.g. default-jdk)" >&2
    exit 1
  fi
  javac_real="$(readlink -f "${javac_path}" || true)"
  if [[ -z "${javac_real}" ]]; then
    javac_real="${javac_path}"
  fi
  JAVA_HOME="$(cd "$(dirname "${javac_real}")/.." && pwd)"
fi

echo "[*] Building Java binding (javac + jar) ..."
javac -h "${OUT_DIR}/jni" \
  -cp "${YCSB_HOME}/lib/*" \
  -d "${OUT_DIR}/classes" \
  "${SRC_DIR}/src/site/ycsb/db/CxlRingClient.java"

jar cf "${OUT_DIR}/cxl-ycsb-binding.jar" -C "${OUT_DIR}/classes" .

echo "[*] Building JNI shared library ..."
gcc -O2 -fPIC -shared \
  -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/linux" \
  -I"${OUT_DIR}/jni" \
  -o "${OUT_DIR}/libcxlringjni.so" \
  "${SRC_DIR}/jni/cxlringjni.c" \
  -lsodium

echo "[+] Built:"
echo "    ${OUT_DIR}/cxl-ycsb-binding.jar"
echo "    ${OUT_DIR}/libcxlringjni.so"
