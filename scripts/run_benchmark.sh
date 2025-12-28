#!/usr/bin/env bash
set -euo pipefail

# Run redis-benchmark against the shim (default: localhost:6380) and
# save the output into project-local results/ directory.
#
# Usage (inside VM2):
#   bash scripts/run_benchmark.sh
#   bash scripts/run_benchmark.sh --host 127.0.0.1 --port 6380 --requests 5000 --clients 50 --tests set,get

HOST="127.0.0.1"
PORT=6380
REQUESTS=10000
CLIENTS=50
TESTS="set,get"
OUTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/results"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --requests) REQUESTS="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --tests) TESTS="$2"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--host 127.0.0.1] [--port 6380] [--requests 10000] [--clients 50] [--tests set,get]
Runs redis-benchmark and saves output under results/ with a timestamped filename.
EOF
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

mkdir -p "${OUTDIR}"
ts="$(date +%Y%m%d_%H%M%S)"
outfile="${OUTDIR}/redis_bench_${HOST}_${PORT}_${ts}.log"

echo "[*] Running redis-benchmark to ${HOST}:${PORT}, requests=${REQUESTS}, clients=${CLIENTS}, tests=${TESTS}"
redis-benchmark -h "${HOST}" -p "${PORT}" -t "${TESTS}" -n "${REQUESTS}" -c "${CLIENTS}" | tee "${outfile}"
echo "[+] Saved benchmark output to ${outfile}"
