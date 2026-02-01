#!/usr/bin/env bash
set -euo pipefail

# Profile redis-benchmark and estimate where time is spent.
# - Client-side breakdown uses strace -c summary grouped by syscall categories
#   to approximate: net_read, net_wait, net_write, other_sys, user_space.
# - Server-side time per command is taken from Redis INFO commandstats
#   (delta before/after) and compared to end-to-end per-op time.
#
# Recommended: use -c 1 --threads 1 -P 1 for per-op latency attribution.
# For throughput runs (c>1 or P>1), client breakdown is still valid but
# the server/E2E ratio is less meaningful.
#
# Usage examples (run on the client VM):
#   bash scripts/redis_bench_overhead.sh --host 127.0.0.1 --port 6379 \
#     --tests set,get --requests 20000 --clients 1 --threads 1 --pipeline 1 --datasize 256
#   bash scripts/redis_bench_overhead.sh --host 127.0.0.1 --port 6380 \
#     --tests set,get --requests 10000 --clients 1 --threads 1 --pipeline 1 --datasize 256 --label sodium

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTDIR="${ROOT}/results"
mkdir -p "${OUTDIR}"

HOST=127.0.0.1
PORT=6379
TESTS="set,get"
REQ=10000
CLIENTS=1
THREADS=1
PIPE=1
DSZ=3
LABEL=""
REDIS_CLI="$(command -v redis-cli || true)"
RBIN="${ROOT}/redis/src/redis-benchmark"

usage() {
  echo "Usage: $0 --host H --port P [--tests set,get] [--requests N] [--clients C] [--threads T] [--pipeline P] [--datasize D] [--label NAME]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --tests) TESTS="$2"; shift 2 ;;
    --requests) REQ="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --pipeline) PIPE="$2"; shift 2 ;;
    --datasize) DSZ="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -x "${RBIN}" ]]; then
  echo "[!] redis-benchmark not found at ${RBIN}" >&2
  exit 1
fi
if [[ -z "${REDIS_CLI}" ]]; then
  echo "[!] redis-cli not found in PATH" >&2
  exit 1
fi

# Output tag
TS="$(date +%Y%m%d_%H%M%S)"
TAG="rb_prof_${LABEL:+${LABEL}_}${HOST}_${PORT}_${TS}"

echo "[*] Pinging Redis at ${HOST}:${PORT} ..."
if ! "${REDIS_CLI}" -h "${HOST}" -p "${PORT}" ping >/dev/null 2>&1; then
  echo "[!] redis-cli PING failed at ${HOST}:${PORT}" >&2
  exit 1
fi

pre_cmdstats="${OUTDIR}/${TAG}_cmdstats_pre.txt"
post_cmdstats="${OUTDIR}/${TAG}_cmdstats_post.txt"
strace_sum="${OUTDIR}/${TAG}_strace.sum"
rb_log="${OUTDIR}/${TAG}_rb.log"

# Capture server-side per-command stats (before)
"${REDIS_CLI}" -h "${HOST}" -p "${PORT}" info commandstats >"${pre_cmdstats}" || true

cmd=("${RBIN}" -h "${HOST}" -p "${PORT}" -t "${TESTS}" -n "${REQ}" -c "${CLIENTS}" --threads "${THREADS}" -P "${PIPE}" -d "${DSZ}")

# Run with strace summary; measure elapsed time with built-in date
start_ts=$(date +%s.%N)
# Use env to avoid strace picking up shell builtins
( strace -f -c -S time -o "${strace_sum}" "${cmd[@]}" -q ) | tee "${rb_log}" >/dev/null
end_ts=$(date +%s.%N)

# Capture server-side per-command stats (after)
"${REDIS_CLI}" -h "${HOST}" -p "${PORT}" info commandstats >"${post_cmdstats}" || true

elapsed=$(awk -v s="${start_ts}" -v e="${end_ts}" 'BEGIN{printf "%.6f", (e-s)}')

# Parse strace summary and group syscall time.
read -r net_read net_write net_wait other_sys total_sys < <(
  awk '
    BEGIN{nr=0}
    /^% time/ {hdr=1; next}
    /^[ -]/ {next}
    NF<6 {next}
    {sec=$2; sc=$6; t[sc]+=sec; total+=sec}
    END{
      nr=1;
      # groups
      nread = t["read"]+t["readv"]+t["recv"]+t["recvfrom"]+t["recvmsg"]
      nwrite = t["write"]+t["writev"]+t["send"]+t["sendto"]+t["sendmsg"]
      nwait = t["poll"]+t["ppoll"]+t["select"]+t["pselect6"]+t["epoll_wait"]
      other = total-(nread+nwrite+nwait)
      if (nread<0) nread=0; if(nwrite<0) nwrite=0; if(nwait<0) nwait=0; if(other<0) other=0;
      printf "%.6f %.6f %.6f %.6f %.6f\n", nread, nwrite, nwait, other, total;
    }
  ' "${strace_sum}"
)

# Compute per-op and percentage breakdown (client-side)
ops=${REQ}
if [[ "${CLIENTS}" -gt 1 || "${THREADS}" -gt 1 || "${PIPE}" -gt 1 ]]; then
  echo "[!] Note: clients/threads/pipeline > 1, per-op E2E latency != elapsed/op; server ratio is approximate." >&2
fi

# Avoid division by zero
if [[ "${ops}" -le 0 ]]; then ops=1; fi

perop_us=$(awk -v e="${elapsed}" -v n="${ops}" 'BEGIN{printf "%.2f", (e*1e6)/n}')
user_space=$(awk -v e="${elapsed}" -v s="${total_sys}" 'BEGIN{u=e-s; if(u<0) u=0; printf "%.6f", u}')

net_read_us=$(awk -v x="${net_read}" -v n="${ops}" 'BEGIN{printf "%.2f", (x*1e6)/n}')
net_wait_us=$(awk -v x="${net_wait}" -v n="${ops}" 'BEGIN{printf "%.2f", (x*1e6)/n}')
net_write_us=$(awk -v x="${net_write}" -v n="${ops}" 'BEGIN{printf "%.2f", (x*1e6)/n}')
other_sys_us=$(awk -v x="${other_sys}" -v n="${ops}" 'BEGIN{printf "%.2f", (x*1e6)/n}')
user_us=$(awk -v x="${user_space}" -v n="${ops}" 'BEGIN{printf "%.2f", (x*1e6)/n}')

# Server-side per-op time from commandstats delta
parse_cmdstats_delta() {
  local pre_file="$1" post_file="$2" cmds_csv="$3"
  local total_usec=0 total_calls=0
  IFS=',' read -r -a arr <<<"${cmds_csv}"
  for cmd in "${arr[@]}"; do
    local key="cmdstat_${cmd}"
    local pre_line post_line
    pre_line=$(grep -E "^${key}:" "${pre_file}" || true)
    post_line=$(grep -E "^${key}:" "${post_file}" || true)
    if [[ -z "${post_line}" ]]; then continue; fi
    # Extract usec= and calls=
    local pre_calls=0 pre_usec=0 post_calls=0 post_usec=0
    if [[ -n "${pre_line}" ]]; then
      pre_calls=$(echo "${pre_line}" | sed -n 's/.*calls=\([0-9]\+\).*/\1/p')
      pre_usec=$(echo  "${pre_line}" | sed -n 's/.*usec=\([0-9]\+\).*/\1/p')
    fi
    post_calls=$(echo "${post_line}" | sed -n 's/.*calls=\([0-9]\+\).*/\1/p')
    post_usec=$(echo  "${post_line}" | sed -n 's/.*usec=\([0-9]\+\).*/\1/p')
    local d_calls=$(( post_calls - pre_calls ))
    local d_usec=$(( post_usec - pre_usec ))
    if [[ ${d_calls} -gt 0 && ${d_usec} -ge 0 ]]; then
      total_calls=$(( total_calls + d_calls ))
      total_usec=$(( total_usec + d_usec ))
    fi
  done
  echo "${total_calls} ${total_usec}"
}

read -r srv_calls srv_usec < <(parse_cmdstats_delta "${pre_cmdstats}" "${post_cmdstats}" "${TESTS}")
server_us_per_call="0.00"
server_ratio_pct="0.00"
if [[ "${srv_calls}" -gt 0 ]]; then
  server_us_per_call=$(awk -v u="${srv_usec}" -v c="${srv_calls}" 'BEGIN{printf "%.2f", u/c}')
  # Compare to E2E per-op
  server_ratio_pct=$(awk -v s="${server_us_per_call}" -v e="${perop_us}" 'BEGIN{ if(e>0){printf "%.1f", (s/e)*100}else{print "0.0"}}')
fi

# Print summary
cat <<SUM
[redis-benchmark overhead] ${HOST}:${PORT} label=${LABEL:-none}
- Run: tests=${TESTS} n=${REQ} c=${CLIENTS} threads=${THREADS} pipeline=${PIPE} datasize=${DSZ}
- Elapsed: ${elapsed}s; Ops: ${REQ}; Per-op E2E (avg by elapsed/op): ${perop_us} us/op

Client-side time per op (from strace, sums to client runtime):
- net_read (read/recv*):     ${net_read_us} us/op
- net_wait (poll/epoll/*):   ${net_wait_us} us/op
- net_write (write/send*):   ${net_write_us} us/op
- other_syscalls:            ${other_sys_us} us/op
- user_space (approx):       ${user_us} us/op

Server-side (from INFO commandstats, delta during run):
- server_time_per_call:      ${server_us_per_call} us/call
- server_time / E2E ratio:   ${server_ratio_pct}%  (note: included inside client net_read/wait)

Artifacts:
  ${rb_log}
  ${strace_sum}
  ${pre_cmdstats}
  ${post_cmdstats}
SUM

