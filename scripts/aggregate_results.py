#!/usr/bin/env python3
import csv
import json
import os
import re
import sys
from pathlib import Path


RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
OUT_CSV = RESULTS_DIR / "summary.csv"


def parse_redis_compare_csv(path: Path):
    rows = []
    with path.open(newline="") as f:
        r = csv.reader(f)
        header = next(r, None)
        if header == ["label", "op", "throughput_rps"]:
            for label, op, thr in r:
                rows.append({
                    "type": "redis-benchmark",
                    "source": path.name,
                    "label": label,
                    "op": op,
                    "throughput_rps": thr,
                })
    return rows


def parse_gapbs_compare_csv(path: Path):
    rows = []
    with path.open(newline="") as f:
        r = csv.reader(f)
        header = next(r, None)
        # Format A: local runner (scripts/host_bench_gapbs_local.sh)
        want_a = ["label", "kernel", "scale", "degree", "trials", "omp_threads", "avg_time_s"]
        # Format B: TDX dual-VM runner (scripts/host_recreate_and_bench_tdx.sh)
        want_b = [
            "label",
            "vm",
            "kernel",
            "scale",
            "degree",
            "trials",
            "omp_threads",
            "edge_traversals",
            "avg_time_s",
            "throughput_teps",
        ]
        if header == want_a:
            for label, kernel, scale, degree, trials, omp_threads, avg_time_s in r:
                rows.append(
                    {
                        "type": "gapbs",
                        "source": path.name,
                        "label": label,
                        "kernel": kernel,
                        "scale": scale,
                        "degree": degree,
                        "trials": trials,
                        "omp_threads": omp_threads,
                        "avg_time_s": avg_time_s,
                    }
                )
        elif header == want_b:
            for (
                label,
                vm,
                kernel,
                scale,
                degree,
                trials,
                omp_threads,
                edge_traversals,
                avg_time_s,
                throughput_teps,
            ) in r:
                rows.append(
                    {
                        "type": "gapbs",
                        "source": path.name,
                        "label": label,
                        "vm": vm,
                        "kernel": kernel,
                        "scale": scale,
                        "degree": degree,
                        "trials": trials,
                        "omp_threads": omp_threads,
                        "edge_traversals": edge_traversals,
                        "avg_time_s": avg_time_s,
                        "throughput_teps": throughput_teps,
                    }
                )
    return rows


def parse_ycsb_log(path: Path):
    # Filename: ycsb_<workload>_{load|run}_HOST_PORT_TIMESTAMP.log
    # Body lines like: [OVERALL], RunTime(ms), 12345
    #                  [OVERALL], Throughput(ops/sec), 6789.12
    #                  [READ], AverageLatency(us), 123
    m = re.match(r"ycsb_(?P<workload>[^_]+)_(?P<phase>load|run)_(?P<host>[^_]+)_(?P<port>\d+)_\d+\.log$", path.name)
    workload = m.group("workload") if m else ""
    phase = m.group("phase") if m else ""
    host = m.group("host") if m else ""
    port = m.group("port") if m else ""

    metrics = {}
    try:
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line or "," not in line:
                    continue
                # Expect CSV-like lines
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 3:
                    continue
                section = parts[0].strip("[] ")
                key = parts[1]
                val = parts[2]
                k = f"{section}.{key}"
                metrics[k] = val
    except Exception:
        return []

    row = {
        "type": "ycsb",
        "source": path.name,
        "workload": workload,
        "phase": phase,
        "host": host,
        "port": port,
        # Common
        "runtime_ms": metrics.get("OVERALL.RunTime(ms)", ""),
        "throughput_ops_sec": metrics.get("OVERALL.Throughput(ops/sec)", ""),
        # READ
        "read_avg_us": metrics.get("READ.AverageLatency(us)", ""),
        "read_p95_us": metrics.get("READ.95thPercentileLatency(us)", ""),
        "read_p99_us": metrics.get("READ.99thPercentileLatency(us)", ""),
        # UPDATE
        "update_avg_us": metrics.get("UPDATE.AverageLatency(us)", ""),
        "update_p95_us": metrics.get("UPDATE.95thPercentileLatency(us)", ""),
        "update_p99_us": metrics.get("UPDATE.99thPercentileLatency(us)", ""),
        # INSERT
        "insert_avg_us": metrics.get("INSERT.AverageLatency(us)", ""),
        "insert_p95_us": metrics.get("INSERT.95thPercentileLatency(us)", ""),
        "insert_p99_us": metrics.get("INSERT.99thPercentileLatency(us)", ""),
    }
    return [row]


def collect():
    rows = []
    if not RESULTS_DIR.exists():
        return rows
    for p in RESULTS_DIR.iterdir():
        if not p.is_file():
            continue
        name = p.name
        if name.endswith(".csv") and "compare" in name:
            # Try redis compare first
            rs = parse_redis_compare_csv(p)
            if rs:
                rows.extend(rs)
                continue
            # Try gapbs compare
            gs = parse_gapbs_compare_csv(p)
            if gs:
                rows.extend(gs)
                continue
        if name.startswith("ycsb_") and name.endswith(".log"):
            ys = parse_ycsb_log(p)
            rows.extend(ys)
    return rows


def write_csv(rows):
    # Union all keys for header stability
    keys = [
        "type", "source",
        "label", "op", "throughput_rps",
        "vm",
        "workload", "phase", "host", "port",
        "runtime_ms", "throughput_ops_sec",
        "read_avg_us", "read_p95_us", "read_p99_us",
        "update_avg_us", "update_p95_us", "update_p99_us",
        "insert_avg_us", "insert_p95_us", "insert_p99_us",
        "kernel", "scale", "degree", "trials", "omp_threads",
        "edge_traversals", "avg_time_s", "throughput_teps",
    ]
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, "") for k in keys})


def main():
    rows = collect()
    write_csv(rows)
    print(f"[+] Wrote {OUT_CSV} with {len(rows)} rows")


if __name__ == "__main__":
    sys.exit(main())
