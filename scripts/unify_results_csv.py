#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# Merge Redis + GAPBS benchmark outputs into a single "wide" CSV for analysis.
#
# Inputs (per timestamp, from scripts/host_recreate_and_bench_tdx.sh):
# - Redis:
#   - results/tdx_native_tcp_<ts>.log            (redis-benchmark text)
#   - results/tdx_sodium_tcp_<ts>.log            (redis-benchmark text)
#   - results/tdx_ring_<ts>.csv                  (cxl_ring_direct --csv)
#   - results/tdx_ring_secure_<ts>.csv           (cxl_ring_direct --csv)
# - GAPBS:
#   - results/tdx_gapbs_compare_<kernel>_<ts>.csv
#   - results/tdx_gapbs_overhead_<kernel>_<ts>.csv
#
# Output:
# - One CSV with a superset schema; columns not applicable to a row are blank.

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


UNIFIED_FIELDS: List[str] = [
    # Run identity
    "ts",
    "app",  # redis|gapbs
    "scenario",  # e.g., TDXNativeTCP / TDXRing / TDXGapbsMultihostCrypto
    "run_label",  # e.g., tdx_ring_2026... (when available)
    "vm",  # vm1|vm2|avg (gapbs); vm2 for redis client-side runs when known
    "op",  # SET|GET (redis)
    "kernel",  # bfs|sssp|...
    "threads",  # redis threads / OMP threads
    # Redis metrics/config (microseconds for latency columns)
    "throughput_rps",
    "avg_us",
    "min_us",
    "p50_us",
    "p75_us",
    "p90_us",
    "p95_us",
    "p99_us",
    "p99_9_us",
    "p99_99_us",
    "max_us",
    "rings",
    "requests",
    "pipeline",
    "max_inflight",
    "push_retries",
    "sleep_ms",
    # GAPBS metrics/config
    "scale",
    "degree",
    "trials",
    "edge_traversals",
    "avg_time_s",
    "throughput_teps",
    "attach_total_ms",
    "attach_wait_ms",
    "attach_decrypt_ms",
    "attach_pretouch_ms",
    # Traceability
    "source_file",
]


def _to_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except Exception:
        return None


def _to_float(s: str) -> Optional[float]:
    try:
        return float(s)
    except Exception:
        return None


def _format_num(v: Optional[float]) -> str:
    if v is None:
        return ""
    if abs(v) >= 1e9:
        return f"{v:.0f}"
    # Keep CSV reasonably stable; avoid scientific notation for common ranges.
    if abs(v - round(v)) < 1e-9:
        return f"{v:.0f}"
    return f"{v:.6f}".rstrip("0").rstrip(".")


def _format_int(v: Optional[int]) -> str:
    return "" if v is None else str(v)


def _quantile_from_points(points: List[Tuple[float, float]], q: float) -> Optional[float]:
    """Linear interpolation over (percentile, value_ms) points."""
    if not points:
        return None
    pts = sorted(points, key=lambda x: x[0])
    if q <= pts[0][0]:
        return pts[0][1]
    if q >= pts[-1][0]:
        return pts[-1][1]
    for i in range(len(pts) - 1):
        p0, v0 = pts[i]
        p1, v1 = pts[i + 1]
        if p0 <= q <= p1:
            if p1 == p0:
                return v1
            t = (q - p0) / (p1 - p0)
            return v0 + (v1 - v0) * t
    return pts[-1][1]


@dataclass
class RedisSummary:
    op: str
    throughput_rps: Optional[float]
    threads: Optional[int]
    avg_ms: Optional[float]
    min_ms: Optional[float]
    p50_ms: Optional[float]
    p95_ms: Optional[float]
    p99_ms: Optional[float]
    max_ms: Optional[float]
    percentile_points_ms: List[Tuple[float, float]]


def parse_redis_benchmark_log(path: Path) -> List[RedisSummary]:
    txt = path.read_text(errors="replace").replace("\r", "")
    parts = re.split(r"^====== ([A-Z]+) ======\n", txt, flags=re.M)
    if len(parts) < 3:
        return []

    out: List[RedisSummary] = []
    # parts = [pre, op1, block1, op2, block2, ...]
    for i in range(1, len(parts), 2):
        if i + 1 >= len(parts):
            break
        op = parts[i].strip().upper()
        block = parts[i + 1]

        thr = None
        m_thr = re.search(r"throughput summary:\s*([0-9.]+)\s+requests per second", block)
        if m_thr:
            thr = _to_float(m_thr.group(1))

        threads = None
        m_threads = re.search(r"^\s*threads:\s*([0-9]+)\s*$", block, flags=re.M)
        if m_threads:
            threads = _to_int(m_threads.group(1))

        avg_ms = min_ms = p50_ms = p95_ms = p99_ms = max_ms = None
        m_lat = re.search(
            r"latency summary \(msec\):\s*\n\s*avg\s*min\s*p50\s*p95\s*p99\s*max\s*\n\s*([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)",
            block,
            flags=re.S,
        )
        if m_lat:
            avg_ms = _to_float(m_lat.group(1))
            min_ms = _to_float(m_lat.group(2))
            p50_ms = _to_float(m_lat.group(3))
            p95_ms = _to_float(m_lat.group(4))
            p99_ms = _to_float(m_lat.group(5))
            max_ms = _to_float(m_lat.group(6))

        # Percentile distribution lines: "75.000% <= 42.847 milliseconds"
        pts: List[Tuple[float, float]] = []
        for m in re.finditer(r"^\s*([0-9.]+)%\s*<=\s*([0-9.]+)\s*milliseconds", block, flags=re.M):
            p = _to_float(m.group(1))
            v = _to_float(m.group(2))
            if p is None or v is None:
                continue
            pts.append((p, v))

        out.append(
            RedisSummary(
                op=op,
                throughput_rps=thr,
                threads=threads,
                avg_ms=avg_ms,
                min_ms=min_ms,
                p50_ms=p50_ms,
                p95_ms=p95_ms,
                p99_ms=p99_ms,
                max_ms=max_ms,
                percentile_points_ms=pts,
            )
        )
    return out


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="") as f:
        r = csv.DictReader(f)
        return list(r)


def collect_timestamps(results_dir: Path) -> List[str]:
    ts_set = set()
    for p in results_dir.iterdir():
        m = re.search(r"_(\d{8}_\d{6})\.(csv|log)$", p.name)
        if m:
            ts_set.add(m.group(1))
    return sorted(ts_set)


def _new_row() -> Dict[str, str]:
    return {k: "" for k in UNIFIED_FIELDS}


def build_rows_for_ts(results_dir: Path, ts: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []

    # Redis: native/sodium from redis-benchmark logs.
    for scenario, log_name in [
        ("TDXNativeTCP", f"tdx_native_tcp_{ts}.log"),
        ("TDXSodiumTCP", f"tdx_sodium_tcp_{ts}.log"),
    ]:
        p = results_dir / log_name
        if not p.exists():
            continue
        for s in parse_redis_benchmark_log(p):
            q50 = s.p50_ms if s.p50_ms is not None else _quantile_from_points(s.percentile_points_ms, 50.0)
            q75 = _quantile_from_points(s.percentile_points_ms, 75.0)
            q90 = _quantile_from_points(s.percentile_points_ms, 90.0)
            q99 = s.p99_ms if s.p99_ms is not None else _quantile_from_points(s.percentile_points_ms, 99.0)
            q999 = _quantile_from_points(s.percentile_points_ms, 99.9)
            q9999 = _quantile_from_points(s.percentile_points_ms, 99.99)

            r = _new_row()
            r["ts"] = ts
            r["app"] = "redis"
            r["scenario"] = scenario
            r["vm"] = "vm2"
            r["op"] = s.op
            r["threads"] = _format_int(s.threads)
            r["throughput_rps"] = _format_num(s.throughput_rps)
            # Convert ms -> us for unified latency columns.
            r["avg_us"] = _format_num(None if s.avg_ms is None else s.avg_ms * 1000.0)
            r["min_us"] = _format_num(None if s.min_ms is None else s.min_ms * 1000.0)
            r["p50_us"] = _format_num(None if q50 is None else q50 * 1000.0)
            r["p75_us"] = _format_num(None if q75 is None else q75 * 1000.0)
            r["p90_us"] = _format_num(None if q90 is None else q90 * 1000.0)
            r["p95_us"] = _format_num(None if s.p95_ms is None else s.p95_ms * 1000.0)
            r["p99_us"] = _format_num(None if q99 is None else q99 * 1000.0)
            r["p99_9_us"] = _format_num(None if q999 is None else q999 * 1000.0)
            r["p99_99_us"] = _format_num(None if q9999 is None else q9999 * 1000.0)
            r["max_us"] = _format_num(None if s.max_ms is None else s.max_ms * 1000.0)
            r["source_file"] = str(p)
            rows.append(r)

    # Redis: ring/ring-secure from CSV.
    for scenario, csv_name in [
        ("TDXRing", f"tdx_ring_{ts}.csv"),
        ("TDXRingSecure", f"tdx_ring_secure_{ts}.csv"),
    ]:
        p = results_dir / csv_name
        if not p.exists():
            continue
        for rr in read_csv_rows(p):
            r = _new_row()
            r["ts"] = ts
            r["app"] = "redis"
            r["scenario"] = scenario
            r["run_label"] = rr.get("label", "")
            r["vm"] = "vm2"
            r["op"] = rr.get("op", "")
            r["threads"] = rr.get("threads", "")
            r["throughput_rps"] = rr.get("throughput_rps", "")
            r["avg_us"] = rr.get("avg_us", "")
            r["p50_us"] = rr.get("p50_us", "")
            r["p75_us"] = rr.get("p75_us", "")
            r["p90_us"] = rr.get("p90_us", "")
            r["p99_us"] = rr.get("p99_us", "")
            r["p99_9_us"] = rr.get("p99.9_us", "")
            r["p99_99_us"] = rr.get("p99.99_us", "")
            r["rings"] = rr.get("rings", "")
            r["requests"] = rr.get("requests", "")
            r["pipeline"] = rr.get("pipeline", "")
            r["max_inflight"] = rr.get("max_inflight", "")
            r["push_retries"] = rr.get("push_retries", "")
            r["sleep_ms"] = rr.get("sleep_ms", "")
            r["source_file"] = str(p)
            rows.append(r)

    # GAPBS compare + overhead.
    overhead_by_key: Dict[Tuple[str, str, str, str, str, str, str], Dict[str, str]] = {}
    for p in results_dir.glob(f"tdx_gapbs_overhead_*_{ts}.csv"):
        for rr in read_csv_rows(p):
            key = (
                rr.get("label", ""),
                rr.get("vm", ""),
                rr.get("kernel", ""),
                rr.get("scale", ""),
                rr.get("degree", ""),
                rr.get("trials", ""),
                rr.get("omp_threads", ""),
            )
            overhead_by_key[key] = rr

    for p in results_dir.glob(f"tdx_gapbs_compare_*_{ts}.csv"):
        for rr in read_csv_rows(p):
            r = _new_row()
            r["ts"] = ts
            r["app"] = "gapbs"
            r["scenario"] = rr.get("label", "")
            r["vm"] = rr.get("vm", "")
            r["kernel"] = rr.get("kernel", "")
            r["threads"] = rr.get("omp_threads", "")
            r["scale"] = rr.get("scale", "")
            r["degree"] = rr.get("degree", "")
            r["trials"] = rr.get("trials", "")
            r["edge_traversals"] = rr.get("edge_traversals", "")
            r["avg_time_s"] = rr.get("avg_time_s", "")
            r["throughput_teps"] = rr.get("throughput_teps", "")

            key = (
                rr.get("label", ""),
                rr.get("vm", ""),
                rr.get("kernel", ""),
                rr.get("scale", ""),
                rr.get("degree", ""),
                rr.get("trials", ""),
                rr.get("omp_threads", ""),
            )
            ov = overhead_by_key.get(key)
            if ov:
                r["attach_total_ms"] = ov.get("attach_total_ms", "")
                r["attach_wait_ms"] = ov.get("attach_wait_ms", "")
                r["attach_decrypt_ms"] = ov.get("attach_decrypt_ms", "")
                r["attach_pretouch_ms"] = ov.get("attach_pretouch_ms", "")

            r["source_file"] = str(p)
            rows.append(r)

    return rows


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Unify Redis + GAPBS result CSV/logs into one CSV.")
    ap.add_argument("--results-dir", default="results", help="Results directory (default: results)")
    ap.add_argument("--ts", default="", help="Timestamp filter (e.g. 20260123_060544). Default: all.")
    ap.add_argument("--out", default="", help="Output CSV path. Default: results/tdx_unified_<ts>.csv or ..._all.csv")
    args = ap.parse_args(argv)

    results_dir = Path(args.results_dir)
    if not results_dir.exists():
        print(f"[!] results dir not found: {results_dir}", file=sys.stderr)
        return 2

    all_ts = collect_timestamps(results_dir)
    if args.ts:
        ts_list = [args.ts]
    else:
        ts_list = all_ts

    if not ts_list:
        print("[!] no timestamps found", file=sys.stderr)
        return 2

    out_path = Path(args.out) if args.out else None
    if out_path is None:
        if args.ts:
            out_path = results_dir / f"tdx_unified_{args.ts}.csv"
        else:
            out_path = results_dir / "tdx_unified_all.csv"

    rows: List[Dict[str, str]] = []
    for ts in ts_list:
        rows.extend(build_rows_for_ts(results_dir, ts))

    def sort_key(r: Dict[str, str]) -> Tuple:
        return (
            r.get("ts", ""),
            r.get("app", ""),
            r.get("scenario", ""),
            r.get("kernel", ""),
            r.get("op", ""),
            r.get("vm", ""),
            _to_int(r.get("threads", "") or "") or 0,
        )

    rows.sort(key=sort_key)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=UNIFIED_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in UNIFIED_FIELDS})

    print(f"[+] wrote {out_path} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

