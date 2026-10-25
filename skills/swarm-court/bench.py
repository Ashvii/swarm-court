#!/usr/bin/env python3
"""swarm-court bench: bounded, local-only latency measurement. Python 3.8+ standard library only.

Hunters and skeptics use this instead of ad-hoc timing loops, so every latency claim in a swarm-court report
comes from the same safe, comparable tool. Safety is enforced here in code, not left to the prompt:

  * HTTP targets must resolve to a loopback address (127.0.0.0/8, ::1). Redirects are never followed.
  * At most 500 requests, 8 concurrent, 60 seconds per run. This is a measurement, never a load test.

Usage:
  bench.py http URL [-X METHOD] [-H 'Name: value']... [--data JSON] [-n 50] [-c 1] [--warmup 3]
                    [--budget-ms 300] --label NAME --out FILE.json
  bench.py cmd  [-n 10] [--warmup 1] [--budget-ms 1000] --label NAME --out FILE.json -- COMMAND ARGS...
  bench.py compare SMALL.json LARGE.json [--size-small 1000 --size-large 10000]

Every result is a JSON file with "tool": "swarm-court-bench"; qa.py collects these into the report.
"""

import argparse
import datetime
import ipaddress
import json
import math
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

TOOL = "swarm-court-bench"
VERSION = "1.0.2"
MAX_REQUESTS = 500
MAX_CONCURRENCY = 8
MAX_SECONDS = 60.0
MAX_WARMUP = 20
REQUEST_TIMEOUT = 15.0


class BenchError(Exception):
    pass


# ---------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------

def assert_local(url):
    """Refuse anything that does not resolve exclusively to loopback addresses."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BenchError("only http/https URLs are supported")
    host = parts.hostname
    if not host:
        raise BenchError("URL has no host")
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        if host.lower() != "localhost" and not host.lower().endswith(".localhost"):
            raise BenchError("refusing %s: only localhost / 127.0.0.1 / ::1 targets are allowed" % host)
        try:
            infos = socket.getaddrinfo(host, parts.port or 80, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise BenchError("cannot resolve %s: %s" % (host, exc))
        addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]
    bad = [str(a) for a in addresses if not a.is_loopback]
    if bad or not addresses:
        raise BenchError("refusing %s: resolves to non-loopback address(es) %s" % (host, ", ".join(bad) or "none"))


def pin_loopback(url, headers):
    """Replace a 'localhost' host with the loopback IP that actually accepts connections.

    On Windows, localhost often resolves to ::1 first; if the server listens on 127.0.0.1 only, every request
    pays a ~2 s IPv6 connect timeout. That fake latency would read as a real performance bug.
    """
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    try:
        ipaddress.ip_address(host)
        return url, host
    except ValueError:
        pass
    port = parts.port or (443 if parts.scheme == "https" else 80)
    for candidate in ("127.0.0.1", "::1"):
        try:
            with socket.create_connection((candidate, port), timeout=0.5):
                pass
        except OSError:
            continue
        headers.setdefault("Host", parts.netloc)
        literal = "[%s]" % candidate if ":" in candidate else candidate
        netloc = "%s:%d" % (literal, port) if parts.port else literal
        return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)), candidate
    raise BenchError("nothing is listening on %s port %d (start the local app first)" % (host, port))


def check_limits(n, concurrency, warmup):
    if not 1 <= n <= MAX_REQUESTS:
        raise BenchError("-n must be between 1 and %d (this is a measurement, not a load test)" % MAX_REQUESTS)
    if not 1 <= concurrency <= MAX_CONCURRENCY:
        raise BenchError("-c must be between 1 and %d" % MAX_CONCURRENCY)
    if not 0 <= warmup <= MAX_WARMUP:
        raise BenchError("--warmup must be between 0 and %d" % MAX_WARMUP)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # report the 3xx as-is; never follow (it could leave localhost)


OPENER = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

def percentile(sorted_values, pct):
    """Nearest-rank percentile of an ascending list."""
    if not sorted_values:
        return None
    rank = max(1, int(math.ceil(pct / 100.0 * len(sorted_values))))
    return sorted_values[min(rank, len(sorted_values)) - 1]


def summarize(samples_ms, errors, status_counts, budget_ms):
    values = sorted(samples_ms)
    stats = {
        "ok": len(values), "errors": errors, "status_counts": status_counts,
        "min_ms": round(values[0], 2) if values else None,
        "p50_ms": round(percentile(values, 50), 2) if values else None,
        "p95_ms": round(percentile(values, 95), 2) if values else None,
        "p99_ms": round(percentile(values, 99), 2) if values else None,
        "max_ms": round(values[-1], 2) if values else None,
        "mean_ms": round(sum(values) / len(values), 2) if values else None,
        "budget_ms": budget_ms,
    }
    stats["over_budget"] = bool(budget_ms is not None and values and stats["p95_ms"] > budget_ms)
    return stats


def run_pool(task, n, concurrency):
    """Run task() n times on `concurrency` threads; stop early at MAX_SECONDS."""
    lock = threading.Lock()
    results = []
    counter = {"next": 0}
    deadline = time.perf_counter() + MAX_SECONDS
    state = {"timed_out": False}

    def worker():
        while True:
            with lock:
                if counter["next"] >= n:
                    return
                if time.perf_counter() > deadline:
                    state["timed_out"] = True
                    return
                counter["next"] += 1
            outcome = task()
            with lock:
                results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results, state["timed_out"]


def http_task(url, method, headers, data):
    body = data.encode("utf-8") if data is not None else None

    def task():
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        start = time.perf_counter()
        try:
            with OPENER.open(req, timeout=REQUEST_TIMEOUT) as resp:
                resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except (urllib.error.URLError, OSError) as exc:
            return {"ms": None, "status": "error: %s" % getattr(exc, "reason", exc)}
        return {"ms": (time.perf_counter() - start) * 1000.0, "status": status}
    return task


def cmd_task(command):
    def task():
        start = time.perf_counter()
        try:
            proc = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=MAX_SECONDS)
            status = "exit %d" % proc.returncode
        except subprocess.TimeoutExpired:
            return {"ms": None, "status": "timeout"}
        except OSError as exc:
            return {"ms": None, "status": "error: %s" % exc}
        ms = (time.perf_counter() - start) * 1000.0
        return {"ms": ms if proc.returncode == 0 else None, "status": status}
    return task


def measure(task, n, concurrency, warmup, budget_ms, ok_status):
    for _ in range(warmup):
        task()
    started = time.perf_counter()
    results, timed_out = run_pool(task, n, concurrency)
    duration = time.perf_counter() - started
    samples, errors, counts = [], 0, {}
    for r in results:
        key = str(r["status"])
        counts[key] = counts.get(key, 0) + 1
        if r["ms"] is not None and ok_status(r["status"]):
            samples.append(r["ms"])
        else:
            errors += 1
    stats = summarize(samples, errors, counts, budget_ms)
    stats.update({"requested": n, "completed": len(results), "timed_out": timed_out,
                  "duration_s": round(duration, 3),
                  "throughput_rps": round(len(results) / duration, 2) if duration > 0 else None})
    return stats


def write_result(path, payload):
    payload.update({"tool": TOOL, "version": VERSION,
                    "measured_at": datetime.datetime.now().replace(microsecond=0).isoformat()})
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    return payload


def one_line(p):
    if p["kind"] == "compare":
        return "%s: p95 %s -> %s ms (x%s) for data x%s => %s" % (
            p["label"], p["small"]["p95_ms"], p["large"]["p95_ms"], p["p95_growth"], p["size_growth"] or "?",
            p["scaling"])
    return "%s: n=%d ok=%d err=%d p50=%s p95=%s p99=%s ms%s" % (
        p["label"], p["requested"], p["ok"], p["errors"], p["p50_ms"], p["p95_ms"], p["p99_ms"],
        (" budget=%sms %s" % (p["budget_ms"], "OVER" if p["over_budget"] else "ok")) if p["budget_ms"] else "")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_http(args):
    check_limits(args.n, args.c, args.warmup)
    assert_local(args.url)
    headers = {}
    for h in args.header or []:
        if ":" not in h:
            raise BenchError("header must be 'Name: value': %r" % h)
        name, value = h.split(":", 1)
        headers[name.strip()] = value.strip()
    if args.data is not None and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"
    url, resolved = pin_loopback(args.url, headers)
    task = http_task(url, args.method.upper(), headers, args.data)
    stats = measure(task, args.n, args.c, args.warmup, args.budget_ms,
                    lambda s: isinstance(s, int) and 200 <= s < 300)
    stats.update({"kind": "http", "label": args.label, "target": "%s %s" % (args.method.upper(), args.url),
                  "resolved_to": resolved, "concurrency": args.c, "warmup": args.warmup,
                  "headers": sorted(headers)})  # header names only: never store token values
    print(one_line(write_result(args.out, stats)))
    return 0


def cmd_cmd(args):
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command:
        raise BenchError("give the command after --")
    check_limits(args.n, 1, args.warmup)
    stats = measure(cmd_task(command), args.n, 1, args.warmup, args.budget_ms,
                    lambda s: s == "exit 0")
    stats.update({"kind": "cmd", "label": args.label, "target": " ".join(command), "concurrency": 1,
                  "warmup": args.warmup})
    print(one_line(write_result(args.out, stats)))
    return 0


def cmd_compare(args):
    with open(args.small, encoding="utf-8") as fh:
        small = json.load(fh)
    with open(args.large, encoding="utf-8") as fh:
        large = json.load(fh)
    for name, p in (("small", small), ("large", large)):
        if p.get("tool") != TOOL or not p.get("p95_ms"):
            raise BenchError("%s is not a successful swarm-court-bench result" % name)
    p95_growth = large["p95_ms"] / small["p95_ms"]
    size_growth = (args.size_large / float(args.size_small)) if args.size_small and args.size_large else None
    if size_growth:
        exponent = math.log(p95_growth) / math.log(size_growth) if p95_growth > 0 and size_growth > 1 else 0
        scaling = ("superlinear" if exponent > 1.2 else "linear" if exponent > 0.7
                   else "sublinear" if exponent > 0.25 else "flat")
    else:
        exponent, scaling = None, "unknown (pass --size-small/--size-large)"
    payload = {"kind": "compare", "label": "%s vs %s" % (small.get("label"), large.get("label")),
               "small": {k: small.get(k) for k in ("label", "p50_ms", "p95_ms")},
               "large": {k: large.get(k) for k in ("label", "p50_ms", "p95_ms")},
               "size_small": args.size_small, "size_large": args.size_large,
               "p95_growth": round(p95_growth, 2), "size_growth": round(size_growth, 2) if size_growth else None,
               "exponent": round(exponent, 2) if exponent is not None else None, "scaling": scaling}
    if args.out:
        write_result(args.out, payload)
    else:
        payload.update({"tool": TOOL, "version": VERSION})
    print(one_line(payload))
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="bench.py", description="swarm-court bounded local latency measurement")
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    h = sub.add_parser("http", help="time a local HTTP endpoint")
    h.add_argument("url")
    h.add_argument("-X", "--method", default="GET")
    h.add_argument("-H", "--header", action="append")
    h.add_argument("--data", help="request body (JSON string)")
    h.add_argument("-n", type=int, default=50)
    h.add_argument("-c", type=int, default=1)
    h.add_argument("--warmup", type=int, default=3)
    h.add_argument("--budget-ms", type=float)
    h.add_argument("--label", required=True)
    h.add_argument("--out", required=True)
    h.set_defaults(func=cmd_http)

    c = sub.add_parser("cmd", help="time a local command (e.g. php script.php)")
    c.add_argument("-n", type=int, default=10)
    c.add_argument("--warmup", type=int, default=1)
    c.add_argument("--budget-ms", type=float)
    c.add_argument("--label", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("command", nargs=argparse.REMAINDER)
    c.set_defaults(func=cmd_cmd)

    m = sub.add_parser("compare", help="scaling between two results (e.g. 1k rows vs 10k rows)")
    m.add_argument("small")
    m.add_argument("large")
    m.add_argument("--size-small", type=float)
    m.add_argument("--size-large", type=float)
    m.add_argument("--out")
    m.set_defaults(func=cmd_compare)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BenchError as exc:
        print("bench.py: error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
