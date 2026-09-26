#!/usr/bin/env python3
"""Dependency freshness check (ticket #106, "Dependency freshness").

The gate builds whatever Cargo.lock says, so version drift is silent. This
check compares the locked versions of the core crate set against the latest
STABLE versions published on crates.io (sparse index) and *reports* the
drift. Warning-level by design: it never fails the gate (per the ticket:
"warning-level first, no hard fail").

bpf-linker is intentionally NOT checked here: it is a host tool, not a cargo
dependency, and is tracked in the runbook (test-vm/README.md, toolchain
gotchas).

Usage:  python3 tests/e2e/dep_freshness.py [path/to/Cargo.lock]
Exit:   0 (report-only); non-zero only on usage/IO errors.
"""

import json
import os
import sys
import urllib.request

CORE_SET = [
    "aya",
    "aya-ebpf",
    "aya-log",
    "aya-build",
    "aya-log-ebpf",
    "network-types",
    "tokio",
    "ratatui",
]

INDEX_BASE = "https://index.crates.io"
UA = "firewhal-dep-freshness (e2e gate preflight; ticket #106)"


def locked_versions(path):
    """Return {package name: version} for every entry in Cargo.lock."""
    versions = {}
    current = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line == "[[package]]":
                current = None
            elif line.startswith("name = ") and current is None:
                current = line.split('"')[1]
            elif line.startswith("version = ") and current is not None:
                versions.setdefault(current, line.split('"')[1])
                current = None
    return versions


def index_path(name):
    """crates.io sparse-index URL path for a crate name."""
    n = name.lower()
    if len(n) == 1:
        return "1/" + n
    if len(n) == 2:
        return "2/" + n
    if len(n) == 3:
        return "3/" + n[0] + "/" + n
    return n[:2] + "/" + n[2:4] + "/" + n


def _semver_key(v):
    """Order key: (nums, is_release, pre-string) — pre-releases sort low."""
    core, _, pre = v.partition("-")
    parts = (core.split(".") + ["0", "0"])[:3]
    nums = tuple(int(p) if p.isdigit() else 0 for p in parts)
    return (nums, 1 if not pre else 0, pre)


def latest_stable_on_crates_io(name):
    """Return (version, created_at) of the newest non-yanked STABLE release."""
    url = f"{INDEX_BASE}/{index_path(name)}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    best = None
    with urllib.request.urlopen(req, timeout=15) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            vers = entry.get("vers", "")
            if entry.get("yanked") or "-" in vers:  # skip yanked + pre-releases
                continue
            key = _semver_key(vers)
            if best is None or key > best[0]:
                best = (key, vers, entry.get("created_at", "?"))
    return (best[1], best[2]) if best else None


def _nums(v):
    core = v.partition("-")[0]
    parts = (core.split(".") + ["0", "0"])[:3]
    return tuple(int(p) if p.isdigit() else 0 for p in parts)


def describe_drift(locked, latest):
    l, r = _nums(locked), _nums(latest)
    if l == r:
        return "current"
    if l[0] < r[0]:
        return f"{r[0] - l[0]} major behind"
    if l[1] < r[1]:
        return f"{r[1] - l[1]} minor behind"
    return f"{r[2] - l[2]} patch behind"


def main():
    if len(sys.argv) > 1:
        lock_path = sys.argv[1]
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        lock_path = os.path.join(here, "..", "..", "Cargo.lock")
    try:
        locked = locked_versions(lock_path)
    except OSError as exc:
        print(f"[dep-freshness] cannot read {lock_path}: {exc}")
        return 1

    print("[dep-freshness] core-set drift vs crates.io (report-only, never fails the gate)")
    width = max(len(n) for n in CORE_SET)
    drifted = 0
    for name in CORE_SET:
        lock_v = locked.get(name)
        if lock_v is None:
            print(f"  {name.ljust(width)}  not in Cargo.lock (skipped)")
            continue
        try:
            latest = latest_stable_on_crates_io(name)
        except Exception:
            print(f"  {name.ljust(width)}  {lock_v.ljust(10)}  ->  ? (crates.io fetch failed)")
            continue
        if latest is None:
            print(f"  {name.ljust(width)}  {lock_v.ljust(10)}  ->  ? (no index entries)")
            continue
        latest_v, created = latest
        if lock_v == latest_v:
            print(f"  {name.ljust(width)}  {lock_v.ljust(10)}  ->  {latest_v.ljust(10)}  current")
        else:
            drifted += 1
            date = created[:10] if created != "?" else "?"
            print(
                f"  {name.ljust(width)}  {lock_v.ljust(10)}  ->  {latest_v.ljust(10)}"
                f"  {describe_drift(lock_v, latest_v)} (latest released {date})"
            )
    if drifted:
        print(
            f"[dep-freshness] WARNING: {drifted} of {len(CORE_SET)} core crates drifted"
            " (report-only; no hard fail)"
        )
    else:
        print(f"[dep-freshness] all {len(CORE_SET)} core crates current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
