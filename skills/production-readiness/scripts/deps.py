#!/usr/bin/env python3
"""Check pinned dependencies against the OSV vulnerability database (osv.dev).

No install needed: reads lockfiles and calls the free OSV API. Only package
names and versions are sent — never your code.

Lockfiles: package-lock.json (v1-v3), yarn.lock (v1), pnpm-lock.yaml,
requirements*.txt (==pins), Pipfile.lock, poetry.lock, go.sum, Gemfile.lock,
composer.lock, Cargo.lock.

Usage: deps.py <repo-path>   (findings also go to $PRS_FINDINGS if set)
Env:   PRS_OSV_URL to point at another OSV-compatible endpoint (used by tests).
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
FINDINGS = os.environ.get("PRS_FINDINGS")
OSV = os.environ.get("PRS_OSV_URL", "https://api.osv.dev").rstrip("/")
SKIP = re.compile(r"(^|/)(node_modules|vendor|\.venv|venv)/")


def files():
    try:
        out = subprocess.run(["git", "-C", ROOT, "ls-files"], capture_output=True, text=True, check=True).stdout.splitlines()
    except Exception:
        out = [os.path.relpath(os.path.join(d, f), ROOT) for d, _, fs in os.walk(ROOT) for f in fs]
    return [f for f in out if not SKIP.search("/" + f)]


def read(f):
    try:
        with open(os.path.join(ROOT, f), encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def parse(f):
    """Yield (ecosystem, name, version)."""
    base, text = os.path.basename(f), read(f)
    if base == "package-lock.json":
        try:
            data = json.loads(text)
        except ValueError:
            return
        for path, meta in (data.get("packages") or {}).items():
            if path and meta.get("version") and not meta.get("link"):
                yield "npm", meta.get("name") or path.split("node_modules/")[-1], meta["version"]
        if not data.get("packages"):
            stack = list((data.get("dependencies") or {}).items())
            while stack:
                name, meta = stack.pop()
                if meta.get("version"):
                    yield "npm", name, meta["version"]
                stack.extend((meta.get("dependencies") or {}).items())
    elif base == "yarn.lock":
        for m in re.finditer(r'^"?(@?[^@\s"]+)@[^\n]*\n\s+version "([^"]+)"', text, re.M):
            yield "npm", m.group(1), m.group(2)
    elif base == "pnpm-lock.yaml":
        for m in re.finditer(r"^\s{2}/?'?(@?[^@\s/'][^@\s']*(?:/[^@\s']+)?)@(\d[^:(\s']*)", text, re.M):
            yield "npm", m.group(1), m.group(2)
    elif re.match(r"requirements.*\.txt$", base):
        for m in re.finditer(r"^\s*([A-Za-z0-9_.\-\[\]]+?)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)", text, re.M):
            yield "PyPI", m.group(1), m.group(2)
    elif base == "Pipfile.lock":
        try:
            data = json.loads(text)
        except ValueError:
            return
        for section in ("default", "develop"):
            for name, meta in (data.get(section) or {}).items():
                v = (meta.get("version") or "").lstrip("=")
                if v:
                    yield "PyPI", name, v
    elif base == "poetry.lock":
        for m in re.finditer(r'\[\[package\]\]\s*\nname = "([^"]+)"\s*\nversion = "([^"]+)"', text):
            yield "PyPI", m.group(1), m.group(2)
    elif base == "go.sum":
        for m in re.finditer(r"^(\S+) v([^\s/]+?)(?:/go\.mod)? h1:", text, re.M):
            yield "Go", m.group(1), m.group(2).split("+")[0]
    elif base == "Gemfile.lock":
        for m in re.finditer(r"^    ([a-zA-Z0-9_.\-]+) \(([0-9][^)\s-]*)\)", text, re.M):
            yield "RubyGems", m.group(1), m.group(2)
    elif base == "composer.lock":
        try:
            data = json.loads(text)
        except ValueError:
            return
        for p in (data.get("packages") or []) + (data.get("packages-dev") or []):
            if p.get("name") and p.get("version"):
                yield "Packagist", p["name"], p["version"].lstrip("v")
    elif base == "Cargo.lock":
        for m in re.finditer(r'\[\[package\]\]\s*\nname = "([^"]+)"\s*\nversion = "([^"]+)"', text):
            yield "crates.io", m.group(1), m.group(2)


LOCKS = re.compile(r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|Pipfile\.lock|poetry\.lock|go\.sum|Gemfile\.lock|composer\.lock|Cargo\.lock)$")


def post(path, payload, timeout=20):
    req = urllib.request.Request(OSV + path, data=json.dumps(payload).encode(), headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def get(path, timeout=20):
    with urllib.request.urlopen(OSV + path, timeout=timeout) as r:
        return json.load(r)


def severity(vuln):
    s = ((vuln.get("database_specific") or {}).get("severity") or "").upper()
    if not s:
        for a in vuln.get("affected") or []:
            s = ((a.get("ecosystem_specific") or {}).get("severity") or "").upper() or s
    return s or "UNKNOWN"


def main():
    pkgs = {}
    for f in files():
        if LOCKS.search(f):
            for eco, name, ver in parse(f):
                pkgs.setdefault((eco, name, ver), f)
    if not pkgs:
        print("No lockfiles with pinned versions found (npm/yarn/pnpm, pip ==pins, Pipfile/poetry, Go, Ruby, PHP, Rust).")
        print("  -> Unpinned dependencies can't be checked — and mean every deploy may install something different. Commit a lockfile.")
        return
    keys = list(pkgs)
    vulns = {}
    try:
        for i in range(0, len(keys), 1000):
            batch = keys[i:i + 1000]
            res = post("/v1/querybatch", {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in batch]})
            for key, r in zip(batch, res.get("results", [])):
                ids = [v["id"] for v in r.get("vulns") or []]
                if ids:
                    vulns[key] = ids
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"Could not reach the OSV API ({OSV}): {exc}. Dependency check skipped.")
        return

    print(f"Dependencies checked: {len(pkgs)} | vulnerable packages: {len(vulns)}")
    if not vulns:
        return
    details, out = {}, []
    for ids in list(vulns.values())[:60]:          # cap detail lookups
        for vid in ids[:5]:
            if vid not in details:
                try:
                    details[vid] = get(f"/v1/vulns/{vid}")
                except (urllib.error.URLError, OSError, ValueError):
                    details[vid] = {}
    rank = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    rows = []
    for (eco, name, ver), ids in vulns.items():
        sevs = [severity(details.get(i, {})) for i in ids]
        worst = min(sevs, key=lambda s: rank.get(s, 4)) if sevs else "UNKNOWN"
        summary = next((details[i].get("summary") for i in ids if details.get(i, {}).get("summary")), "")
        rows.append((rank.get(worst, 4), worst, eco, name, ver, ids, summary, pkgs[(eco, name, ver)]))
    rows.sort()
    for _, worst, eco, name, ver, ids, summary, f in rows[:40]:
        print(f"  {worst:9} {eco}:{name}@{ver}  {', '.join(ids[:3])}{' …' if len(ids) > 3 else ''}  {summary[:70]}")
    if len(rows) > 40:
        print(f"  … and {len(rows) - 40} more")
    for _, worst, eco, name, ver, ids, summary, f in rows:
        sev = "critical" if worst == "CRITICAL" else "warning" if worst in ("HIGH", "MODERATE", "MEDIUM", "UNKNOWN") else "info"
        out.append(f"{sev}\tvulnerable-dependency\t{f}\t{eco}:{name}@{ver} {worst} {ids[0]}{' ' + summary[:80] if summary else ''}")
    print("  -> Upgrade to a fixed version (see https://osv.dev/vulnerability/<id>). Not every advisory is reachable from your code; prioritize CRITICAL/HIGH in runtime dependencies.")
    if FINDINGS:
        with open(FINDINGS, "a", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
