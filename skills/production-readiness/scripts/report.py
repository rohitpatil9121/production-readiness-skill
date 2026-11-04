#!/usr/bin/env python3
"""Run the scan and turn its findings into text, JSON, SARIF, HTML or Markdown.

Usage:
  report.py [repo] [--format text|json|sarif|html|markdown] [--output FILE]
            [--fail-on critical|warning|info|none] [--deps] [--deep]
            [--save-history] [--probe URL [--protected PATH]... [--login PATH]]

  --write F:PATH also write format F (json/sarif/html/markdown/text) to PATH; repeatable, one scan
  --fail-on      exit 1 if any (non-ignored) finding is at or above this severity (default: none)
  --save-history append counts to <repo>/.production-readiness/history.jsonl and show the change
  --probe URL    also run probe.sh against a running instance you own

Ignore known/accepted findings in <repo>/.production-readiness-ignore, one per line:
  rule-id                 # ignore a rule everywhere
  path/glob/**            # ignore everything in matching files
  rule-id path/glob/**    # ignore a rule in matching files
"""
import argparse
import datetime as dt
import fnmatch
import html
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SEV_RANK = {"critical": 3, "warning": 2, "info": 1, "none": 99}
SARIF_LEVEL = {"critical": "error", "warning": "warning", "info": "note"}
RULE_HELP = {
    "secret-in-code": "A credential in a known format is committed. Rotate it at the provider, then load it from the environment.",
    "secret-hardcoded": "A secret is assigned as a literal in code. Move it to an environment variable and rotate it.",
    "secret-in-history": "A secret was removed from the code but is still in git history. Rotate it; rewriting history does not un-leak it.",
    "secret-public-env": "A secret-looking value uses a public env prefix (NEXT_PUBLIC_/VITE_/...) and ends up in the browser bundle.",
    "secret-default-fallback": "A secret falls back to a hardcoded default. Startup must fail in production when it's missing.",
    "unguarded-write-route": "A route that changes data has no visible authentication. Anyone can call it.",
    "unsigned-webhook": "A webhook endpoint doesn't verify the sender's signature, so anyone can forge events.",
    "possible-idor": "A record is fetched by an id from the URL without checking it belongs to the current user.",
    "supabase-rls-missing": "A Supabase table has no Row Level Security. Its REST API is reachable with the public anon key.",
    "supabase-rls-disabled": "Row Level Security is explicitly disabled on a Supabase table.",
    "supabase-policy-open-write": "A Supabase policy allows writes for everyone (using/with check true).",
    "supabase-policy-open-read": "A Supabase policy lets everyone read every row.",
    "supabase-service-role-key": "A Supabase service_role key (bypasses RLS) is committed.",
    "supabase-service-role-client": "The Supabase service_role key is used in client-side code.",
    "firebase-rules-open": "Firebase rules allow access without any condition.",
    "firebase-rules-test-mode": "Firebase rules are in test mode (open until a date).",
    "vulnerable-dependency": "A pinned dependency version has a known vulnerability (OSV).",
    "sql-string-building": "SQL is built by string concatenation/formatting — SQL injection risk. Use parameters.",
    "jwt-not-verified": "A JWT is decoded without verifying its signature.",
    "cors-allow-all": "CORS allows any origin.",
    "debug-enabled": "Debug mode is on, which can leak stack traces and internals.",
    "dynamic-code-exec": "eval/exec/shell execution — dangerous if any input reaches it.",
    "unsafe-html-sink": "HTML is injected from data — XSS risk unless the data is trusted or sanitized.",
    "weak-randomness": "Math.random/random used for something that looks like a token, code or id.",
    "tls-verification-off": "TLS certificate verification is disabled.",
    "secrets-in-logs": "A token/secret/password appears to be logged.",
    "token-in-url": "An auth token is put in a URL, where it leaks via logs, history and Referer.",
    "unsafe-deserialization": "Unsafe deserialization (pickle/yaml.load) — code execution if input is untrusted.",
}


def run_scan(repo, args, findings_file):
    cmd = ["bash", os.path.join(HERE, "scan.sh")]
    if args.deep:
        cmd.append("--deep")
    elif args.deps:
        cmd.append("--deps")
    cmd.append(repo)
    env = dict(os.environ, PRS_FINDINGS=findings_file)
    out = subprocess.run(cmd, capture_output=True, text=True, env=env).stdout
    if args.probe:
        pcmd = ["bash", os.path.join(HERE, "probe.sh"), args.probe]
        for p in args.protected or []:
            pcmd += ["--protected", p]
        if args.login:
            pcmd += ["--login", args.login]
        out += "\n" + subprocess.run(pcmd, capture_output=True, text=True, env=env).stdout
    return out


def load_findings(path):
    seen, rows = set(), []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 4:
                continue
            key = tuple(parts)
            if key not in seen:
                seen.add(key)
                sev, rule, loc, msg = parts
                rows.append({"severity": sev, "rule": rule, "location": loc, "message": msg})
    rows.sort(key=lambda r: (-SEV_RANK.get(r["severity"], 0), r["rule"], r["location"]))
    return rows


def load_ignores(repo):
    path = os.path.join(repo, ".production-readiness-ignore")
    rules = []
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
                rules.append(line.split(None, 1))
    return rules


def ignored(f, ignores):
    file_part = f["location"].rsplit(":", 1)[0] if re.search(r":\d+$", f["location"]) else f["location"]
    for parts in ignores:
        if len(parts) == 2 and parts[0] == f["rule"] and fnmatch.fnmatch(file_part, parts[1]):
            return True
        if len(parts) == 1 and (parts[0] == f["rule"] or fnmatch.fnmatch(file_part, parts[0])):
            return True
    return False


def profile(scan_text):
    m = re.search(r"^Profile: (.*)$", scan_text, re.M)
    d = re.search(r"^Deploy target: (.*)$", scan_text, re.M)
    prof = {}
    if m:
        for part in m.group(1).split("|"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                prof[k.strip()] = v.strip()
    if d:
        bits = d.group(1).split("| Repo visibility:")
        prof["deploy"] = bits[0].strip()
        if len(bits) > 1:
            prof["visibility"] = bits[1].strip().split(" ")[0]
    return prof


def counts(rows):
    c = {"critical": 0, "warning": 0, "info": 0}
    for r in rows:
        c[r["severity"]] = c.get(r["severity"], 0) + 1
    return c


def split_loc(loc):
    m = re.match(r"(.+):(\d+)$", loc)
    return (m.group(1), int(m.group(2))) if m else (loc, None)


# ---------------------------------------------------------------- formats
def to_text(scan_text, rows, ign, c):
    out = [scan_text.rstrip(), "", "== Summary =="]
    out.append(f"critical: {c['critical']} | warning: {c['warning']} | info: {c['info']}" + (f" | ignored: {ign}" if ign else ""))
    for r in rows:
        if r["severity"] == "critical":
            out.append(f"  CRITICAL {r['rule']:28} {r['location']}  {r['message']}")
    return "\n".join(out) + "\n"


def to_markdown(rows, prof, c, ign):
    icon = {"critical": "🔴", "warning": "⚠️", "info": "ℹ️"}
    lines = ["## Production readiness scan", "",
             f"**{c['critical']}** critical · **{c['warning']}** warnings · {c['info']} info" + (f" · {ign} ignored" if ign else ""), ""]
    if prof:
        lines += [f"`type={prof.get('type', '?')}` `deploy={prof.get('deploy', '?')}` `server={prof.get('own server', '?')}` `LLM={prof.get('LLM', '?')}`", ""]
    if rows:
        lines += ["| | Rule | Location | Finding |", "|---|---|---|---|"]
        for r in rows[:100]:
            lines.append(f"| {icon.get(r['severity'], '')} | `{r['rule']}` | `{r['location']}` | {r['message'].replace('|', '/')} |")
        if len(rows) > 100:
            lines.append(f"| | | | …and {len(rows) - 100} more |")
    else:
        lines.append("No findings. 🎉")
    lines += ["", "_Signals, not verdicts: open each one before acting. Generated by [production-readiness](https://github.com/rohitpatil9121/production-readiness-skill)._"]
    return "\n".join(lines) + "\n"


def to_sarif(rows, repo):
    fallback = next((f for f in ("README.md", "readme.md", "package.json", "requirements.txt") if os.path.exists(os.path.join(repo, f))), ".")
    rule_ids = sorted({r["rule"] for r in rows})
    results = []
    for r in rows:
        path, line = split_loc(r["location"])
        if not os.path.exists(os.path.join(repo, path)):
            path, line = fallback, None
        loc = {"physicalLocation": {"artifactLocation": {"uri": path}}}
        if line:
            loc["physicalLocation"]["region"] = {"startLine": line}
        results.append({"ruleId": r["rule"], "level": SARIF_LEVEL.get(r["severity"], "note"),
                        "message": {"text": r["message"] + ("" if path == split_loc(r["location"])[0] else f" ({r['location']})")},
                        "locations": [loc]})
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "production-readiness",
                "informationUri": "https://github.com/rohitpatil9121/production-readiness-skill",
                "rules": [{"id": rid, "shortDescription": {"text": rid.replace("-", " ")},
                           "fullDescription": {"text": RULE_HELP.get(rid, rid)},
                           "help": {"text": RULE_HELP.get(rid, rid)}} for rid in rule_ids],
            }},
            "results": results,
        }],
    }, indent=2)


def to_html(rows, prof, c, scan_text, repo_name, ign, history):
    esc = html.escape
    sev_label = {"critical": "Critical", "warning": "Warning", "info": "Info"}
    trs = "\n".join(
        f'<tr data-sev="{esc(r["severity"])}"><td><span class="pill {esc(r["severity"])}">{sev_label.get(r["severity"], r["severity"])}</span></td>'
        f'<td><code>{esc(r["rule"])}</code></td><td><code>{esc(r["location"])}</code></td><td>{esc(r["message"])}</td></tr>' for r in rows)
    prof_html = " ".join(f'<span class="tag">{esc(k)}: {esc(v)}</span>' for k, v in prof.items())
    hist_html = ""
    if history and len(history) > 1:
        pts = history[-12:]
        mx = max(1, max(p["counts"]["critical"] + p["counts"]["warning"] for p in pts))
        bars = "".join(
            f'<div class="bar" title="{esc(p["date"][:10])}: {p["counts"]["critical"]} critical, {p["counts"]["warning"]} warnings">'
            f'<i class="w" style="height:{p["counts"]["warning"] / mx * 100:.0f}%"></i><i class="c" style="height:{p["counts"]["critical"] / mx * 100:.0f}%"></i></div>'
            for p in pts)
        hist_html = f'<section><h2>Trend</h2><div class="bars">{bars}</div><p class="muted">Last {len(pts)} saved scans (critical stacked on warnings).</p></section>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Production readiness — {esc(repo_name)}</title>
<style>
:root{{--bg:#fff;--fg:#111827;--muted:#6b7280;--card:#f9fafb;--line:#e5e7eb;--crit:#dc2626;--warn:#d97706;--info:#2563eb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0b1020;--fg:#e5e7eb;--muted:#9ca3af;--card:#111827;--line:#1f2937;--crit:#f87171;--warn:#fbbf24;--info:#60a5fa}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}}h1{{margin:0 0 4px;font-size:24px}}h2{{font-size:17px;margin:28px 0 10px}}
.muted{{color:var(--muted)}}.tag{{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 10px;margin:4px 4px 0 0;font-size:13px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:18px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}}.card b{{font-size:28px;display:block}}
.card.critical b{{color:var(--crit)}}.card.warning b{{color:var(--warn)}}.card.info b{{color:var(--info)}}
.filters button{{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:6px 12px;margin-right:6px;cursor:pointer}}
.filters button.on{{border-color:var(--fg)}}
.table-wrap{{overflow-x:auto;border:1px solid var(--line);border-radius:12px}}
table{{border-collapse:collapse;width:100%;min-width:640px}}td,th{{padding:9px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
th{{background:var(--card);font-size:13px;color:var(--muted)}}code{{font-size:13px;overflow-wrap:anywhere}}td:nth-child(2) code{{white-space:nowrap}}
.pill{{font-size:12px;font-weight:600;border-radius:999px;padding:2px 8px;color:#fff}}.pill.critical{{background:var(--crit)}}.pill.warning{{background:var(--warn)}}.pill.info{{background:var(--info)}}
.bars{{display:flex;gap:6px;align-items:flex-end;height:90px}}.bar{{flex:1;max-width:36px;height:100%;display:flex;flex-direction:column-reverse;background:var(--card);border-radius:4px;overflow:hidden}}
.bar i{{display:block}}.bar .c{{background:var(--crit)}}.bar .w{{background:var(--warn)}}
pre{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px;overflow:auto;font-size:12.5px}}
</style></head><body><main>
<h1>Production readiness — {esc(repo_name)}</h1>
<div class="muted">Generated {dt.datetime.now().strftime('%Y-%m-%d %H:%M')} · signals, not verdicts: open each finding before acting.</div>
<div>{prof_html}</div>
<div class="cards"><div class="card critical"><b>{c['critical']}</b>Critical</div><div class="card warning"><b>{c['warning']}</b>Warnings</div>
<div class="card info"><b>{c['info']}</b>Info</div><div class="card"><b>{ign}</b>Ignored</div></div>
{hist_html}
<section><h2>Findings</h2>
<div class="filters"><button class="on" data-f="all">All</button><button data-f="critical">Critical</button><button data-f="warning">Warnings</button><button data-f="info">Info</button></div><br>
<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Finding</th></tr></thead><tbody>
{trs or '<tr><td colspan="4">No findings 🎉</td></tr>'}
</tbody></table></div></section>
<section><h2>Full scan output</h2><details><summary>Show</summary><pre>{esc(scan_text)}</pre></details></section>
<p class="muted">This report maps weaknesses in your project. Don't publish it while critical items are open.</p>
</main>
<script>
document.querySelectorAll('.filters button').forEach(function(b){{b.addEventListener('click',function(){{
document.querySelectorAll('.filters button').forEach(function(x){{x.classList.remove('on')}});b.classList.add('on');
var f=b.getAttribute('data-f');document.querySelectorAll('tbody tr[data-sev]').forEach(function(r){{r.style.display=(f==='all'||r.getAttribute('data-sev')===f)?'':'none'}});}})}});
</script></body></html>
"""


def save_history(repo, rows, c):
    d = os.path.join(repo, ".production-readiness")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "history.jsonl")
    commit = subprocess.run(["git", "-C", repo, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip() or None
    by_rule = {}
    for r in rows:
        by_rule[r["rule"]] = by_rule.get(r["rule"], 0) + 1
    entry = {"date": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "commit": commit, "counts": c, "rules": by_rule}
    history = load_history(repo)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    return history + [entry]


def load_history(repo):
    path = os.path.join(repo, ".production-readiness", "history.jsonl")
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def delta_text(history):
    if len(history) < 2:
        return "History: first saved scan."
    a, b = history[-2], history[-1]
    parts = []
    for k in ("critical", "warning", "info"):
        diff = b["counts"].get(k, 0) - a["counts"].get(k, 0)
        parts.append(f"{k} {a['counts'].get(k, 0)} → {b['counts'].get(k, 0)} ({'+' if diff > 0 else ''}{diff})")
    fixed = [r for r in a["rules"] if r not in b["rules"]]
    new = [r for r in b["rules"] if r not in a["rules"]]
    s = f"Since last scan ({a['date'][:10]}{', ' + a['commit'] if a.get('commit') else ''}): " + " | ".join(parts)
    if fixed:
        s += f"\n  resolved rules: {', '.join(fixed)}"
    if new:
        s += f"\n  new rules: {', '.join(new)}"
    return s


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--format", choices=["text", "json", "sarif", "html", "markdown"], default="text")
    ap.add_argument("--output", "-o")
    ap.add_argument("--write", action="append", default=[], metavar="FORMAT:PATH")
    ap.add_argument("--fail-on", choices=["critical", "warning", "info", "none"], default="none")
    ap.add_argument("--deps", action="store_true")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--save-history", action="store_true")
    ap.add_argument("--probe")
    ap.add_argument("--protected", action="append")
    ap.add_argument("--login")
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)

    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".tsv") as tf:
        findings_file = tf.name
    try:
        scan_text = run_scan(repo, args, findings_file)
        rows = load_findings(findings_file)
    finally:
        os.unlink(findings_file)

    ignores = load_ignores(repo)
    kept = [r for r in rows if not ignored(r, ignores)]
    ign = len(rows) - len(kept)
    c = counts(kept)
    prof = profile(scan_text)
    history = save_history(repo, kept, c) if args.save_history else load_history(repo)

    def render(fmt):
        if fmt == "json":
            return json.dumps({"repo": repo, "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                               "profile": prof, "counts": c, "ignored": ign, "findings": kept}, indent=2) + "\n"
        if fmt == "sarif":
            return to_sarif(kept, repo) + "\n"
        if fmt == "html":
            return to_html(kept, prof, c, scan_text, os.path.basename(repo), ign, history)
        if fmt == "markdown":
            return to_markdown(kept, prof, c, ign)
        return to_text(scan_text, kept, ign, c) + (delta_text(history) + "\n" if args.save_history else "")

    for spec in args.write:
        fmt, _, path = spec.partition(":")
        if fmt not in ("json", "sarif", "html", "markdown", "text") or not path:
            ap.error(f"--write expects FORMAT:PATH, got {spec!r}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render(fmt))
    body = render(args.format)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"Wrote {args.output} — critical: {c['critical']}, warning: {c['warning']}, info: {c['info']}" + (f", ignored: {ign}" if ign else ""),
              file=sys.stderr)
        if args.save_history:
            print(delta_text(history), file=sys.stderr)
    else:
        sys.stdout.write(body)

    threshold = SEV_RANK[args.fail_on]
    if any(SEV_RANK.get(r["severity"], 0) >= threshold for r in kept):
        print(f"Failing: findings at or above '{args.fail_on}'.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
