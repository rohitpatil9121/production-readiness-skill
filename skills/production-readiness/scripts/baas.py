#!/usr/bin/env python3
"""Backend-as-a-service checks: Supabase and Firebase.

Apps built on Supabase/Firebase often have no backend of their own: the browser
talks to the database directly, so the database's own rules ARE the security.
The classic leaks: Supabase tables without Row Level Security, policies that are
`using (true)`, the service_role key shipped to the browser, and Firebase rules
left in "test mode".

Usage: baas.py <repo-path>   (findings also go to $PRS_FINDINGS if set)
"""
import base64
import json
import os
import re
import subprocess
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
FINDINGS = os.environ.get("PRS_FINDINGS")
SKIP = re.compile(r"(^|/)(node_modules|dist|build|\.next|vendor|coverage)/")
SERVER_PATH = re.compile(r"(^|/)(server|backend|api|functions|scripts|supabase/functions|lambda|workers?)/|\.server\.|(^|/)route\.(t|j)s$|middleware\.(t|j)s$|(^|/)app/api/", re.I)
CODE_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".dart", ".kt", ".swift")


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


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


found = []
def emit(sev, rule, loc, msg):
    found.append((sev, rule, loc, msg))


FILES = files()
uses_supabase = any(("supabase" in read(f).lower()) for f in FILES if os.path.basename(f) in ("package.json", "requirements.txt", "pubspec.yaml")) \
    or any(f.startswith("supabase/") for f in FILES)
uses_firebase = any(re.search(r"(^|/)(firestore\.rules|storage\.rules|database\.rules\.json|firebase\.json)$", f) for f in FILES)

# Is Supabase called straight from client code (anon key in the browser)? Then RLS is the only guard.
client_supabase = [f for f in FILES if f.endswith(CODE_EXT) and not SERVER_PATH.search(f) and re.search(r"createClient\s*\(", read(f)) and "supabase" in read(f).lower()]

# ---------------------------------------------------------------- Supabase SQL
if uses_supabase:
    created, enabled = {}, set()
    for f in [x for x in FILES if x.endswith(".sql")]:
        sql = read(f)
        low = sql.lower()
        for m in re.finditer(r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?public\"?\.)?\"?(\w+)\"?", low):
            created.setdefault(m.group(1), f"{f}:{line_of(low, m.start())}")
        for m in re.finditer(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:\"?public\"?\.)?\"?(\w+)\"?\s+enable\s+row\s+level\s+security", low):
            enabled.add(m.group(1))
        for m in re.finditer(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:\"?public\"?\.)?\"?(\w+)\"?\s+disable\s+row\s+level\s+security", low):
            emit("critical", "supabase-rls-disabled", f"{f}:{line_of(low, m.start())}", f"RLS explicitly disabled on table {m.group(1)}")
        for m in re.finditer(r"create\s+policy\s+(\"[^\"]*\"|\w+)\s+on\s+(?:\"?public\"?\.)?\"?(\w+)\"?(.*?);", low, re.S):
            body = m.group(3)
            op = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", body)
            op = op.group(1) if op else "all"
            open_ = re.search(r"using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)", body)
            if open_:
                loc = f"{f}:{line_of(low, m.start())}"
                if op == "select":
                    emit("warning", "supabase-policy-open-read", loc, f"policy {m.group(1)} lets everyone read every row of {m.group(2)} — fine only for truly public data")
                else:
                    emit("critical", "supabase-policy-open-write", loc, f"policy {m.group(1)} on {m.group(2)} allows {op} for everyone (using/with check true)")
    for table, loc in sorted(created.items()):
        if table not in enabled:
            sev = "critical" if client_supabase else "warning"
            why = "the browser talks to Supabase directly, so anyone with the anon key can read/write it" if client_supabase \
                else ("Supabase serves public-schema tables over its REST API to anyone holding the anon key; enable RLS "
                      "(with no policies it denies anon access, while the service role still works) as defense in depth")
            emit(sev, "supabase-rls-missing", loc, f"table {table} has no 'enable row level security' — {why}")

# ---------------------------------------------------------------- service_role key in client code
def jwt_role(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except Exception:
        return None


for f in FILES:
    if not f.endswith(CODE_EXT + (".env", ".json", ".py", ".yaml", ".yml")) and not re.search(r"(^|/)\.env", f):
        continue
    text = read(f)
    for m in re.finditer(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", text):
        if jwt_role(m.group(0)) == "service_role":
            emit("critical", "supabase-service-role-key", f"{f}:{line_of(text, m.start())}",
                 "hardcoded Supabase service_role key — it bypasses all RLS; rotate it (Project Settings → API) and keep it server-side")
    if f.endswith(CODE_EXT) and not SERVER_PATH.search(f):
        m = re.search(r"(SUPABASE_SERVICE_ROLE\w*|service_?role_?key|serviceRoleKey)", text, re.I)
        if m and re.search(r"createClient\s*\(", text):
            emit("critical", "supabase-service-role-client", f"{f}:{line_of(text, m.start())}",
                 "service_role key used in client-side code — anyone can extract it from the bundle and bypass RLS")

# ---------------------------------------------------------------- Firebase rules
for f in FILES:
    base = os.path.basename(f)
    if base in ("firestore.rules", "storage.rules") or f.endswith(".rules"):
        text = read(f)
        for m in re.finditer(r"allow\s+([a-z, ]+?)\s*(?::\s*if\s+true\s*;|;)", text):
            ops = m.group(1)
            sev = "critical" if re.search(r"write|create|update|delete", ops) else "warning"
            emit(sev, "firebase-rules-open", f"{f}:{line_of(text, m.start())}", f"'allow {ops.strip()}' with no condition — open to everyone")
        for m in re.finditer(r"request\.time\s*<\s*timestamp\.date\(", text):
            emit("critical", "firebase-rules-test-mode", f"{f}:{line_of(text, m.start())}",
                 "test-mode rules: the database is open to everyone until this date, then locks everyone out")
    elif base == "database.rules.json":
        text = read(f)
        for m in re.finditer(r"\"\.(read|write)\"\s*:\s*(true|\"true\")", text):
            sev = "critical" if m.group(1) == "write" else "warning"
            emit(sev, "firebase-rules-open", f"{f}:{line_of(text, m.start())}", f"Realtime Database '.{m.group(1)}': true — open to everyone")

# ---------------------------------------------------------------- report
if not (uses_supabase or uses_firebase or found):
    sys.exit(0)
print(f"Supabase: {'yes' if uses_supabase else 'no'}{' (called from client code: ' + ', '.join(client_supabase[:3]) + ')' if client_supabase else ''} | Firebase rules: {'yes' if uses_firebase else 'no'}")
if uses_supabase and not any(f.endswith(".sql") for f in FILES):
    print("  No .sql files in the repo — RLS can't be checked from code. Check every table in the Supabase dashboard (Table Editor shows 'RLS disabled'),")
    print("  or pull the schema with `supabase db pull` and re-scan.")
if not found:
    print("No open rules, missing RLS or exposed service keys found.")
for sev, rule, loc, msg in found:
    print(f"  {'CRITICAL' if sev == 'critical' else 'warning ':8} {loc:40} {msg}")
if FINDINGS and found:
    with open(FINDINGS, "a", encoding="utf-8") as fh:
        fh.write("".join(f"{s}\t{r}\t{l}\t{m}\n" for s, r, l, m in found))
