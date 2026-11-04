#!/usr/bin/env python3
"""List HTTP routes and flag the ones with no visible auth guard.

Heuristic, not a proof: a route marked GUARDED may still have broken checks,
and an UNGUARDED one may be protected somewhere this script can't see (mount-level
middleware in another file, API Gateway authorizer). Read the code before scoring.

Supports: Express/Koa-style routers (JS/TS), FastAPI, Flask, Next.js route
handlers (app/**/route.ts, pages/api/**). Lambda handlers are listed separately.

Usage: routes.py <repo-path>
"""
import os
import re
import subprocess
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
SKIP_DIRS = re.compile(r"(^|/)(node_modules|dist|build|\.next|venv|\.venv|__pycache__|vendor|coverage|test|tests|__tests__|e2e)/")
AUTH = re.compile(
    r"auth|Auth|requireUser|require_?user|requireRole|require_role|login_required|jwt|verify(Token|_token|Supabase|_supabase)"
    r"|guard|Guard|protect|isAuthenticated|current_user|currentUser|getSession|getServerSession|get_current|session\.user"
    r"|requireActive|requireAdmin|require_admin|permission",
)
PUBLIC_HINT = re.compile(r"/auth/|refresh|login|logout|signin|signup|register|otp|forgot|reset[-_]?password|password[-_/]reset|health|ready|status|callback|verify|public|static|favicon|^/?$", re.I)
WEBHOOK_HINT = re.compile(r"webhook|hook|whatsapp|twilio|stripe|razorpay|smepay|payment[-_]?(callback|notify)", re.I)
SIGNATURE = re.compile(r"signature|validateRequest|constructEvent|hmac|verify_?webhook|x-hub-signature|X-Twilio-Signature", re.I)

EXPRESS_ROUTE = re.compile(r"\b(app|router|api|server|r)\.(get|post|put|patch|delete|all)\(\s*(['\"`])([^'\"`]*)\3(.*)")
EXPRESS_USE_AUTH = re.compile(r"\b(app|router|api|r)\.use\(([^)]*)\)")
FASTAPI_ROUTE = re.compile(r"@(\w+)\.(get|post|put|patch|delete|api_route)\(\s*['\"]([^'\"]*)['\"]")
FASTAPI_ROUTER_DEPS = re.compile(r"APIRouter\([^)]*dependencies\s*=\s*\[[^\]]*Depends\(([^)]*)\)")
FLASK_ROUTE = re.compile(r"@(\w+)\.route\(\s*['\"]([^'\"]*)['\"](.*)")
NEXT_HANDLER = re.compile(r"export\s+(async\s+)?(function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b")


def tracked_files():
    try:
        out = subprocess.run(["git", "-C", ROOT, "ls-files"], capture_output=True, text=True, check=True).stdout
        files = out.splitlines()
    except Exception:
        files = [os.path.relpath(os.path.join(d, f), ROOT) for d, _, fs in os.walk(ROOT) for f in fs]
    return [f for f in files if not SKIP_DIRS.search("/" + f)]


def read(path):
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


routes, lambdas, mount_auth = [], [], []

for f in tracked_files():
    ext = os.path.splitext(f)[1]
    if ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        lines = read(f)
        # Next.js route handlers: guarded if the file calls any auth helper.
        if re.search(r"(^|/)(app/.*/route|pages/api/.*)\.(t|j)sx?$", f):
            file_guarded = any(AUTH.search(l) for l in lines)
            for i, l in enumerate(lines, 1):
                m = NEXT_HANDLER.search(l)
                if m:
                    path = "/" + re.sub(r"^.*?(?:^|/)(?:src/)?(?:app|pages)/(?=api/)|/route\.(t|j)sx?$|\.(t|j)sx?$", "", f)
                    routes.append((m.group(3), path, f, i, file_guarded))
            continue
        guarded_from = None  # router.use(requireAuth) guards every later route in the file
        for i, l in enumerate(lines, 1):
            u = EXPRESS_USE_AUTH.search(l)
            if u and AUTH.search(u.group(2)):
                if re.match(r"\s*['\"`]", u.group(2)):  # app.use("/api/x", requireAuth, router)
                    mount_auth.append(f"{f}:{i}")
                elif guarded_from is None:
                    guarded_from = i
            m = EXPRESS_ROUTE.search(l)
            if m:
                rest = m.group(5)
                guarded = bool(AUTH.search(rest)) or (guarded_from is not None and i > guarded_from)
                routes.append((m.group(2).upper(), m.group(4), f, i, guarded))
    elif ext == ".py":
        lines = read(f)
        text = "\n".join(lines)
        router_guarded = bool(re.search(FASTAPI_ROUTER_DEPS, text)) and bool(AUTH.search(" ".join(FASTAPI_ROUTER_DEPS.findall(text))))
        if re.search(r"def\s+(lambda_)?handler\s*\(\s*event\s*,\s*context", text):
            lambdas.append(f)
        for i, l in enumerate(lines, 1):
            if re.search(r"@\w+\.(get|post|put|patch|delete|api_route|route)\(\s*$", l) and i < len(lines):
                l = l.rstrip() + lines[i].strip()  # path is on the next line
            m = FASTAPI_ROUTE.search(l)
            fl = FLASK_ROUTE.search(l)
            if not (m or fl):
                continue
            # Collect decorators above/below and the def signature up to "):" (FastAPI deps live there).
            block = []
            for j in range(max(0, i - 4), min(len(lines), i + 25)):
                block.append(lines[j])
                if j >= i and re.search(r"\)\s*(->[^:]*)?:\s*$", lines[j]):
                    break
            sig = "\n".join(block)
            guarded = router_guarded or bool(re.search(r"Depends\([^)]*(" + AUTH.pattern + r")", sig)) or bool(
                re.search(r"@(login_required|jwt_required|auth\.login_required|requires_auth|permission_required)", sig))
            if m:
                method = m.group(2).upper() if m.group(2) != "api_route" else "ANY"
                routes.append((method, m.group(3), f, i, guarded))
            else:
                methods = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", fl.group(3)) or ["GET"]
                routes.append(("/".join(methods), fl.group(2), f, i, guarded))

if not routes and not lambdas:
    print("No HTTP routes found (supported: Express-style, FastAPI, Flask, Next.js).")
    sys.exit(0)

write = lambda m: any(x in m for x in ("POST", "PUT", "PATCH", "DELETE", "ALL", "ANY"))
unguarded = [r for r in routes if not r[4]]
is_hook = lambda r: write(r[0]) and (WEBHOOK_HINT.search(r[1]) or WEBHOOK_HINT.search(os.path.basename(r[2])))
hooks = [r for r in unguarded if is_hook(r)]
risky = [r for r in unguarded if write(r[0]) and r not in hooks and not PUBLIC_HINT.search(r[1])]
public_like = [r for r in unguarded if r not in risky and r not in hooks]
signed_files = {f for f in {r[2] for r in hooks} if any(SIGNATURE.search(l) for l in read(f))}

print(f"Routes found: {len(routes)} | with visible auth guard: {len(routes) - len(unguarded)} | without: {len(unguarded)}")
if mount_auth:
    print(f"Mount-level auth middleware seen at {', '.join(mount_auth[:5])} — routes in those routers may be guarded there; verify.")
if risky:
    print(f"\nUNGUARDED WRITE ROUTES ({len(risky)}) — anyone can call these unless protected elsewhere:")
    for m, p, f, i, _ in risky[:40]:
        print(f"  {m:7} {p or '(dynamic)':40} {f}:{i}")
if hooks:
    print(f"\nWebhook-style routes ({len(hooks)}) — must verify the sender's signature (and fail closed if the secret is unset):")
    for m, p, f, i, _ in hooks[:15]:
        note = "signature check found in file" if f in signed_files else "NO SIGNATURE CHECK FOUND"
        print(f"  {m:7} {p or '(dynamic)':40} {f}:{i}  [{note}]")
if public_like:
    print(f"\nUnguarded but look public-by-design or read-only ({len(public_like)}) — confirm each is meant to be public:")
    for m, p, f, i, _ in public_like[:25]:
        print(f"  {m:7} {p or '(dynamic)':40} {f}:{i}")
if lambdas:
    print(f"\nLambda handlers ({len(lambdas)}): {', '.join(lambdas[:10])}")
    print("  -> auth must come from an API Gateway authorizer or a check inside the handler; verify.")
