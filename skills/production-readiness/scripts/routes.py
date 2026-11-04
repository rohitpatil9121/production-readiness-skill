#!/usr/bin/env python3
"""List HTTP routes, flag the ones with no visible auth guard, and flag likely IDOR.

Heuristic, not a proof: a route marked guarded may still have broken checks, and
an unguarded one may be protected somewhere this script can't see (global
middleware in another file, an API gateway authorizer). Read the code before scoring.

Frameworks: Express/Koa/Fastify-style routers, NestJS, Next.js route handlers,
FastAPI, Flask, Django/DRF, Spring, Go (gin/echo/chi/net-http), Laravel, Rails.
Lambda handlers are listed separately.

Usage: routes.py <repo-path>
If PRS_FINDINGS is set, findings are also appended to that file as tab-separated
lines: severity, rule, location, message.
"""
import os
import re
import subprocess
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."
FINDINGS = os.environ.get("PRS_FINDINGS")
SKIP_DIRS = re.compile(r"(^|/)(node_modules|dist|build|\.next|venv|\.venv|__pycache__|vendor|coverage|test|tests|__tests__|e2e|spec|migrations)/")

AUTH = re.compile(
    r"auth|Auth|requireUser|require_?user|requireRole|require_role|login_required|jwt|verify(Token|_token|Supabase|_supabase)"
    r"|guard|Guard|protect|isAuthenticated|IsAuthenticated|current_user|currentUser|getSession|getServerSession|get_current"
    r"|session\.user|requireActive|requireAdmin|require_admin|permission|Permission|PreAuthorize|Secured|RolesAllowed"
)
PUBLIC_HINT = re.compile(r"/auth/|refresh|login|logout|signin|signup|register|otp|forgot|reset[-_]?password|password[-_/]reset"
                         r"|health|ready|status|callback|verify|public|static|favicon|^/?$", re.I)
WEBHOOK_HINT = re.compile(r"webhook|hook|whatsapp|twilio|stripe|razorpay|smepay|payment[-_]?(callback|notify)", re.I)
SIGNATURE = re.compile(r"signature|validateRequest|constructEvent|hmac|verify_?webhook|x-hub-signature|X-Twilio-Signature", re.I)

# IDOR: a handler loads a record by an id from the URL, and nothing in the handler
# mentions the current user/owner. Only checked on guarded routes (unguarded ones
# are already reported as worse).
ID_LOOKUP = re.compile(
    r"findById\(|findByPk\(|findUnique\(|findFirst\(|findOne\(|\.get\(\s*\w+\s*,\s*\w*id\b|\.get_object_or_404\(|get_object_or_404\("
    r"|\.filter\([^)]*\bid\b|\.eq\(\s*['\"]id['\"]|WHERE\s+id\s*=|where:\s*\{\s*(id|_id)\b|\.find\(\s*params\[:id\]\)|::find(OrFail)?\(|findById\b"
    r"|objects\.get\(\s*(pk|id)\s*=|\.First\(&\w+,\s*\w*[iI][dD]\)",
    re.I,
)
OWNER = re.compile(r"owner|user_?id|userId|req\.user|request\.user|current_user|currentUser|auth\(\)|Auth::|session\.user|tenant|account_?id|organization", re.I)

routes = []      # (method, path, file, line, guarded, idor)
notes = []       # free-text notes
lambdas = []
mount_auth = []


def tracked_files():
    try:
        out = subprocess.run(["git", "-C", ROOT, "ls-files"], capture_output=True, text=True, check=True).stdout
        files = out.splitlines()
    except Exception:
        files = [os.path.relpath(os.path.join(d, f), ROOT) for d, _, fs in os.walk(ROOT) for f in fs]
    return [f for f in files if not SKIP_DIRS.search("/" + f)]


_cache = {}
def read(path):
    if path not in _cache:
        try:
            with open(os.path.join(ROOT, path), encoding="utf-8", errors="ignore") as fh:
                _cache[path] = fh.read().splitlines()
        except OSError:
            _cache[path] = []
    return _cache[path]


def window(lines, i, n=30):
    """Handler body heuristic: from the route line until the next route-ish line or n lines."""
    out = []
    for j in range(i - 1, min(len(lines), i - 1 + n)):
        if j > i - 1 and re.search(r"^\s*(@\w+\.(get|post|put|patch|delete|route)|\b(app|router|r)\.(get|post|put|patch|delete)\(|@(Get|Post|Put|Patch|Delete)\(|def \w+\(|public function )", lines[j]):
            break
        out.append(lines[j])
    return "\n".join(out)


def idor(lines, i, path):
    if not re.search(r":\w*id\b|\{\w*id\}|<\w*:?\w*id>|\[\w*id\]|\{\w*\}", path or "", re.I):
        return False
    body = window(lines, i)
    return bool(ID_LOOKUP.search(body)) and not OWNER.search(body)


def add(method, path, f, i, guarded, lines=None):
    routes.append((method, path, f, i, guarded, guarded and lines is not None and idor(lines, i, path)))


# ------------------------------------------------------------------ JS / TS
EXPRESS_ROUTE = re.compile(r"\b(app|router|api|server|r|fastify|routes)\.(get|post|put|patch|delete|all)\(\s*(['\"`])([^'\"`]*)\3(.*)")
EXPRESS_USE_AUTH = re.compile(r"\b(app|router|api|r|server|fastify)\.(use|addHook|register)\(([^)]*)\)")
NEXT_HANDLER = re.compile(r"export\s+(async\s+)?(function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b")
NEST_CONTROLLER = re.compile(r"@Controller\(\s*(?:['\"`]([^'\"`]*)['\"`])?")
NEST_METHOD = re.compile(r"@(Get|Post|Put|Patch|Delete|All)\(\s*(?:['\"`]([^'\"`]*)['\"`])?")


def scan_js(f, lines):
    text = "\n".join(lines)
    if re.search(r"(^|/)(app/.*/route|pages/api/.*)\.(t|j)sx?$", f):
        file_guarded = bool(AUTH.search(text))
        for i, l in enumerate(lines, 1):
            m = NEXT_HANDLER.search(l)
            if m:
                path = "/" + re.sub(r"^.*?(?:^|/)(?:src/)?(?:app|pages)/(?=api/)|/route\.(t|j)sx?$|\.(t|j)sx?$", "", f)
                add(m.group(3), path, f, i, file_guarded, lines)
        return
    if "@Controller" in text:  # NestJS
        base, class_guard = "", False
        for i, l in enumerate(lines, 1):
            c = NEST_CONTROLLER.search(l)
            if c:
                base = "/" + (c.group(1) or "").strip("/")
                class_guard = any("@UseGuards" in x for x in lines[max(0, i - 4):i])
                continue
            m = NEST_METHOD.search(l)
            if m:
                deco = "\n".join(lines[max(0, i - 4):i + 3])
                guarded = class_guard or "@UseGuards" in deco or bool(re.search(r"@(Roles|Auth\w*)\(", deco))
                path = (base.rstrip("/") + "/" + (m.group(2) or "").strip("/")).rstrip("/") or "/"
                add(m.group(1).upper(), path, f, i, guarded, lines)
        return
    guarded_from = None
    for i, l in enumerate(lines, 1):
        u = EXPRESS_USE_AUTH.search(l)
        if u and AUTH.search(u.group(3)):
            if re.match(r"\s*['\"`]", u.group(3)):
                mount_auth.append(f"{f}:{i}")
            elif guarded_from is None:
                guarded_from = i
        m = EXPRESS_ROUTE.search(l)
        if m:
            guarded = bool(AUTH.search(m.group(5))) or (guarded_from is not None and i > guarded_from)
            add(m.group(2).upper(), m.group(4), f, i, guarded, lines)


# ------------------------------------------------------------------ Python
FASTAPI_ROUTE = re.compile(r"@(\w+)\.(get|post|put|patch|delete|api_route)\(\s*['\"]([^'\"]*)['\"]")
FASTAPI_ROUTER_DEPS = re.compile(r"(APIRouter|FastAPI)\([^)]*dependencies\s*=\s*\[[^\]]*Depends\(([^)]*)\)", re.S)
FLASK_ROUTE = re.compile(r"@(\w+)\.route\(\s*['\"]([^'\"]*)['\"](.*)")
DRF_DEFAULT_AUTH = re.compile(r"DEFAULT_PERMISSION_CLASSES[^\]]*IsAuthenticated", re.S)


def scan_py(f, lines, drf_global):
    text = "\n".join(lines)
    if re.search(r"def\s+(lambda_)?handler\s*\(\s*event\s*,\s*context", text):
        lambdas.append(f)
    router_guarded = any(AUTH.search(d[1]) for d in FASTAPI_ROUTER_DEPS.findall(text))
    for i, l in enumerate(lines, 1):
        if re.search(r"@\w+\.(get|post|put|patch|delete|api_route|route)\(\s*$", l) and i < len(lines):
            l = l.rstrip() + lines[i].strip()
        m = FASTAPI_ROUTE.search(l)
        fl = FLASK_ROUTE.search(l)
        if m or fl:
            block = []
            for j in range(max(0, i - 4), min(len(lines), i + 25)):
                block.append(lines[j])
                if j >= i and re.search(r"\)\s*(->[^:]*)?:\s*$", lines[j]):
                    break
            sig = "\n".join(block)
            guarded = router_guarded or bool(re.search(r"Depends\([^)]*(" + AUTH.pattern + r")", sig)) or bool(
                re.search(r"@(login_required|jwt_required|auth\.login_required|requires_auth|permission_required)", sig))
            if m:
                add(m.group(2).upper() if m.group(2) != "api_route" else "ANY", m.group(3), f, i, guarded, lines)
            else:
                methods = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", fl.group(3)) or ["GET"]
                add("/".join(methods), fl.group(2), f, i, guarded, lines)
            continue
        # Django / DRF function views
        dv = re.search(r"@api_view\(\s*\[([^\]]*)\]", l)
        if dv:
            start = i - 1
            while start > 0 and lines[start - 1].lstrip().startswith("@"):
                start -= 1
            end = i - 1
            while end < len(lines) - 1 and not lines[end].lstrip().startswith("def "):
                end += 1
            deco = "\n".join(lines[start:end + 1])
            d = re.search(r"def\s+(\w+)", lines[end])
            guarded = drf_global or bool(re.search(r"permission_classes\(\s*\[[^\]]*IsAuthenticated|login_required|IsAdminUser", deco))
            methods = "/".join(re.findall(r"['\"](\w+)['\"]", dv.group(1))) or "GET"
            add(methods, f"view:{d.group(1) if d else '?'}", f, i, guarded, lines)
            continue
        # Django / DRF class views
        cv = re.search(r"^class\s+(\w+)\(([^)]*(APIView|ViewSet|View|GenericAPIView|ListCreateAPIView|RetrieveUpdateDestroyAPIView|ModelViewSet|CreateView|UpdateView|DeleteView)[^)]*)\)", l)
        if cv:
            body = "\n".join(lines[i - 1:i + 40])
            guarded = drf_global or "LoginRequiredMixin" in cv.group(2) or "PermissionRequiredMixin" in cv.group(2) or bool(
                re.search(r"permission_classes\s*=\s*\[[^\]]*(IsAuthenticated|IsAdminUser|\w*Permission)", body)) or "login_required" in body
            writes = re.search(r"ModelViewSet|CreateView|UpdateView|DeleteView|ListCreate|Destroy|def (post|put|patch|delete)\(", cv.group(2) + body)
            add("WRITE" if writes else "GET", f"view:{cv.group(1)}", f, i, guarded, None)
        # Django function view with decorator (non-DRF)
        if re.match(r"\s*@login_required", l):
            continue


# ------------------------------------------------------------------ Java (Spring)
SPRING_CLASS = re.compile(r"@RequestMapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\"")
SPRING_METHOD = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\")?")


def scan_java(f, lines, spring_global):
    text = "\n".join(lines)
    if "@RestController" not in text and "@Controller" not in text:
        return
    base, class_guard = "", False
    for i, l in enumerate(lines, 1):
        if re.match(r"\s*(public\s+)?class\s", l):
            head = "\n".join(lines[max(0, i - 6):i])
            c = SPRING_CLASS.search(head)
            base = "/" + (c.group(1).strip("/") if c else "")
            class_guard = bool(re.search(r"@(PreAuthorize|Secured|RolesAllowed)", head))
            continue
        m = SPRING_METHOD.search(l)
        if m and not re.match(r"\s*(public\s+)?class", l) and i > 1:
            deco = "\n".join(lines[max(0, i - 4):i + 2])
            guarded = spring_global or class_guard or bool(re.search(r"@(PreAuthorize|Secured|RolesAllowed)", deco))
            method = m.group(1).upper() if m.group(1) != "Request" else "ANY"
            path = (base.rstrip("/") + "/" + (m.group(2) or "").strip("/")).rstrip("/") or "/"
            add(method, path, f, i, guarded, lines)


# ------------------------------------------------------------------ Go
GO_ROUTE = re.compile(r"\b(\w+)\.(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|Handle|HandleFunc)\(\s*\"([^\"]*)\"(.*)")
GO_USE = re.compile(r"\b(\w+)\.(Use|Group)\((.*)")


def scan_go(f, lines):
    guarded_groups, guarded_from = set(), None
    for i, l in enumerate(lines, 1):
        u = GO_USE.search(l)
        if u and AUTH.search(u.group(3)):
            lhs = re.match(r"\s*(\w+)\s*:?=", l)
            if lhs:
                guarded_groups.add(lhs.group(1))       # admin := r.Group("/admin", AuthRequired())
            else:
                guarded_groups.add(u.group(1))         # admin.Use(AuthRequired())
                if u.group(1) in ("r", "router", "e", "app", "mux") and guarded_from is None:
                    guarded_from = i
        m = GO_ROUTE.search(l)
        if m:
            method = m.group(2).upper()
            if method.startswith("HANDLE"):
                method = "ANY"
            guarded = m.group(1) in guarded_groups or bool(AUTH.search(m.group(4))) or (guarded_from is not None and i > guarded_from)
            add(method, m.group(3), f, i, guarded, lines)


# ------------------------------------------------------------------ PHP (Laravel)
LARAVEL_ROUTE = re.compile(r"Route::(get|post|put|patch|delete|any|resource|apiResource)\(\s*['\"]([^'\"]*)['\"](.*)")


def scan_php(f, lines):
    if not re.search(r"(^|/)routes/[^/]+\.php$", f):
        return
    depth, guard_depths = 0, []
    for i, l in enumerate(lines, 1):
        opens_group = re.search(r"middleware\([^)]*auth", l) and "group(" in l
        if opens_group:
            guard_depths.append(depth + 1)
        m = LARAVEL_ROUTE.search(l)
        if m:
            guarded = bool(guard_depths) or bool(re.search(r"->middleware\([^)]*auth", m.group(3)))
            method = {"resource": "WRITE", "apiResource": "WRITE", "any": "ANY"}.get(m.group(1), m.group(1).upper())
            add(method, m.group(2), f, i, guarded, None)
        depth += l.count("{") - l.count("}")
        while guard_depths and depth < guard_depths[-1]:
            guard_depths.pop()


# ------------------------------------------------------------------ Ruby (Rails)
def scan_rails(files):
    ctrls = [f for f in files if re.search(r"(^|/)app/controllers/.+_controller\.rb$", f)]
    if not ctrls:
        return
    app_ctrl = next((f for f in ctrls if f.endswith("application_controller.rb")), None)
    global_auth = bool(app_ctrl) and bool(re.search(r"before_action\s+:authenticate|before_action\s+:require_login|before_action\s+:authorize",
                                                     "\n".join(read(app_ctrl))))
    for f in ctrls:
        if f == app_ctrl:
            continue
        lines = read(f)
        text = "\n".join(lines)
        own = re.search(r"before_action\s+:(authenticate\w*|require_login|authorize\w*)(.*)", text)
        skip = re.search(r"skip_before_action\s+:(authenticate\w*|require_login)(.*)", text)
        for i, l in enumerate(lines, 1):
            m = re.match(r"\s*def\s+(create|update|destroy|show|edit|index|new)\b", l)
            if not m:
                continue
            action = m.group(1)
            guarded = global_auth or bool(own)
            if skip and (not re.search(r"only:", skip.group(2)) or re.search(rf":{action}\b", skip.group(2))):
                guarded = False
            method = {"create": "POST", "update": "PUT", "destroy": "DELETE"}.get(action, "GET")
            name = re.sub(r"^.*app/controllers/|_controller\.rb$", "", f)
            add(method, f"{name}#{action}", f, i, guarded, None)


# ------------------------------------------------------------------ run
files = tracked_files()
drf_global = any(DRF_DEFAULT_AUTH.search("\n".join(read(f))) for f in files if re.search(r"settings[^/]*\.py$|(^|/)settings/", f))
spring_global = any(re.search(r"anyRequest\(\)\s*\.\s*authenticated\(\)", "\n".join(read(f))) for f in files if f.endswith(".java"))
if drf_global:
    notes.append("DRF DEFAULT_PERMISSION_CLASSES requires authentication globally — views opt out with permission_classes = [AllowAny].")
if spring_global:
    notes.append("Spring Security: anyRequest().authenticated() found — routes are authenticated unless permitAll() matches them.")

for f in files:
    ext = os.path.splitext(f)[1]
    if ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        scan_js(f, read(f))
    elif ext == ".py":
        scan_py(f, read(f), drf_global)
    elif ext in (".java", ".kt"):
        scan_java(f, read(f), spring_global)
    elif ext == ".go":
        scan_go(f, read(f))
    elif ext == ".php":
        scan_php(f, read(f))
scan_rails(files)

if not routes and not lambdas:
    print("No HTTP routes found (supported: Express-style, NestJS, Next.js, FastAPI, Flask, Django/DRF, Spring, Go, Laravel, Rails).")
    sys.exit(0)

is_write = lambda m: any(x in m for x in ("POST", "PUT", "PATCH", "DELETE", "ALL", "ANY", "WRITE"))
unguarded = [r for r in routes if not r[4]]
hooks = [r for r in unguarded if is_write(r[0]) and (WEBHOOK_HINT.search(r[1]) or WEBHOOK_HINT.search(os.path.basename(r[2])))]
risky = [r for r in unguarded if is_write(r[0]) and r not in hooks and not PUBLIC_HINT.search(r[1])]
public_like = [r for r in unguarded if r not in risky and r not in hooks]
signed = {f for f in {r[2] for r in hooks} if any(SIGNATURE.search(l) for l in read(f))}
idors = [r for r in routes if r[5]]

out = []
def emit(sev, rule, loc, msg):
    out.append(f"{sev}\t{rule}\t{loc}\t{msg}")

print(f"Routes found: {len(routes)} | with visible auth guard: {len(routes) - len(unguarded)} | without: {len(unguarded)}")
for n in notes:
    print(n)
if mount_auth:
    print(f"Mount-level auth middleware seen at {', '.join(mount_auth[:5])} — routes in those routers may be guarded there; verify.")
if risky:
    print(f"\nUNGUARDED WRITE ROUTES ({len(risky)}) — anyone can call these unless protected elsewhere:")
    for m, p, f, i, *_ in risky[:40]:
        print(f"  {m:7} {p or '(dynamic)':40} {f}:{i}")
    for m, p, f, i, *_ in risky:
        emit("critical", "unguarded-write-route", f"{f}:{i}", f"{m} {p} has no visible auth guard")
if hooks:
    print(f"\nWebhook-style routes ({len(hooks)}) — must verify the sender's signature (and fail closed if the secret is unset):")
    for m, p, f, i, *_ in hooks[:15]:
        print(f"  {m:7} {p or '(dynamic)':40} {f}:{i}  [{'signature check found in file' if f in signed else 'NO SIGNATURE CHECK FOUND'}]")
    for m, p, f, i, *_ in hooks:
        if f not in signed:
            emit("critical", "unsigned-webhook", f"{f}:{i}", f"{m} {p} accepts webhooks without a signature check")
if idors:
    print(f"\nPOSSIBLE IDOR ({len(idors)}) — authenticated, but the record is looked up by URL id with no owner/user check in the handler:")
    for m, p, f, i, *_ in idors[:25]:
        print(f"  {m:7} {p or '(dynamic)':40} {f}:{i}")
    for m, p, f, i, *_ in idors:
        emit("warning", "possible-idor", f"{f}:{i}", f"{m} {p} loads a record by id without an owner check")
if public_like:
    print(f"\nUnguarded but look public-by-design or read-only ({len(public_like)}) — confirm each is meant to be public:")
    for m, p, f, i, *_ in public_like[:25]:
        print(f"  {m:7} {p or '(dynamic)':40} {f}:{i}")
if lambdas:
    print(f"\nLambda handlers ({len(lambdas)}): {', '.join(lambdas[:10])}")
    print("  -> auth must come from an API Gateway authorizer or a check inside the handler; verify.")

if FINDINGS and out:
    with open(FINDINGS, "a", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
