#!/usr/bin/env bash
# Tests for scan.sh, routes.py and install.sh.
# Fixture apps are generated in a temp dir at run time: fake secrets are
# assembled from parts so no secret-looking string is committed to this repo.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SCAN="$REPO/skills/production-readiness/scripts/scan.sh"
ROUTES="$REPO/skills/production-readiness/scripts/routes.py"
WORK="$(mktemp -d)"
if [ -n "${KEEP:-}" ]; then echo "Fixtures kept in $WORK"; else trap 'rm -rf "$WORK"' EXIT; fi
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); printf "  ok   %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf "  FAIL %s\n" "$1"; }
has()  { if printf "%s" "$OUT" | grep -qE -- "$2"; then ok "$1"; else bad "$1  (expected /$2/)"; fi; }
hasnt(){ if printf "%s" "$OUT" | grep -qE -- "$2"; then bad "$1  (did not expect /$2/)"; else ok "$1"; fi; }

newrepo(){ mkdir -p "$WORK/$1" && cd "$WORK/$1" && git init -q && git config user.email t@example.com && git config user.name test; }
commit(){ git add -A && git commit -qm "$1"; }

# ---------------------------------------------------------------- fixtures
U="admin"; P="hunter2-$(printf 'fake')-pass"; HOST="cluster0.example.net"
MONGO="mongodb+srv://$U:$P@$HOST/db"

newrepo vuln-express
cat > package.json <<'EOF'
{ "name": "vuln", "dependencies": { "express": "^4.19.2", "mongodb": "^6.0.0", "cors": "^2.8.5" } }
EOF
echo "const uri = \"$MONGO\";" > db.js
commit "add db"
cat > db.js <<'EOF'
const uri = process.env.MONGODB_URI;
EOF
cat > index.js <<'EOF'
const express = require("express");
const cors = require("cors");
const app = express();
app.use(cors());
app.use(express.json());
app.get("/health", (req, res) => res.json({ ok: true }));
app.post("/api/posts/:id/delete", async (req, res) => { res.json({ deleted: req.params.id }); });
app.post("/webhook", (req, res) => { res.sendStatus(200); });
app.post("/api/login", (req, res) => {
  const otp = String(Math.floor(Math.random() * 900000));
  console.log("token", req.body.token);
  res.json({ otp });
});
app.listen(process.env.PORT || 3000);
EOF
printf ".env\nnode_modules/\n" > .gitignore
commit "app"

newrepo clean-express
cat > package.json <<'EOF'
{ "name": "clean", "dependencies": { "express": "^4.19.2", "helmet": "^8.0.0", "express-rate-limit": "^8.0.0", "jsonwebtoken": "^9.0.0" } }
EOF
cat > index.js <<'EOF'
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { requireAuth } = require("./auth");
const app = express();
app.use(helmet());
app.use(rateLimit({ windowMs: 60000, limit: 100 }));
app.post("/api/login", (req, res) => res.json({}));
app.post("/api/notes", requireAuth, (req, res) => res.json({}));
app.delete("/api/notes/:id", requireAuth, (req, res) => res.json({}));
app.listen(process.env.PORT || 3000);
EOF
cat > auth.js <<'EOF'
const jwt = require("jsonwebtoken");
exports.requireAuth = (req, res, next) => { req.user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET); next(); };
EOF
printf ".env\n" > .gitignore; printf "JWT_SECRET=\n" > .env.example
commit "clean app"

newrepo fastapi-app
printf "fastapi\nuvicorn\n" > requirements.txt
mkdir -p app
cat > app/config.py <<'EOF'
class Settings:
    debug: bool = True
EOF
cat > app/main.py <<'EOF'
from fastapi import FastAPI, Depends, APIRouter
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
router = APIRouter()
app.add_middleware(CORSMiddleware, allow_origins=["*"])


def get_current_user():
    ...


@router.post(
    "/notes",
)
def create_note(
    body: dict,
    user=Depends(get_current_user),
):
    return body


@app.delete("/notes/{note_id}")
def delete_note(note_id: int):
    return {"ok": True}
EOF
commit "fastapi"

newrepo static-site
printf "<html><body>hi</body></html>\n" > index.html
commit "site"

newrepo serverless
printf '{ "name": "s", "dependencies": { "next": "15.0.0" } }\n' > package.json
printf '{ "functions": {} }\n' > vercel.json
mkdir -p app/api/items
cat > app/api/items/route.ts <<'EOF'
export async function POST(req: Request) { return Response.json({}); }
EOF
commit "next"

# ---------------------------------------------------------------- tests
echo "scan.sh — vulnerable Express app"
OUT=$(bash "$SCAN" "$WORK/vuln-express" 2>&1)
has   "detects backend profile"                 "type=backend/full-stack"
has   "flags CORS allow-all"                    "CORS allow-all +index.js:4"
has   "flags weak randomness for OTP"           "Weak randomness for tokens +index.js:10"
has   "flags secrets in logs"                   "Secrets in logs +index.js:11"
has   "flags unguarded delete route"            "POST +/api/posts/:id/delete"
has   "flags unsigned webhook"                  "/webhook.*NO SIGNATURE CHECK FOUND"
has   "finds secret removed from code but in history" "removed since: [1-9]"
hasnt "never prints the secret value"           "$P"

echo "scan.sh — clean Express app"
OUT=$(bash "$SCAN" "$WORK/clean-express" 2>&1)
has   "sees guarded routes"                     "with visible auth guard: 2"
hasnt "no unguarded write routes"               "UNGUARDED WRITE ROUTES"
has   "no risky patterns"                       "== Risky patterns.*"
hasnt "no CORS warning"                         "CORS allow-all"
has   "history clean"                           "removed since: 0"

echo "scan.sh — FastAPI app"
OUT=$(bash "$SCAN" "$WORK/fastapi-app" 2>&1)
has   "flags debug on"                          "Debug on +app/config.py:2"
has   "flags CORS wildcard"                     "CORS allow-all +app/main.py:6"
has   "multi-line decorator route guarded via Depends" "with visible auth guard: 1"
has   "unguarded delete flagged"                "DELETE +/notes/\\{note_id\\}"

echo "scan.sh — static site"
OUT=$(bash "$SCAN" "$WORK/static-site" 2>&1)
has   "detects static site"                     "type=static site"
has   "says server areas are N/A"               "No own backend detected"
hasnt "no .env nagging for static sites"        ".env ignored by git"

echo "scan.sh — Next.js on Vercel"
OUT=$(bash "$SCAN" "$WORK/serverless" 2>&1)
has   "detects serverless deploy"               "vercel\\(serverless\\)"
has   "warns about in-memory state"             "Serverless: in-memory"
has   "Next.js route path normalized"           "POST +/api/items"

echo "routes.py — standalone"
OUT=$(python3 "$ROUTES" "$WORK/clean-express" 2>&1)
has   "runs standalone"                         "Routes found: 3"

# ---------------------------------------------------------------- frameworks
SCRIPTS="$REPO/skills/production-readiness/scripts"
newrepo frameworks
mkdir -p nest/src django/app spring/src go laravel/routes rails/app/controllers
cat > nest/src/notes.controller.ts <<'EOF'
@Controller('notes')
export class NotesController {
  @UseGuards(JwtAuthGuard)
  @Post()
  create() {}

  @Delete(':id')
  remove() {}
}
EOF
cat > django/app/views.py <<'EOF'
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_note(request):
    pass

@api_view(['DELETE'])
def delete_note(request, pk):
    pass
EOF
cat > spring/src/NoteController.java <<'EOF'
@RestController
@RequestMapping("/api/notes")
public class NoteController {
    @PreAuthorize("isAuthenticated()")
    @PostMapping
    public Note create() { return null; }

    @DeleteMapping("/{id}")
    public void delete() {}
}
EOF
cat > go/main.go <<'EOF'
package main
func main() {
	r := gin.Default()
	r.POST("/public/signup", signup)
	r.DELETE("/items/:id", deleteItem)
	admin := r.Group("/admin", AuthRequired())
	admin.POST("/users", createUser)
}
EOF
cat > laravel/routes/api.php <<'EOF'
<?php
Route::middleware(['auth:sanctum'])->group(function () {
    Route::post('/notes', [NoteController::class, 'store']);
});
Route::delete('/files/{id}', [FileController::class, 'destroy']);
EOF
cat > rails/app/controllers/application_controller.rb <<'EOF'
class ApplicationController < ActionController::Base
end
EOF
cat > rails/app/controllers/posts_controller.rb <<'EOF'
class PostsController < ApplicationController
  def create
  end
  def destroy
  end
end
EOF
cat > rails/app/controllers/comments_controller.rb <<'EOF'
class CommentsController < ApplicationController
  before_action :authenticate_user!
  def create
  end
end
EOF
commit "frameworks"
echo "routes.py — other frameworks"
OUT=$(python3 "$ROUTES" "$WORK/frameworks" 2>&1)
has   "NestJS guarded route seen"               "Routes found: 1[0-9]"
has   "NestJS unguarded delete"                 "DELETE +/notes/:id +nest/src/notes.controller.ts"
has   "DRF unguarded delete"                    "DELETE +view:delete_note"
hasnt "DRF guarded create not flagged"          "view:create_note"
has   "Spring unguarded delete"                 "DELETE +/api/notes/\\{id\\}"
hasnt "Spring guarded post not flagged"         "POST +/api/notes +spring"
has   "Go unguarded delete"                     "DELETE +/items/:id"
hasnt "Go group with auth middleware guarded"   "POST +/users"
has   "Laravel unguarded delete"                "DELETE +/files/\\{id\\}"
hasnt "Laravel auth group guarded"              "POST +/notes +laravel"
has   "Rails unguarded destroy"                 "DELETE +posts#destroy"
hasnt "Rails before_action guarded"             "comments#create"

# ---------------------------------------------------------------- IDOR
newrepo idor
printf '{ "dependencies": { "express": "^4" } }\n' > package.json
cat > index.js <<'EOF'
const app = require("express")();
app.get("/api/notes/:id", requireAuth, async (req, res) => {
  const note = await db.note.findUnique({ where: { id: req.params.id } });
  res.json(note);
});
app.get("/api/docs/:id", requireAuth, async (req, res) => {
  const doc = await db.doc.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });
  res.json(doc);
});
app.listen(3000);
EOF
commit idor
echo "routes.py — IDOR"
OUT=$(python3 "$ROUTES" "$WORK/idor" 2>&1)
has   "flags lookup by id without owner"        "POSSIBLE IDOR \\(1\\)"
has   "points at the right route"               "GET +/api/notes/:id"
hasnt "owner-checked route not flagged"         "GET +/api/docs/:id +index.js"

# ---------------------------------------------------------------- Supabase / Firebase
newrepo baas
printf '{ "dependencies": { "@supabase/supabase-js": "^2", "react": "^18" } }\n' > package.json
mkdir -p supabase/migrations src
cat > supabase/migrations/001.sql <<'EOF'
create table public.profiles (id uuid primary key, name text);
create table public.notes (id uuid primary key, body text);
alter table public.notes enable row level security;
create policy "anyone can edit" on public.notes for update using (true);
create policy "public read" on public.notes for select using (true);
EOF
H=$(printf '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=\n' | tr '/+' '_-')
PL=$(printf '{"iss":"supabase","role":"service_role","iat":1700000000}' | base64 | tr -d '=\n' | tr '/+' '_-')
SIG=$(printf 'notarealsignaturejustatestvalue' | base64 | tr -d '=\n' | tr '/+' '_-')
cat > src/supabase.js <<EOF
import { createClient } from "@supabase/supabase-js";
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);
export const admin = "$H.$PL.$SIG";
EOF
cat > firestore.rules <<'EOF'
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2026, 12, 1);
    }
    match /public/{id} {
      allow read;
    }
  }
}
EOF
commit baas
echo "baas.py — Supabase / Firebase"
OUT=$(python3 "$SCRIPTS/baas.py" "$WORK/baas" 2>&1)
has   "table without RLS is critical when client uses Supabase" "CRITICAL.*table profiles has no 'enable row level security'"
hasnt "table with RLS not flagged"              "table notes has no"
has   "open write policy critical"              "CRITICAL.*allows update for everyone"
has   "open read policy is a warning"           "warning.*lets everyone read every row of notes"
has   "service_role JWT detected"               "CRITICAL.*service_role key"
has   "firebase test mode"                      "CRITICAL.*test-mode rules"
has   "firebase allow read without condition"   "warning.*'allow read' with no condition"
hasnt "never prints the key"                    "$PL"

# Wait (up to 20s; macOS runners start Python slowly) until a fake server has written its port.
wait_port(){ local i; for i in $(seq 1 100); do [ -s "$1" ] && return 0; sleep 0.2; done; echo "  fake server did not start ($1)"; return 1; }

# ---------------------------------------------------------------- deps (fake OSV)
newrepo deps
cat > package-lock.json <<'EOF'
{ "lockfileVersion": 3, "packages": { "": {"name": "x"}, "node_modules/lodash": {"version": "4.17.15"}, "node_modules/left-pad": {"version": "1.3.0"} } }
EOF
printf "django==3.2.0\nrequests>=2\n" > requirements.txt
commit deps
cat > "$WORK/fake_osv.py" <<'EOF'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, obj):
        b = json.dumps(obj).encode(); self.send_response(200); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        q = json.loads(self.rfile.read(int(self.headers["content-length"])))["queries"]
        bad = {("lodash", "4.17.15"): "GHSA-test-crit", ("django", "3.2.0"): "GHSA-test-high"}
        self._send({"results": [{"vulns": [{"id": bad[(x["package"]["name"], x["version"])]}]} if (x["package"]["name"], x["version"]) in bad else {} for x in q]})
    def do_GET(self):
        vid = self.path.rsplit("/", 1)[-1]
        sev = {"GHSA-test-crit": "CRITICAL", "GHSA-test-high": "HIGH"}.get(vid, "LOW")
        self._send({"id": vid, "summary": f"test advisory {vid}", "database_specific": {"severity": sev}})
import socketserver
class Srv(HTTPServer):
    def server_bind(self):  # skip HTTPServer's getfqdn(): a reverse-DNS lookup that hangs ~30s on macOS runners
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]
srv = Srv(("127.0.0.1", 0), H); print(srv.server_port, flush=True); srv.serve_forever()
EOF
python3 "$WORK/fake_osv.py" > "$WORK/osv.port" & OSV_PID=$!
wait_port "$WORK/osv.port"
echo "deps.py — OSV lookup (fake server)"
OUT=$(PRS_OSV_URL="http://127.0.0.1:$(cat "$WORK/osv.port")" python3 "$SCRIPTS/deps.py" "$WORK/deps" 2>&1)
has   "counts pinned deps (npm + pip ==)"       "Dependencies checked: 3 \\| vulnerable packages: 2"
has   "critical npm vuln listed"                "CRITICAL +npm:lodash@4.17.15 +GHSA-test-crit"
has   "high PyPI vuln listed"                   "HIGH +PyPI:django@3.2.0"
hasnt "unpinned requirement ignored"            "requests@"
OUT=$(PRS_OSV_URL="http://127.0.0.1:9" python3 "$SCRIPTS/deps.py" "$WORK/deps" 2>&1)
has   "offline handled gracefully"              "Could not reach the OSV API"
kill $OSV_PID 2>/dev/null

# ---------------------------------------------------------------- probe (fake app)
cat > "$WORK/fake_app.py" <<'EOF'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
SECURE = sys.argv[1] == "secure"
hits = {"n": 0}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body=b"", extra=None):
        self.send_response(code)
        if SECURE:
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
        else:
            self.send_header("X-Powered-By", "Express")
            o = self.headers.get("Origin")
            if o:
                self.send_header("Access-Control-Allow-Origin", o); self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.send_header("content-length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == "/.env":
            return self.send(404) if SECURE else self.send(200, b"DB_PASSWORD=hunter2\n")
        if self.path == "/api/me":
            return self.send(401) if SECURE else self.send(200, b'{"id":1}')
        if self.path.startswith("/__prs"):
            return self.send(404, b"Not found" if SECURE else b'Error\n    at Router.handle (/app/node_modules/express/router.js:12:3)')
        return self.send(200, b"<html>ok</html>")
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length") or 0))
        hits["n"] += 1
        if SECURE and hits["n"] > 5:
            return self.send(429, b"slow down")
        return self.send(401, b'{"error":"bad credentials"}')
import socketserver
class Srv(HTTPServer):
    def server_bind(self):  # skip HTTPServer's getfqdn(): a reverse-DNS lookup that hangs ~30s on macOS runners
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]
srv = Srv(("127.0.0.1", 0), H); print(srv.server_port, flush=True); srv.serve_forever()
EOF
start_app(){ python3 "$WORK/fake_app.py" "$1" > "$WORK/$1.port" & echo $! > "$WORK/$1.pid"; wait_port "$WORK/$1.port"; }
start_app insecure; start_app secure
echo "probe.sh — insecure app"
OUT=$(bash "$SCRIPTS/probe.sh" "http://127.0.0.1:$(cat "$WORK/insecure.port")" --protected /api/me --login /api/login --login-attempts 8 2>&1)
has   "missing CSP"                             "No Content-Security-Policy"
has   "CORS reflect with credentials"           "CRITICAL +Reflects any Origin WITH credentials"
has   "exposed .env"                            "CRITICAL +/.env is publicly downloadable"
has   "stack trace leak"                        "404 page shows a stack trace"
has   "protected route open"                    "CRITICAL +/api/me returned 200"
has   "no rate limit"                           "No 429 after 8 bad attempts"
hasnt "never prints .env content"               "hunter2"
echo "probe.sh — secure app"
OUT=$(bash "$SCRIPTS/probe.sh" "http://127.0.0.1:$(cat "$WORK/secure.port")" --protected /api/me --login /api/login --login-attempts 8 2>&1)
hasnt "no criticals on secure app"              "CRITICAL"
has   "sees 401"                                "/api/me → 401"
has   "sees 429"                                "429 after [0-9]+ attempts"
kill "$(cat "$WORK/insecure.pid")" "$(cat "$WORK/secure.pid")" 2>/dev/null

# ---------------------------------------------------------------- report.py
echo "report.py — formats, fail-on, ignore, history"
REP="$SCRIPTS/report.py"
OUT=$(python3 "$REP" "$WORK/vuln-express" --format json 2>&1)
has   "json has counts"                         "\"critical\": [1-9]"
has   "json has unguarded route finding"        "\"rule\": \"unguarded-write-route\""
OUT=$(python3 "$REP" "$WORK/vuln-express" --format sarif 2>&1)
has   "sarif 2.1.0"                             "\"version\": \"2.1.0\""
has   "sarif location with line"                "\"startLine\": 7"
python3 "$REP" "$WORK/vuln-express" --fail-on critical >/dev/null 2>&1; rc=$?
if [ "$rc" = 1 ]; then ok "fail-on critical exits 1"; else bad "fail-on critical exits 1 (got $rc)"; fi
python3 "$REP" "$WORK/clean-express" --fail-on critical >/dev/null 2>&1; rc=$?
if [ "$rc" = 0 ]; then ok "clean app passes fail-on critical"; else bad "clean app passes fail-on critical (got $rc)"; fi
printf "unguarded-write-route\nunsigned-webhook\nsecret-in-history\n" > "$WORK/vuln-express/.production-readiness-ignore"
OUT=$(python3 "$REP" "$WORK/vuln-express" --format json 2>&1)
has   "ignore file applied"                     "\"ignored\": [1-9]"
hasnt "ignored rule gone"                       "\"rule\": \"unguarded-write-route\""
rm "$WORK/vuln-express/.production-readiness-ignore"
python3 "$REP" "$WORK/vuln-express" --save-history >/dev/null 2>&1
OUT=$(python3 "$REP" "$WORK/vuln-express" --save-history 2>&1)
has   "history shows delta"                     "Since last scan"
python3 "$REP" "$WORK/vuln-express" --format html -o "$WORK/r.html" >/dev/null 2>&1
OUT=$(cat "$WORK/r.html")
has   "html report renders findings"            "unguarded-write-route"
has   "html has trend chart"                    "class=\"bars\""
python3 "$REP" "$WORK/vuln-express" --format markdown -o "$WORK/s.md" --write "json:$WORK/a.json" --write "sarif:$WORK/a.sarif" >/dev/null 2>&1
if [ -s "$WORK/s.md" ] && [ -s "$WORK/a.json" ] && [ -s "$WORK/a.sarif" ]; then ok "--write produces several formats from one scan"; else bad "--write produces several formats"; fi

echo "install.sh"
FAKEHOME="$WORK/home"; mkdir -p "$FAKEHOME"
OUT=$(HOME="$FAKEHOME" bash "$REPO/install.sh" 2>&1)
if [ -f "$FAKEHOME/.claude/skills/production-readiness/SKILL.md" ] && [ -x "$FAKEHOME/.claude/skills/production-readiness/scripts/scan.sh" ]; then ok "user install"; else bad "user install"; fi
OUT=$(HOME="$FAKEHOME" bash "$REPO/install.sh" --project "$WORK/static-site" 2>&1)
if [ -f "$WORK/static-site/.claude/skills/production-readiness/SKILL.md" ]; then ok "project install"; else bad "project install"; fi
OUT=$(HOME="$FAKEHOME" bash "$REPO/install.sh" --uninstall 2>&1)
if [ ! -d "$FAKEHOME/.claude/skills/production-readiness" ]; then ok "uninstall"; else bad "uninstall"; fi

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
