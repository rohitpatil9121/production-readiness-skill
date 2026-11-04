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
