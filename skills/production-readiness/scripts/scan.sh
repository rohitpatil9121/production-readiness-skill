#!/usr/bin/env bash
# Quick signal scan for production-readiness areas.
# Signals only — a hit means "go read this file", not "this is handled".
# Usage: scan.sh [--deep] [--deps] [repo-path]
#   --deps  check pinned dependencies against the OSV vulnerability database (sends package names+versions to osv.dev)
#   --deep  --deps, plus run installed scanners (gitleaks, semgrep, npm audit, pip-audit, hadolint)
# Set PRS_FINDINGS=<file> to also get machine-readable findings (used by report.py).
set -uo pipefail
DEEP=0; DEPS=0
while [ $# -gt 0 ]; do case "$1" in --deep) DEEP=1; DEPS=1; shift ;; --deps) DEPS=1; shift ;; *) break ;; esac; done
ROOT="${1:-.}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# emit <critical|warning|info> <rule-id> <file:line> <message>
emit(){ [ -n "${PRS_FINDINGS:-}" ] && printf "%s\t%s\t%s\t%s\n" "$1" "$2" "$3" "$4" >> "$PRS_FINDINGS"; return 0; }
cd "$ROOT" || { echo "Cannot cd into $ROOT"; exit 1; }

# ---- file list: tracked files if git, else find; skip vendored/binary/generated ----
LIST=$(mktemp); trap 'rm -f "$LIST"' EXIT
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git ls-files > "$LIST"; IS_GIT=1
else
  find . -type f -not -path '*/.git/*' | sed 's#^\./##' > "$LIST"; IS_GIT=0
fi
CODE=$(mktemp); trap 'rm -f "$LIST" "$CODE"' EXIT
grep -vE '(^|/)(node_modules|dist|build|\.next|venv|\.venv|__pycache__|vendor|target|coverage|android|ios)/|\.(min\.js|map|lock|png|jpe?g|gif|svg|ico|webp|mp3|mp4|wav|woff2?|ttf|pdf|pkl|db|sqlite|zip)$|package-lock\.json|pnpm-lock|yarn\.lock' "$LIST" > "$CODE"

g()  { tr '\n' '\0' < "$CODE" | xargs -0 grep -lIE "$1" 2>/dev/null; }          # files matching
gc() { g "$1" | wc -l | tr -d ' '; }
has(){ grep -qE "$1" "$LIST"; }

# ---- app profile (decides which areas apply) ----
deps_files=$(grep -E '(^|/)(package\.json|requirements[^/]*\.txt|pyproject\.toml|go\.mod|pom\.xml|build\.gradle|Gemfile|composer\.json)$' "$LIST" | grep -v node_modules)
dep_hit(){ [ -n "$deps_files" ] && echo "$deps_files" | tr '\n' '\0' | xargs -0 grep -qiE "$1" 2>/dev/null; }

server=no
dep_hit '"(express|fastify|koa|hono|@nestjs/core|next)"|fastapi|django|flask|gin-gonic|spring-boot|rails|laravel' && server=yes
has '(^|/)(lambda_function\.py|serverless\.ya?ml|template\.ya?ml)$|(^|/)lambda/' && server=yes
[ "$server" = no ] && [ "$(gc 'http\.createServer\(|new WebSocketServer|app\.listen\(|uvicorn\.run|serve_forever')" -gt 0 ] && server=yes
db=no; dep_hit 'prisma|mongoose|mongodb|sequelize|typeorm|drizzle|knex|"pg"|sqlalchemy|psycopg|django|supabase|firebase|dynamodb|boto3' && db=yes
ai=no; dep_hit 'openai|anthropic|groq|langchain|llamaindex|google-generativeai|@google/genai|ollama|transformers' && ai=yes
users=no; [ "$(gc 'login|signin|sign_in|signup|password|auth\.|requireAuth|get_current_user|useAuth')" -gt 0 ] && users=yes

mobile=no; has '(^|/)(capacitor\.config\.(json|ts)|AndroidManifest\.xml|app\.json|pubspec\.yaml)$|(^|/)ios/.*\.xcodeproj' && mobile=yes
ext=no; has '(^|/)manifest(\.config\.[jt]s|\.json)$' && [ "$(gc 'chrome\.(runtime|storage|tabs|action)|manifest_version')" -gt 0 ] && ext=yes
if [ "$ext" = yes ] && [ "$server" = yes ]; then TYPE="browser extension + backend"
elif [ "$ext" = yes ]; then TYPE="browser extension"
elif [ "$server" = yes ]; then TYPE="backend/full-stack"
elif has '\.ipynb$'; then TYPE="notebook/ML"
elif dep_hit '"(react|vue|svelte|vite|phaser|three)"'; then TYPE="frontend SPA (no own backend)"
elif has '\.html$'; then TYPE="static site"
else TYPE="other/library"; fi

deploy=""
has '(^|/)vercel\.json$|(^|/)\.vercel/' && deploy+="vercel(serverless) "
has '(^|/)netlify\.toml$' && deploy+="netlify(serverless) "
has '(^|/)(serverless\.ya?ml|template\.ya?ml|samconfig\.toml)$|(^|/)lambda_function\.py$|(^|/)lambda/' && deploy+="aws-lambda(serverless) "
has '(^|/)render\.yaml$' && deploy+="render "
has '(^|/)fly\.toml$' && deploy+="fly "
has '(^|/)(railway\.json|Procfile)$' && deploy+="railway/heroku "
has '(^|/)(app\.yaml|cloudbuild[^/]*\.ya?ml)$' && deploy+="gcp "
has '(^|/)Dockerfile[^/]*$' && deploy+="docker "
[ -n "$(g 'kind: *Deployment')" ] && deploy+="kubernetes "
has '^\.github/workflows/.*pages' && deploy+="github-pages "

visibility=unknown
remote=$(git remote get-url origin 2>/dev/null || true)
if [ -n "$remote" ] && printf "%s" "$remote" | grep -q "github.com" && command -v gh >/dev/null; then
  slug=$(printf "%s" "$remote" | sed -E 's#(\.git)?$##; s#.*github\.com[:/]##')
  visibility=$(GH_PROMPT_DISABLED=1 gh repo view "$slug" --json visibility -q .visibility 2>/dev/null | tr 'A-Z' 'a-z')
  [ -n "$visibility" ] || visibility=unknown
fi

echo "== Production readiness signal scan: $(pwd) =="
echo "Profile: type=$TYPE | own server=$server | database=$db | user accounts=$users | LLM=$ai | mobile app=$mobile"
echo "Deploy target: ${deploy:-unknown (ask the user)} | Repo visibility: $visibility$( [ "$visibility" = public ] && echo ' (any committed secret is already leaked)')"
case "$deploy" in *serverless*) echo "  -> Serverless: in-memory rate limits/caches/counters are per-instance and reset; local disk is ephemeral; no long-running workers. Keep state in DB/Redis, files in object storage, jobs in a queue service.";; esac
[ "$server" = no ] && echo "  -> No own backend detected: most server-side areas (rate limiting, queues, DB indexing, LB, K8s) are likely N/A. Focus on secrets, client-side keys, CI, tests."
echo

# ---- area signals (word-boundary-ish patterns to cut false positives) ----
declare -a AREAS=(
  "Authentication|\\b(bcrypt|bcryptjs|argon2|passlib|jsonwebtoken|pyjwt|next-auth|@clerk|auth0|passport)\\b|jwt\\.(sign|verify|encode|decode)|supabase\\.auth|firebase/auth|verifyIdToken|django\\.contrib\\.auth"
  "Authorization|\\b(requireRole|require_role|require_admin|isAdmin|authorize|hasPermission|has_perm|@PreAuthorize|casl|casbin)\\b|row level security|owner_?id|user_?id ?== ?"
  "Rate limiting|rate-?limit|ratelimit|\\bthrottl|slowapi|express-rate-limit|@nestjs/throttler|upstash/ratelimit"
  "API resilience|(timeout|signal) *[:=]|AbortSignal\\.timeout|axios-retry|p-retry|tenacity|backoff|circuit.?breaker|idempotenc"
  "Input validation|\\b(zod|joi|yup|pydantic|class-validator|marshmallow|express-validator|valibot)\\b|BaseModel\\)|z\\.object\\("
  "Caching|Cache-Control|\\blru-cache\\b|functools\\.(lru_)?cache|stale-while-revalidate|\\bmemoize"
  "Redis|\\b(redis|ioredis|upstash)\\b"
  "DB indexes/migrations|@@index|CREATE (UNIQUE )?INDEX|db_index|@Index|index=True|alembic|prisma migrate|knex migrate|makemigrations"
  "Health checks|/healthz?\\b|/readyz|livenessProbe|readinessProbe|SIGTERM"
  "Security headers/CORS|\\bhelmet\\b|CORSMiddleware|\\bcors\\(|Content-Security-Policy|Access-Control-Allow-Origin"
  "Queues/background jobs|\\b(bullmq|celery|sidekiq|rabbitmq|amqplib|kafkajs|inngest|apscheduler|node-cron|BackgroundTasks)\\b|from rq |SQS|@temporalio"
  "WebSockets/realtime|socket\\.io|new WebSocket|\\bws\\b.*require|WebSocketServer|EventSource|supabase.*channel\\("
  "Structured logging|\\b(winston|pino|bunyan|structlog|loguru)\\b|logging\\.getLogger"
  "Error tracking/metrics|@sentry|sentry_sdk|datadog|prom-client|prometheus|opentelemetry|newrelic"
  "LLM usage|\\b(openai|anthropic|groq|langchain|llamaindex|generativeai)\\b|chat\\.completions|messages\\.create"
  "MCP server|modelcontextprotocol|FastMCP|McpServer"
  "RAG/vector DB|\\b(pinecone|weaviate|qdrant|chromadb|milvus|pgvector)\\b|embeddings?\\.create|cosine_?similarity|\\bhnsw\\b"
  "Fine-tuning|fine.?tun|\\bpeft\\b|\\blora\\b|wandb|mlflow"
  "Load testing|\\bk6\\b|locust|artillery"
)
printf "%-24s %6s  %s\n" "AREA" "FILES" "EXAMPLES"
zero=""
for entry in "${AREAS[@]}"; do
  name="${entry%%|*}"; pattern="${entry#*|}"
  hits=$(g "$pattern"); c=$(printf "%s" "$hits" | grep -c . || true)
  if [ "$c" -gt 0 ]; then printf "%-24s %6s  %s\n" "$name" "$c" "$(printf "%s" "$hits" | head -3 | tr '\n' ' ')"; else zero+="$name, "; fi
done
[ -n "$zero" ] && echo "No signals for: ${zero%, }"

echo
echo "== Infra =="
printf "%-24s %s\n" "Dockerfile"      "$(grep -cE '(^|/)Dockerfile[^/]*$' "$LIST")"
printf "%-24s %s\n" ".dockerignore"   "$(grep -cE '(^|/)\.dockerignore$' "$LIST")"
printf "%-24s %s\n" "docker-compose"  "$(grep -cE '(^|/)(docker-)?compose[^/]*\.ya?ml$' "$LIST")"
printf "%-24s %s\n" "K8s manifests"   "$(g 'kind: *(Deployment|StatefulSet|Ingress|HorizontalPodAutoscaler)' | wc -l | tr -d ' ')"
ci="none"
has '^\.github/workflows/' && ci="GitHub Actions ($(grep -c '^\.github/workflows/' "$LIST"))"
has '^\.gitlab-ci\.yml$' && ci="GitLab CI"; has '^Jenkinsfile$' && ci="Jenkins"; has '^\.circleci/' && ci="CircleCI"
has '(^|/)cloudbuild[^/]*\.ya?ml$' && ci="$ci + Cloud Build"
printf "%-24s %s\n" "CI/CD"           "$ci"
printf "%-24s %s\n" "Deploy config"   "$(grep -E '(^|/)(render\.yaml|vercel\.json|netlify\.toml|fly\.toml|Procfile|app\.yaml|serverless\.ya?ml)$' "$LIST" | tr '\n' ' ')"
printf "%-24s %s\n" "Dependabot/Renovate" "$(has '^\.github/dependabot\.ya?ml$|(^|/)renovate\.json$' && echo yes || echo no)"
printf "%-24s %s\n" "Test files" "$(grep -cE '(\.|_)(test|spec)\.[a-z]+$|(^|/)test_[^/]+\.py$|_test\.(py|go)$' "$LIST")"

echo
echo "== Secrets & repo hygiene (values never printed) =="
env_used=$(gc 'process\.env|os\.environ|os\.getenv|import\.meta\.env|dotenv')
committed_env=$(grep -E '(^|/)\.env(\.[a-z]+)?$' "$LIST" | grep -vE 'example|sample|template' | tr '\n' ' ')
printf "%-24s %s\n" "Env vars used in code" "$env_used file(s)"
printf "%-24s %s\n" "Committed .env files" "${committed_env:-none}$( [ -n "$committed_env" ] && echo ' <- CHECK: only public values allowed (e.g. VITE_* URLs)')"
if [ "$env_used" -gt 0 ] && [ "$IS_GIT" = 1 ]; then
  if git check-ignore -q .env 2>/dev/null; then ig=yes; else ig="NO <- add .env to .gitignore"; fi
  printf "%-24s %s\n" ".env ignored by git" "$ig"
  printf "%-24s %s\n" ".env.example" "$(grep -qE '(^|/)\.env[^/]*(example|sample|template)' "$LIST" && echo yes || echo 'no <- document required env vars')"
fi
SECRET_RE='AIza[0-9A-Za-z_-]{35}|sk-(proj-|ant-)?[A-Za-z0-9_-]{20,}|sk_live_[0-9A-Za-z]{20,}|rk_live_[0-9A-Za-z]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|gh[ousr]_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|-----BEGIN ([A-Z]+ )?PRIVATE KEY|(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqps?)://[^:/@[:space:]"'"'"'$]+:[^@[:space:]"'"'"'$]{3,}@|eyJhbGciOi[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}'
HARD_RE='(SECRET_KEY|JWT_SECRET|secret_key|jwt_secret|API_KEY|api_key|apiKey|PASSWORD|password|AUTH_TOKEN|auth_token)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'$[:space:]{}<]{12,}["'"'"']'
NOEX=$(mktemp); grep -vE '(example|sample|template)[^/]*$|(^|/)(docs?|fixtures?)/' "$CODE" > "$NOEX"
leaks=$(tr '\n' '\0' < "$NOEX" | xargs -0 grep -nIoE "$SECRET_RE" 2>/dev/null | cut -d: -f1,2 | sort -u)
hard=$(tr '\n' '\0' < "$NOEX" | xargs -0 grep -nIE "$HARD_RE" 2>/dev/null | grep -viE 'example|placeholder|your[_-]|xxx|<|test|mock|fake|dummy|autoComplete|aria-label|type=|label' | grep -vE "[\"'](public_|pk_(live|test)_)" | cut -d: -f1,2 | sort -u)
fallback=$(tr '\n' '\0' < "$CODE" | xargs -0 grep -nIE "(SECRET|secret_key|jwtSecret|JWT_SECRET).{0,40}(\|\||\bor\b|getenv\([^,]+,|: *str *=) *[\"'][^\"']{6,}[\"']" 2>/dev/null | cut -d: -f1,2 | sort -u)
printf "%-24s %s\n" "Known key/URI patterns" "$(printf "%s" "$leaks" | grep -c . || true) hit(s) $(printf "%s" "$leaks" | head -5 | tr '\n' ' ')"
printf "%-24s %s\n" "Hardcoded secret assigns" "$(printf "%s" "$hard" | grep -c . || true) hit(s) $(printf "%s" "$hard" | head -5 | tr '\n' ' ')"
printf "%-24s %s\n" "Default-secret fallbacks" "$(printf "%s" "$fallback" | grep -c . || true) hit(s) $(printf "%s" "$fallback" | head -5 | tr '\n' ' ') <- must fail-fast in production"
for l in $leaks; do emit critical secret-in-code "$l" "known secret/credential format (value not shown) — rotate it"; done
for l in $hard; do emit critical secret-hardcoded "$l" "hardcoded secret assignment — move to env and rotate"; done
for l in $fallback; do emit warning secret-default-fallback "$l" "secret falls back to a default — must fail fast in production"; done
pub=$(g '(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Z_]*(SECRET|PRIVATE|SERVICE_ROLE|_TOKEN)' | tr '\n' ' ')
for f in $pub; do emit critical secret-public-env "$f" "secret-looking variable with a public (browser-bundled) prefix"; done
for f in $committed_env; do emit warning committed-env-file "$f" "committed .env file — only public values allowed"; done
[ "${ig:-yes}" != yes ] && emit warning env-not-ignored ".gitignore" ".env is not ignored by git"
printf "%-24s %s\n" "Secrets in public env" "${pub:-none}"
art=$(grep -E '(^|/)(__pycache__/|\.DS_Store$|node_modules/)|\.(pyc|db|sqlite3?|log)$' "$LIST" | wc -l | tr -d ' ')
[ "$art" -gt 0 ] && emit info committed-artifacts "$(grep -E '(^|/)(__pycache__/|\.DS_Store$|node_modules/)|\.(pyc|db|sqlite3?|log)$' "$LIST" | head -1)" "$art build/db/log artifact file(s) committed"
printf "%-24s %s\n" "Committed artifacts" "$art file(s)$( [ "$art" -gt 0 ] && echo ' (pyc/db/log/node_modules — may hold user data; gitignore them)')"

echo
echo "== Risky patterns (file:line — open each one) =="
RISKF=$(mktemp); grep -vE '(^|/)(tests?|__tests__|e2e|spec|fixtures?|mocks?)/|\.(test|spec)\.[a-z]+$|(^|/)test_[^/]+\.py$|\.(md|mdx|txt|rst|adoc)$' "$NOEX" > "$RISKF"
risk(){ local name="$1" re="$2" sev="$3" rule="$4" hits h
  hits=$(tr '\n' '\0' < "$RISKF" | xargs -0 grep -nIE "$re" 2>/dev/null | grep -vE '^\S+:[0-9]+:\s*(//|#|\*)|__html: *JSON\.stringify' | cut -d: -f1,2 | sort -u)
  [ -n "$hits" ] || return 0
  printf "%-28s %s\n" "$name" "$(printf "%s" "$hits" | head -5 | tr '\n' ' ')$( [ "$(printf "%s\n" "$hits" | wc -l)" -gt 5 ] && echo '…')"
  for h in $hits; do emit "$sev" "$rule" "$h" "$name"; done; }
risk "CORS allow-all" 'allow_origins *= *\[ *["'"'"']\*|origin: *(["'"'"']\*|true)|cors\(\)|Access-Control-Allow-Origin["'"'"']?\s*[:,]\s*["'"'"']\*' warning cors-allow-all
risk "Debug on" '(^|[^a-z_])(DEBUG|debug)( *: *bool)? *[:=] *(True|true|1)\b|app\.run\([^)]*debug *= *True' warning debug-enabled
risk "SQL built from strings" '(execute|query|raw|\$queryRawUnsafe)\( *(f["'"'"']|["'"'"'][^"'"'"']*(SELECT|INSERT|UPDATE|DELETE)[^"'"'"']*["'"'"'] *(\+|%|\.format))|`(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{' critical sql-string-building
risk "eval/exec/shell" '(^|[^.[:alnum:]_])(eval|exec)\(|shell *= *True|child_process.*exec\(|os\.system\(' warning dynamic-code-exec
risk "Unsafe HTML sink" 'dangerouslySetInnerHTML|\.innerHTML *= *[^"'"'"'`;]*(response|data|res\.|json|text|msg|message|feedback)|v-html|\|safe\b|mark_safe\(' warning unsafe-html-sink
risk "Weak randomness for tokens" 'Math\.random\(\).*(otp|code|token|secret|id|pass)|(otp|code|token|secret|pass).*Math\.random\(|random\.(choice|choices|randint)\(.*(token|otp|code|id)' warning weak-randomness
risk "TLS verification off" 'verify *= *False|rejectUnauthorized: *false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureSkipVerify' info tls-verification-off
risk "JWT not verified" 'jwt\.decode\([^)]*verify_signature["'"'"']? *: *False|algorithms *= *\[ *["'"'"']none|jwt\.decode\(token\)' critical jwt-not-verified
risk "Secrets in logs" '(console\.(log|info)|print|logger\.\w+)\([^)]*(token|secret|password|authToken|AUTH_TOKEN|api_?key)' warning secrets-in-logs
risk "Token in URL" '[?&](t|token|access_token|jwt|auth)=\$\{|[?&](t|token|access_token|jwt)=["'"'"']? *\+ *(token|getToken|auth)|searchParams\.(set|append)\(["'"'"'](t|token|access_token)["'"'"']' warning token-in-url
risk "Unsafe deserialization" 'pickle\.loads?\(|yaml\.load\([^)]*\)$|marshal\.loads' warning unsafe-deserialization
echo "(no line above = no hits)"

if [ "$server" = yes ] && command -v python3 >/dev/null; then
  echo; echo "== Routes & auth guards =="
  python3 "$HERE/routes.py" "$(pwd)"
fi

if command -v python3 >/dev/null; then
  baas_out=$(python3 "$HERE/baas.py" "$(pwd)")
  [ -n "$baas_out" ] && { echo; echo "== Supabase / Firebase rules =="; printf "%s\n" "$baas_out"; }
fi

if [ "$DEPS" = 1 ]; then
  echo; echo "== Dependencies (OSV database) =="
  if command -v python3 >/dev/null; then python3 "$HERE/deps.py" "$(pwd)"; else echo "python3 needed for the dependency check"; fi
fi

echo; echo "== Git history (secrets deleted from code are still leaked) =="
if [ "$IS_GIT" = 1 ]; then
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
    echo "Shallow clone ($(git rev-list --count HEAD) commit(s)) — history NOT checked. Run: git fetch --unshallow, then re-scan."
    emit info history-not-checked "git history" "shallow clone — secrets in history not checked"
  else
    hist=$(git log --all -p --no-color -G "$SECRET_RE" 2>/dev/null | grep -E '^-[^-]' | grep -cE "$SECRET_RE" || true)
    [ "${hist:-0}" -gt 0 ] && emit critical secret-in-history "git history" "$hist secret line(s) removed from code but still in git history — rotate them"
    echo "Secrets present in old commits but removed since: ${hist:-0} line(s)$( [ "${hist:-0}" -gt 0 ] && echo ' <- ROTATE them; inspect with: git log -p -G "<pattern>"')"
  fi
fi

if [ "$DEEP" = 1 ]; then
  echo; echo "== Deep scan (installed tools only) =="
  ran=0
  command -v gitleaks >/dev/null && { ran=1; echo "-- gitleaks"; gitleaks detect --no-banner --redact -s . 2>&1 | tail -3; }
  command -v semgrep  >/dev/null && { ran=1; echo "-- semgrep (p/default)"; semgrep scan --config p/default --quiet --metrics=off . 2>&1 | grep -E "Findings|findings|blocking" | head -3; }
  for pj in $(grep -E '(^|/)package-lock\.json$' "$LIST" | head -5); do
    command -v npm >/dev/null && { ran=1; echo "-- npm audit $(dirname "$pj")"; (cd "$(dirname "$pj")" && npm audit --omit=dev --audit-level=high 2>&1 | grep -E "vulnerabilit|found 0" | tail -1); }
  done
  command -v pip-audit >/dev/null && for rq in $(grep -E '(^|/)requirements[^/]*\.txt$' "$LIST" | head -3); do ran=1; echo "-- pip-audit $rq"; pip-audit -r "$rq" 2>&1 | tail -2; done
  command -v hadolint >/dev/null && for df in $(grep -E '(^|/)Dockerfile[^/]*$' "$LIST" | head -3); do ran=1; echo "-- hadolint $df"; hadolint "$df" 2>&1 | head -5; done
  [ "$ran" = 0 ] && echo "None of gitleaks/semgrep/npm/pip-audit/hadolint are installed — results above are regex-based only."
fi

echo
echo "Signals only. Open each hit and verify against references/checklist.md before scoring."
