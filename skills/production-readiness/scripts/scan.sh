#!/usr/bin/env bash
# Quick signal scan for production-readiness areas.
# Signals only — a hit means "go read this file", not "this is handled".
# Usage: scan.sh [--deep] [repo-path]
#   --deep  also run installed scanners (gitleaks, semgrep, npm audit, pip-audit, hadolint)
set -uo pipefail
DEEP=0; [ "${1:-}" = "--deep" ] && { DEEP=1; shift; }
ROOT="${1:-.}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

echo "== Production readiness signal scan: $(pwd) =="
echo "Profile: type=$TYPE | own server=$server | database=$db | user accounts=$users | LLM=$ai | mobile app=$mobile"
echo "Deploy target: ${deploy:-unknown (ask the user)}"
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
SECRET_RE='AIza[0-9A-Za-z_-]{35}|sk-(proj-|ant-)?[A-Za-z0-9_-]{20,}|sk_live_[0-9A-Za-z]{20,}|rk_live_|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|gh[ousr]_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|-----BEGIN ([A-Z]+ )?PRIVATE KEY|(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqps?)://[^:/@[:space:]"'"'"'$]+:[^@[:space:]"'"'"'$]{3,}@|eyJhbGciOi[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}'
HARD_RE='(SECRET_KEY|JWT_SECRET|secret_key|jwt_secret|API_KEY|api_key|apiKey|PASSWORD|password|AUTH_TOKEN|auth_token)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'$[:space:]{}<]{12,}["'"'"']'
NOEX=$(mktemp); grep -vE '(example|sample|template)[^/]*$|(^|/)(docs?|fixtures?)/' "$CODE" > "$NOEX"
leaks=$(tr '\n' '\0' < "$NOEX" | xargs -0 grep -nIoE "$SECRET_RE" 2>/dev/null | cut -d: -f1,2 | sort -u)
hard=$(tr '\n' '\0' < "$NOEX" | xargs -0 grep -nIE "$HARD_RE" 2>/dev/null | grep -viE 'example|placeholder|your[_-]|xxx|<|test|mock|fake|dummy|autoComplete|aria-label|type=|label' | cut -d: -f1,2 | sort -u)
fallback=$(tr '\n' '\0' < "$CODE" | xargs -0 grep -nIE "(SECRET|secret_key|jwtSecret|JWT_SECRET).{0,40}(\|\||\bor\b|getenv\([^,]+,|: *str *=) *[\"'][^\"']{6,}[\"']" 2>/dev/null | cut -d: -f1,2 | sort -u)
printf "%-24s %s\n" "Known key/URI patterns" "$(printf "%s" "$leaks" | grep -c . || true) hit(s) $(printf "%s" "$leaks" | head -5 | tr '\n' ' ')"
printf "%-24s %s\n" "Hardcoded secret assigns" "$(printf "%s" "$hard" | grep -c . || true) hit(s) $(printf "%s" "$hard" | head -5 | tr '\n' ' ')"
printf "%-24s %s\n" "Default-secret fallbacks" "$(printf "%s" "$fallback" | grep -c . || true) hit(s) $(printf "%s" "$fallback" | head -5 | tr '\n' ' ') <- must fail-fast in production"
pub=$(g '(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Z_]*(SECRET|PRIVATE|SERVICE_ROLE|_TOKEN)' | tr '\n' ' ')
printf "%-24s %s\n" "Secrets in public env" "${pub:-none}"
art=$(grep -E '(^|/)(__pycache__/|\.DS_Store$|node_modules/)|\.(pyc|db|sqlite3?|log)$' "$LIST" | wc -l | tr -d ' ')
printf "%-24s %s\n" "Committed artifacts" "$art file(s)$( [ "$art" -gt 0 ] && echo ' (pyc/db/log/node_modules — may hold user data; gitignore them)')"

echo
echo "== Risky patterns (file:line — open each one) =="
RISKF=$(mktemp); grep -vE '(^|/)(tests?|__tests__|e2e|spec|fixtures?|mocks?)/|\.(test|spec)\.[a-z]+$|(^|/)test_[^/]+\.py$' "$NOEX" > "$RISKF"
risk(){ local name="$1" re="$2" hits
  hits=$(tr '\n' '\0' < "$RISKF" | xargs -0 grep -nIE "$re" 2>/dev/null | grep -vE '^\S+:[0-9]+:\s*(//|#|\*)|__html: *JSON\.stringify' | cut -d: -f1,2 | sort -u)
  [ -n "$hits" ] && printf "%-28s %s\n" "$name" "$(printf "%s" "$hits" | head -5 | tr '\n' ' ')$( [ "$(printf "%s\n" "$hits" | wc -l)" -gt 5 ] && echo '…')"; }
risk "CORS allow-all"            'allow_origins *= *\[ *["'"'"']\*|origin: *(["'"'"']\*|true)|cors\(\)|Access-Control-Allow-Origin["'"'"']?\s*[:,]\s*["'"'"']\*'
risk "Debug on"                  '(^|[^a-z_])(DEBUG|debug)( *: *bool)? *[:=] *(True|true|1)\b|app\.run\([^)]*debug *= *True'
risk "SQL built from strings"    '(execute|query|raw|\$queryRawUnsafe)\( *(f["'"'"']|["'"'"'][^"'"'"']*(SELECT|INSERT|UPDATE|DELETE)[^"'"'"']*["'"'"'] *(\+|%|\.format))|`(SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{'
risk "eval/exec/shell"           '(^|[^.[:alnum:]_])(eval|exec)\(|shell *= *True|child_process.*exec\(|os\.system\('
risk "Unsafe HTML sink"          'dangerouslySetInnerHTML|\.innerHTML *= *[^"'"'"'`;]*(response|data|res\.|json|text|msg|message|feedback)|v-html|\|safe\b|mark_safe\('
risk "Weak randomness for tokens" 'Math\.random\(\).*(otp|code|token|secret|id|pass)|(otp|code|token|secret|pass).*Math\.random\(|random\.(choice|choices|randint)\(.*(token|otp|code|id)'
risk "TLS verification off"      'verify *= *False|rejectUnauthorized: *false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureSkipVerify'
risk "JWT not verified"          'jwt\.decode\([^)]*verify_signature["'"'"']? *: *False|algorithms *= *\[ *["'"'"']none|jwt\.decode\(token\)'
risk "Secrets in logs"           '(console\.(log|info)|print|logger\.\w+)\([^)]*(token|secret|password|authToken|AUTH_TOKEN|api_?key)'
risk "Token in URL"              '[?&](t|token|access_token|jwt|auth)=\$\{|[?&](t|token|access_token|jwt)=["'"'"']? *\+ *(token|getToken|auth)|searchParams\.(set|append)\(["'"'"'](t|token|access_token)["'"'"']'
risk "Unsafe deserialization"    'pickle\.loads?\(|yaml\.load\([^)]*\)$|marshal\.loads'
echo "(no line above = no hits)"

if [ "$server" = yes ] && command -v python3 >/dev/null; then
  echo; echo "== Routes & auth guards =="
  python3 "$HERE/routes.py" "$(pwd)"
fi

echo; echo "== Git history (secrets deleted from code are still leaked) =="
if [ "$IS_GIT" = 1 ]; then
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
    echo "Shallow clone ($(git rev-list --count HEAD) commit(s)) — history NOT checked. Run: git fetch --unshallow, then re-scan."
  else
    hist=$(git log --all -p --no-color -G "$SECRET_RE" 2>/dev/null | grep -E '^-[^-]' | grep -cE "$SECRET_RE" || true)
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
