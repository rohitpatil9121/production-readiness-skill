# Production Readiness Checklist

Each area: **Check** (what good looks like), **Red flags**, **Grep hints**.
Grep hints are starting points — always read the code around a hit.

---

## 1. Authentication (who are you?)
**Check**
- Passwords hashed with bcrypt/argon2/scrypt (never MD5/SHA1/plain).
- Sessions or JWTs with expiry; refresh-token rotation; logout invalidates.
- JWT signature verified with a strong secret from env; algorithm pinned (no `none`).
- Cookies: `HttpOnly`, `Secure`, `SameSite`.
- Brute-force protection on login, account lockout / CAPTCHA.
- Password reset tokens: single-use, short-lived, random.
- OAuth/SSO uses `state` param; MFA available for sensitive apps.
- Prefer a proven provider/library (Auth.js, Clerk, Auth0, Passport, Django auth) over hand-rolled.

- **OTP login**: code from a CSPRNG (`crypto.randomInt` / `secrets`), short TTL, **max attempts per code** (e.g. 5, then invalidate), rate limit on both *request* (SMS/WhatsApp cost) and *verify*. A 6-digit OTP with no attempt cap is brute-forceable.
- **Secret fallbacks**: `process.env.JWT_SECRET || "dev-secret"` is fine only if startup **throws** when it's missing in production. A warning log is not enough.

**Red flags**: secret like `"secret"`/`"changeme"` in code, default-secret fallback without a production fail-fast, OTP verify without attempt counter or rate limit, `Math.random()` for OTPs/tokens, `jwt.decode` without verify, tokens in `localStorage` for high-risk apps, no expiry, passwords logged.

**Grep**: `bcrypt|argon2|jwt|jsonwebtoken|passport|session|next-auth|clerk|auth0|firebase.auth|supabase.auth|login|signin|password`

## 2. Authorization (what are you allowed to do?)
**Check**
- Every protected route has middleware/guard/decorator; default-deny.
- Object-level checks: user can only access *their* resources (prevents IDOR) — e.g. `WHERE id = ? AND owner_id = ?`.
- Roles/permissions (RBAC/ABAC) defined centrally, not scattered `if user.isAdmin`.
- Admin endpoints separated and protected; Row Level Security if using Supabase/Postgres.
- Authorization enforced server-side, never only in the frontend.

- **Control-plane/admin actions** (scaling, fault injection, settings, toggling guardrails, deleting data) must never be callable anonymously — even in "demo" apps that can point at real infrastructure.

**Red flags**: unauthenticated POST endpoints that change system state, `findById(req.params.id)` with no owner check, role read from request body/client, RLS disabled, admin route without guard.

**Grep**: `role|permission|isAdmin|authorize|guard|@PreAuthorize|policy|can\(|rbac|casl|row level security|enable_rls`

## 3. Rate limiting & abuse protection
**Check**
- Global limit + stricter limits on login, signup, OTP, password reset, expensive/AI endpoints.
- Store in Redis (not memory) when running >1 instance.
- Returns 429 with `Retry-After`; per-user and per-IP keys; trust proxy configured correctly.
- Request body size limits, timeouts, pagination caps.

**Red flags**: no limiter on LLM endpoints (cost bomb), in-memory limiter behind load balancer, unbounded `limit` query param.

**Grep**: `rate.?limit|ratelimit|throttle|slowapi|express-rate-limit|bottleneck|429|upstash/ratelimit`

## 4. API integration (calling 3rd-party services)
**Check**
- Timeouts on every outbound call; retries with exponential backoff + jitter, only for idempotent ops.
- Circuit breaker / graceful fallback when the provider is down.
- API keys in env/secret manager, never in frontend bundle or git.
- Webhooks: signature verified, idempotency key handled, replay-safe.
- Input/output validated (zod/pydantic/joi); errors mapped, not leaked raw.

- Webhook verification must **fail closed** in production: if the signing secret is unset, reject (or refuse to start), don't just log a warning and accept.

**Red flags**: webhook accepted unverified when secret missing, `fetch()`/`axios` without timeout, keys in `NEXT_PUBLIC_*`/`VITE_*`, webhook handler without signature check.

**Grep**: `axios|fetch\(|requests\.|httpx|timeout|retry|backoff|webhook|signature|idempotenc|stripe|openai|NEXT_PUBLIC_|VITE_`

## 5. State management
**Check**
- Frontend: clear split of server state (React Query/SWR/RTK Query) vs UI state (Zustand/Redux/context); no giant global store of server data.
- Backend is stateless (no user state in process memory) so it can scale horizontally; sessions in Redis/DB.
- Optimistic updates have rollback; loading/error states handled.

**Red flags**: module-level `let users = []` as storage, in-memory sessions with multiple replicas, prop-drilling chaos, duplicated server data in multiple stores.

**Grep**: `redux|zustand|recoil|jotai|react-query|tanstack|swr|createContext|MemoryStore|global `

## 6. Caching
**Check**
- Clear cache strategy: what's cached, TTL, invalidation on write.
- HTTP caching headers / CDN for static assets.
- Protection against stampede (locking, stale-while-revalidate).
- Never cache per-user/private data under shared keys.

**Red flags**: cache without TTL, no invalidation, caching authenticated responses publicly.

**Grep**: `cache|Cache-Control|ttl|memoize|lru|stale-while-revalidate|revalidate|cdn`

## 7. Redis
**Check**
- Connection via env URL, TLS + password in prod, connection pooling, reconnect handling.
- Keys namespaced and have TTL; eviction policy chosen.
- App degrades gracefully if Redis is down (or failure is intentional & documented).

**Red flags**: `KEYS *` in code, no TTL anywhere, Redis exposed without auth.

**Grep**: `redis|ioredis|upstash|setex|expire|KEYS \*`

## 8. Database & indexing
**Check**
- Indexes on columns used in `WHERE`, `JOIN`, `ORDER BY`, foreign keys; unique constraints for business rules.
- Migrations versioned (Prisma/Alembic/Flyway/Knex/Django), not manual edits.
- No N+1 queries (use joins/`include`/`select_related`); pagination everywhere.
- Parameterized queries only; connection pooling; transactions for multi-step writes.
- Backups + restore tested; soft-delete or audit trail where needed.

**Red flags**: string-concatenated SQL, `SELECT *` on huge tables without limit, no migrations folder, missing FK indexes, queries in loops.

**Grep**: `index|@@index|@Index|db_index|CREATE INDEX|migration|unique|\$queryRaw|execute\(f"|\+ *req\.|select_related|prefetch_related|include:|transaction`

## 9. Load balancing
**Check**
- App runs as multiple stateless instances behind LB/reverse proxy (Nginx, ALB, Cloud LB, Ingress).
- Health check endpoints (`/healthz` liveness, `/readyz` readiness) used by LB.
- Sticky sessions avoided (or justified for websockets); graceful shutdown drains connections (SIGTERM handling).

**Grep**: `nginx|upstream|healthz|health|readiness|liveness|SIGTERM|graceful|haproxy|ingress`

## 10. Microservices / service boundaries
**Check**
- If microservices: clear ownership, each service owns its DB, contracts versioned (OpenAPI/protobuf), service-to-service auth, timeouts & retries, distributed tracing.
- If monolith: that's fine — check it's a *modular* monolith with clear layers (routes → services → repositories).
- Don't recommend microservices for small teams/MVPs without reason.

**Red flags**: shared database between services, synchronous call chains 4+ deep, business logic in route handlers.

**Grep**: `grpc|proto|openapi|swagger|service|gateway|docker-compose`

## 11. System design
**Check**
- Architecture documented (diagram/README): components, data flow, single points of failure.
- Config via env (12-factor); environments separated (dev/staging/prod).
- Secrets not in repo (`.env` in `.gitignore`, `.env.example` present).
- Error handling strategy: centralized error middleware, consistent error format, no stack traces to clients.
- Input validation at boundaries; CORS configured narrowly; security headers (helmet/CSP).
- Idempotency for payments/critical writes; data consistency approach stated.

- CORS config that **falls back to allow-all** when the env var is empty (`cors(origins.length ? {origin} : {})`) — fail closed instead.
- **Sensitive data at rest**: third-party credentials users give you (AWS keys, API tokens, OAuth refresh tokens) must be encrypted (KMS / envelope encryption / `pgcrypto`) or, better, replaced by delegated access (AWS cross-account IAM role + external ID, OAuth). Plaintext columns = one DB leak exposes every customer's cloud account.

**Red flags**: `.env` committed, `cors({origin: "*"})` with credentials, CORS that defaults to `*` when unconfigured, users' cloud/API keys stored in plaintext, `DEBUG=True` in prod settings, stack traces in responses.

**Grep**: `process.env|os.environ|dotenv|cors|helmet|CSP|DEBUG|errorHandler|exception_handler|zod|pydantic|joi|yup`

## 12. Docker
**Check**
- Multi-stage build, slim/distroless base, pinned versions (not `:latest`).
- Runs as non-root `USER`; `.dockerignore` excludes `.env`, `node_modules`, `.git`.
- Layer caching order (deps before source); `HEALTHCHECK`; no secrets in `ENV`/`ARG`.
- `docker-compose.yml` for local dev with DB/Redis.

**Red flags**: `FROM node:latest`, `COPY . .` before install, secrets baked into image, running as root.

**Grep/Glob**: `Dockerfile*`, `docker-compose*.yml`, `.dockerignore`, `USER `, `HEALTHCHECK`, `:latest`

## 13. Kubernetes / orchestration
**Check** (Conditional — often N/A for small apps on PaaS like Vercel/Render/Railway/Fly)
- Resource requests/limits; liveness/readiness probes; HPA; PodDisruptionBudget.
- Secrets via Secret/external secret manager, not plain ConfigMap.
- Rolling update strategy; namespaces; NetworkPolicies; Helm/Kustomize for env differences.

**Red flags**: no limits, no probes, secrets in ConfigMaps or plaintext YAML, `privileged: true`.

**Grep/Glob**: `k8s/`, `helm/`, `kind: Deployment`, `resources:`, `livenessProbe`, `HorizontalPodAutoscaler`

## 14. CI/CD pipeline
**Check**
- CI runs on every PR: install, lint, type-check, tests, build, security scan (dependency audit, secret scan).
- CD: automated deploy to staging → prod with approval; rollback path; migrations run safely.
- Branch protection; secrets in CI secret store; dependency updates (Dependabot/Renovate).

**Red flags**: no CI at all, tests skipped in CI, deploy from laptop, secrets echoed in logs.

**Glob**: `.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/`, `azure-pipelines.yml`, `vercel.json`, `.github/dependabot.yml`

## 15. Scaling
**Check**
- Stateless app tier (see 5, 9); DB is the likely bottleneck → indexes, pooling, read replicas when needed.
- Heavy work moved off the request path (queues); static assets on CDN; file uploads to object storage (S3/GCS), not local disk.
- Pagination, streaming for large responses; N+1 removed.
- Known limits documented; load test exists (k6/Locust/Artillery) for critical paths.

**Red flags**: files saved to local disk, sync processing of long tasks in HTTP handlers, unbounded queries.

**Grep**: `multer|upload|fs.writeFile|s3|gcs|blob|k6|locust|artillery|pool`

## 16. Testing
**Check**
- Unit tests for business logic; integration tests for API + DB; a few E2E tests for critical flows (signup, payment).
- Tests run in CI; coverage measured on critical modules (not chasing 100%).
- Auth/authorization tests (user A can't access user B's data).
- Test data isolated (test DB/containers), no reliance on prod.

**Red flags**: zero test files, tests that only check `expect(true)`, tests that hit real prod APIs.

**Glob/Grep**: `**/*.test.*`, `**/*.spec.*`, `tests/`, `__tests__`, `jest|vitest|pytest|mocha|playwright|cypress|supertest`

## 17. Monitoring & observability
**Check**
- Structured logging (JSON) with request IDs; no secrets/PII in logs; log levels.
- Error tracking (Sentry/Rollbar/Bugsnag).
- Metrics (Prometheus/Datadog/CloudWatch): latency, error rate, throughput, saturation.
- Distributed tracing (OpenTelemetry) for multi-service setups.
- Alerts on SLO breaches; uptime checks; dashboards.

**Red flags**: only `console.log`/`print`, logging passwords/tokens, no error tracking.

**Grep**: `winston|pino|bunyan|structlog|logging|sentry|datadog|prometheus|opentelemetry|newrelic|console\.log`

## 18. Queues & background jobs
**Check**
- Long/slow tasks (emails, reports, AI calls, image processing) run in a queue (BullMQ, Celery, Sidekiq, RQ, SQS, RabbitMQ, Kafka, Inngest, Temporal).
- Jobs idempotent; retries with backoff; dead-letter queue; visibility/timeouts.
- Scheduled jobs (cron) don't run N times with N replicas (use locks/leader election or a scheduler service).
- Job monitoring dashboard / failure alerts.

**Red flags**: `setTimeout`/`setInterval` as a job system, fire-and-forget promises in request handlers, cron in every replica.

**Grep**: `bull|bullmq|celery|sidekiq|rq|sqs|rabbitmq|amqp|kafka|inngest|temporal|agenda|node-cron|cron|setInterval|apscheduler`

## 19. WebSockets / real-time
**Check**
- Authenticated on connect (token validated), authorization per room/channel.
- Scale-out via pub/sub adapter (Redis adapter for Socket.IO etc.) when >1 instance.
- Heartbeats/ping-pong, reconnect with backoff on client, message size limits, rate limiting per connection.
- LB configured for upgrade (`Upgrade`/`Connection` headers, timeouts).

**Red flags**: no auth on socket connect, broadcasting to all without room checks, in-memory room state with multiple instances.

**Grep**: `socket.io|ws|websocket|WebSocket|sse|EventSource|pusher|ably|channels|@SubscribeMessage`

## 20. AI agents & LLM apps
**Check**
- Prompt-injection defenses: untrusted content separated from instructions; tool permissions least-privilege; human confirmation for destructive actions.
- Output validated (structured output / schema) before acting; max iterations/steps on agent loops.
- Cost controls: per-user quotas, token limits, caching, model selection by task.
- Timeouts, retries, fallback model; streaming for UX.
- Evals / regression tests for prompts; logging of prompts & responses (with PII redaction); tracing (Langfuse/LangSmith/OTel).
- API keys server-side only.

**Red flags**: LLM output passed to `eval`/shell/SQL, unlimited agent loops, LLM key in frontend, no per-user limit.

**Grep**: `anthropic|openai|langchain|llamaindex|agent|tool_call|tools:|max_iterations|max_tokens|langfuse|langsmith|eval\(|exec\(`

## 21. MCP servers
**Check**
- Tools have clear schemas and descriptions; input validated.
- Auth for remote MCP (OAuth/token); least-privilege scopes; no arbitrary file/shell access without guardrails.
- Errors returned as structured tool errors; timeouts on long tools; logging.
- Transport chosen deliberately (stdio for local, Streamable HTTP for remote).

**Red flags**: tool that runs arbitrary shell/SQL from model input, remote MCP with no auth, secrets returned in tool output.

**Grep**: `@modelcontextprotocol|mcp|McpServer|FastMCP|server.tool|list_tools|call_tool`

## 22. RAG & vector databases
**Check**
- Chunking strategy justified (size/overlap, structure-aware); metadata stored (source, timestamp, tenant).
- Embedding model versioned; re-index plan when it changes.
- Multi-tenant filtering at query time (user only retrieves their docs).
- Hybrid search / reranking for quality; top-k tuned; citations returned.
- Retrieval evals (recall@k, answer faithfulness); ingestion pipeline idempotent; index on vector column (HNSW/IVFFlat for pgvector).

**Red flags**: no tenant filter on vector search (data leak!), no vector index, re-embedding everything on each deploy.

**Grep**: `pinecone|weaviate|qdrant|chroma|milvus|pgvector|vector|embedding|embed\(|similarity|hnsw|ivfflat|rerank|chunk`

## 23. LLM fine-tuning (Conditional — usually N/A)
**Check**
- Clear reason fine-tuning beats prompting/RAG; baseline measured first.
- Dataset versioned, cleaned, deduplicated, PII removed; train/val/test split; license checked.
- Eval suite comparing base vs tuned; experiment tracking (W&B/MLflow); model artifacts versioned.
- Serving plan: cost, latency, rollback to previous model.

**Grep**: `fine.?tun|lora|peft|trl|transformers|wandb|mlflow|jsonl|training`

---

## 24. File uploads
**Check**
- Size limit enforced while streaming (not after reading it all into memory); type checked by content/magic bytes, not just extension.
- Server picks the stored name (UUID), never the client's filename/key — prevents path traversal and overwriting others' files.
- Stored in object storage (S3/R2/GCS/Supabase Storage), not local disk (lost on redeploy, breaks with 2+ instances).
- Private files served via short-lived signed URLs after an ownership check; public bucket only for truly public assets.
- Presigned upload URLs: issued only to authenticated users, with server-chosen key, content-type and max size (`content-length-range` POST policy).
- Images re-encoded or served from a separate domain; SVG/HTML uploads not served inline.

**Red flags**: `file.filename` used in the path, no size cap, uploads under `static/` on the app server, presigned URL endpoint without auth, client-chosen S3 key.

**Grep**: `UploadFile|multer|formidable|busboy|request\.files|generate_presigned|getSignedUrl|createPresignedPost|upload`

## 25. Payments
**Check**
- Amount and currency computed server-side from your own catalogue/order — never trusted from the client.
- Payment status changes only via the provider's **signed webhook** (or a server-side status fetch), never from a client redirect alone.
- Webhooks idempotent (store provider event/payment id; ignore repeats) and verified; respond 2xx fast.
- Order state machine (created → paid → fulfilled/refunded) with no skipping; reconciliation job compares provider records with yours.
- Test vs live keys separated by env; live secret key server-side only.

**Red flags**: `amount` read from request body, marking paid on the success-page redirect, webhook without signature check or idempotency.

**Grep**: `stripe|razorpay|paypal|cashfree|phonepe|paytm|smepay|upi|checkout|payment_intent|order_id|webhook`

## 26. Serverless functions (Vercel, Netlify, AWS Lambda, Cloud Functions)
**Check**
- No reliance on process memory between requests: rate limits, OTP attempt counters, caches, sessions live in DB/Redis (e.g. Upstash).
- No local disk persistence; `/tmp` only for scratch.
- Function timeout and memory set deliberately; slow work handed to a queue (SQS, Inngest, QStash) instead of running past the limit.
- DB connections pooled for serverless (Supabase pooler, Prisma Accelerate/Data Proxy, RDS Proxy) — otherwise connection exhaustion under load.
- AWS: least-privilege IAM role per function (no `*` actions/resources), API Gateway authorizer or in-handler auth, throttling configured, `KeyError`/bad input returns 4xx not 500.
- Cold-start-sensitive init (SDK clients) at module scope; secrets from env/Secrets Manager.

**Red flags**: in-memory `Map` used as a rate limiter/counter, `fs.writeFile` outside `/tmp`, unauthenticated Lambda URL, IAM `"Action": "*"`.

**Grep**: `vercel\.json|netlify\.toml|serverless\.yml|lambda_handler|exports\.handler|new Map\(|/tmp/|iam|Resource: *\*`

## 27. Mobile apps (Capacitor/Ionic, React Native, Flutter, native Android/iOS)
**Check**
- No secrets in the app bundle — anything shipped in an APK/IPA is extractable. Only public config (Firebase config, API base URL, OAuth client IDs).
- Tokens in secure storage (Keychain/Keystore via `@capacitor/preferences`+secure plugin, `expo-secure-store`, `flutter_secure_storage`), not plain `localStorage`/AsyncStorage for long-lived tokens.
- Tokens never in URLs (`?t=`) — they leak via logs, history and Referer.
- Release build: `debuggable false`, no cleartext HTTP (`usesCleartextTraffic=false` / ATS), WebView not loading arbitrary URLs.
- Restricted Google API keys (Android package + SHA-1); signing keystore and `key.properties` never committed.
- Offline queue/outbox idempotent so retries don't double-submit; app handles token expiry gracefully.
- Force-update / minimum version check for breaking API changes.

**Red flags**: API secret in `capacitor.config`/`.env` bundled into the app, `android:debuggable="true"`, `.jks`/`.keystore` in git, token in query strings.

**Grep**: `localStorage|AsyncStorage|SharedPreferences|usesCleartextTraffic|debuggable|google-services\.json|\.jks|keystore|\?t=`

## 28. Browser extensions
**Check**
- Minimal `permissions` and `host_permissions` (no `<all_urls>` unless essential); Manifest V3.
- No API keys in the extension — calls to paid APIs go through your backend, which authenticates the user/install and rate limits per user (CORS on `chrome-extension://` is **not** auth: anyone can call your backend with curl).
- No remote code (`eval`, remote scripts); strict CSP.
- Messages from content scripts/web pages validated; never inject page-supplied HTML.
- Store listing privacy disclosure matches what's collected.

**Red flags**: `<all_urls>`, keys in `src/` or `manifest`, backend endpoint that trusts the Origin header as authentication.

**Grep**: `manifest_version|host_permissions|<all_urls>|chrome\.runtime\.onMessage|externally_connectable|apiKey`

## 29. Backups, disaster recovery & data privacy
**Check**
- Automated DB backups with point-in-time recovery where available; a restore has actually been tested; backups stored separately from prod credentials.
- Uploaded files versioned or backed up; destructive admin actions soft-delete or are logged.
- Documented RTO/RPO even if informal ("we can lose up to 24h of data").
- Personal data inventory: what PII you store, why, and for how long; delete-my-account/export path (GDPR, India's DPDP Act).
- PII minimized in logs and analytics; phone numbers/emails masked in logs.
- Sensitive columns encrypted (users' third-party credentials, government IDs); passwords hashed.

**Red flags**: free-tier DB with no backups for a live business app, committed `.db` files with user data, PII printed in logs, no way to delete a user.

**Grep**: `backup|pg_dump|pitr|retention|delete_account|deleteAccount|gdpr|dpdp|privacy|console\.log\(.*(phone|email)`

---

## Bonus cross-cutting checks (always run)
- **Secrets**: no keys in repo history/code (`sk-`, `AKIA`, `AIza`, `-----BEGIN`, `password=`, **DB URIs with `user:pass@`**); `.env` gitignored. A committed secret must be **rotated** — deleting it from the latest commit doesn't remove it from git history or from forks/clones.
- **Client-side keys**: anything in HTML/JS/APK is public. Firebase web config and Google Maps keys are meant to be public but must be **restricted** (HTTP referrer / app restrictions, API restrictions) in the cloud console; Gemini/OpenAI/DB keys must never be client-side.
- **Committed artifacts**: `*.db`/`*.sqlite` (may contain real user data + password hashes), `__pycache__`, logs, `node_modules` → remove and gitignore.
- **Dependencies**: lockfile committed; `npm audit` / `pip-audit` clean of criticals.
- **Security headers & OWASP Top 10**: XSS (no `dangerouslySetInnerHTML`/`innerHTML` with user data), CSRF for cookie auth, SSRF on URL-fetching features, file-upload validation.
- **Data & privacy**: backups, data retention, GDPR/DPDP delete-my-data path.
- **Docs**: README with setup, env vars, deploy, runbook for incidents.
