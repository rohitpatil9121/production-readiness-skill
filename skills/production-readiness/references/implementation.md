# Implementation Recipes

Stack-specific defaults for building each missing area. Use the library the
project already uses if one exists; otherwise pick from here. Always check the
latest version/API of a library in its docs or installed package before writing code.

Stacks covered: **Node (Express / Fastify / NestJS / Next.js)**, **Python
(FastAPI / Django / Flask)**. For other stacks, use the equivalent mature library.

---

## 1. Authentication
| Stack | Default |
|---|---|
| Next.js | Auth.js (next-auth) or Clerk; middleware for protected routes |
| Express/Fastify | `bcrypt`/`argon2` + `jsonwebtoken` (access 15m + refresh 7d, rotation) or `passport` |
| NestJS | `@nestjs/passport` + `@nestjs/jwt`, `AuthGuard` |
| FastAPI | `passlib[bcrypt]`/`argon2-cffi` + `pyjwt`, `OAuth2PasswordBearer` dependency |
| Django | built-in auth; `djangorestframework-simplejwt` for APIs |
| Supabase/Firebase | use their auth; verify tokens server-side |

Steps: hash on signup → verify on login → issue short-lived token (HttpOnly,
Secure, SameSite cookie for web) → `requireAuth` middleware → refresh + logout
(invalidate refresh token in DB/Redis) → rate-limit login. Secret from `JWT_SECRET`
env (add to `.env.example`). Tests: wrong password 401, expired token 401, no token 401.

## 2. Authorization
- Central `requireRole(...roles)` / `@Roles()` guard / FastAPI `Depends(require_role("admin"))`.
- Ownership check in the query: `where: { id, ownerId: user.id }` / `filter(id=..., owner=request.user)`.
  Return **404** (not 403) for others' resources to avoid leaking existence.
- Supabase/Postgres: enable RLS + policies `auth.uid() = user_id`.
- Libraries: CASL (Node), `django-guardian` / DRF permissions, Casbin (any).
- Tests: user A → user B's resource = 404; non-admin → admin route = 403.

## 3. Rate limiting
| Stack | Default |
|---|---|
| Express | `express-rate-limit` + `rate-limit-redis` store |
| Fastify | `@fastify/rate-limit` (Redis option) |
| NestJS | `@nestjs/throttler` (+ Redis storage) |
| Next.js / edge | `@upstash/ratelimit` in middleware |
| FastAPI | `slowapi` (Redis backend) |
| Django | `django-ratelimit` or DRF throttling |

Global ~100 req/min/IP; auth/OTP endpoints ~5/min; AI endpoints per-user quota.
Set `trust proxy` correctly behind LB. Also add body size limit and request timeout.

## 4. API integration resilience
- Shared HTTP client wrapper with timeout (5–10s), retry w/ exponential backoff +
  jitter for idempotent calls (`p-retry`, `axios-retry`, `got`; Python `tenacity`, `httpx` timeouts).
- Circuit breaker for critical deps: `opossum` (Node), `pybreaker` (Python).
- Webhooks: verify signature (e.g. `stripe.webhooks.constructEvent`), store event id
  for idempotency, respond 2xx fast and process in a queue.
- Move any key from `NEXT_PUBLIC_*`/`VITE_*` to server-only routes.

## 5. State management
- Frontend: TanStack Query / SWR for server state; Zustand for UI state. Remove server data copies from global stores.
- Backend: move in-memory sessions/state to Redis or DB so instances are stateless.

## 6–7. Caching & Redis
- Client: `ioredis` (Node), `redis` (Python, `redis.asyncio`). URL from `REDIS_URL`.
- Cache-aside helper: `getOrSet(key, ttl, fn)`; namespaced keys `app:entity:id`; always TTL.
- Invalidate on write (delete key in the same service method that updates the DB).
- HTTP: `Cache-Control` for static/public responses; Next.js `revalidate`.
- Add Redis to `docker-compose.yml` for local dev. App should log and fall back to DB if Redis is down (for cache use).

## 8. Database & indexing
- Find queried columns (WHERE/JOIN/ORDER BY/FKs) and add indexes via a **migration**:
  Prisma `@@index([...])` → `prisma migrate dev`; Django `Meta.indexes` → `makemigrations`;
  SQLAlchemy `index=True` → Alembic; raw SQL `CREATE INDEX CONCURRENTLY` for Postgres.
- Fix N+1 with `include`/`select_related`/`prefetch_related`/`joinedload`.
- Replace string-built SQL with parameterized queries.
- Add pagination (cursor-based for large tables) with max page size.
- Wrap multi-step writes in transactions. Configure connection pool size.

## 9. Health checks, graceful shutdown, load balancing
- `GET /healthz` (process alive) and `GET /readyz` (DB/Redis reachable).
- Handle SIGTERM: stop accepting requests, finish in-flight, close DB/Redis, exit.
- Sample `nginx.conf` upstream only if the user self-hosts; on PaaS, rely on platform LB.

## 10–11. System design hygiene
- Config module that validates env at startup (`zod`/`envalid`; `pydantic-settings`) — fail fast.
- `.env.example`, `.env` in `.gitignore`.
- Central error handler returning `{ error: { code, message } }`, no stack traces in prod.
- Request validation at every route (zod / class-validator / pydantic / DRF serializers).
- `helmet` (Node) / security middleware; CORS allowlist from env.
- Layering: routes → services → repositories if logic lives in handlers (only refactor with consent if large).
- Add `docs/ARCHITECTURE.md` with a short component diagram (Mermaid).

## 12. Docker
Node template:
```dockerfile
FROM node:22-slim AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM node:22-slim AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package*.json ./
USER node
EXPOSE 3000
HEALTHCHECK CMD node -e "fetch('http://localhost:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/index.js"]
```
Python: `python:3.12-slim`, `pip install --no-cache-dir -r requirements.txt`, non-root user,
`gunicorn -k uvicorn.workers.UvicornWorker` (FastAPI) / `gunicorn` (Django).
Adapt build output paths and versions to the project. Add `.dockerignore`
(`node_modules`, `.git`, `.env*`, `dist`, `__pycache__`) and `docker-compose.yml` with app + DB + Redis.

## 13. Kubernetes (only if asked)
Deployment (requests/limits, liveness `/healthz`, readiness `/readyz`, non-root
securityContext), Service, Ingress, HPA (CPU 70%), PDB, Secret refs via `envFrom`.
Put under `k8s/` (or a Helm chart if they have multiple envs).

## 14. CI/CD
GitHub Actions `.github/workflows/ci.yml` on `pull_request` + `push` to main:
checkout → setup runtime with cache → install (`npm ci` / `pip install`) → lint →
type-check → test (with Postgres/Redis `services:` if needed) → build → `npm audit --audit-level=high` / `pip-audit`.
Add `.github/dependabot.yml`. Deploy job only if the user names the target
(Vercel/Render/Fly/AWS) — use repo secrets, never inline keys.

## 15. Scaling
- Move file uploads to object storage (S3/R2/GCS presigned URLs).
- Move slow work to queues (see 18).
- Add a `k6` script in `loadtest/` for the main endpoints.

## 16. Testing
| Stack | Default |
|---|---|
| Node | Vitest or Jest + Supertest; Playwright for E2E |
| Python | pytest + httpx `AsyncClient`/`TestClient`; pytest-django |
Start with: auth flow, authorization (cross-user access), validation errors,
one happy path per main resource, rate limit returns 429. Use a separate test DB
(testcontainers or docker-compose service). Add `test` script and run it in CI.

## 17. Monitoring & observability
- Structured logger: `pino` (+ `pino-http` with request id) / Python `structlog` or `logging` JSON formatter. Redact `password`, `token`, `authorization`.
- Errors: Sentry SDK (`SENTRY_DSN` env; no-op if unset).
- Metrics: `prom-client` `/metrics` / `prometheus-fastapi-instrumentator`, or OpenTelemetry SDK.
- Replace stray `console.log`/`print` in server code with the logger.

## 18. Queues & background jobs
| Stack | Default |
|---|---|
| Node | BullMQ (Redis) — separate `worker.ts` entry; or Inngest/Trigger.dev on serverless |
| Python | Celery (Redis/RabbitMQ) or RQ; Django: Celery + `django-celery-beat` |
Jobs idempotent, `attempts` + exponential backoff, failed-job handling (DLQ), worker
as its own process/container. Cron: repeatable jobs in the queue (one runner), not `setInterval` in every replica.

## 19. WebSockets
- Socket.IO: auth middleware `io.use((socket,next)=> verify(socket.handshake.auth.token))`, room-level authz, `@socket.io/redis-adapter` for multi-instance, `maxHttpBufferSize`, per-socket rate limit.
- FastAPI: validate token on `websocket.accept()`; Redis pub/sub (or `broadcaster`) for fan-out.
- Client: reconnect with backoff; server heartbeats.

## 20. AI agents / LLM features
- All LLM calls server-side through one `llm` module: timeout, retries, fallback model, `max_tokens`, streaming.
- Per-user quota + rate limit (cost control); log token usage.
- Structured outputs validated by schema before use; never `eval`/exec LLM output; parameterize any SQL it influences.
- Agent loops: `max_steps`, tool allowlist, human confirmation for destructive tools, untrusted content wrapped/labeled.
- Tracing: Langfuse / LangSmith / OpenTelemetry. Add a small eval set (`evals/`) with expected outputs.

## 21. MCP server
- Official SDKs: `@modelcontextprotocol/sdk` (TS), `mcp` / FastMCP (Python).
- Each tool: clear description, input schema, validation, timeout, structured errors.
- Remote: Streamable HTTP + OAuth/bearer auth; least-privilege tools; no raw shell/SQL tools.

## 22. RAG & vector DB
- Store: pgvector if already on Postgres (add HNSW index), else Qdrant/Pinecone/Chroma.
- Ingestion script: structure-aware chunking (~500–1000 tokens, 10–20% overlap), metadata (source, tenant_id, updated_at, embedding_model), idempotent upsert by content hash.
- Query: **filter by tenant/user**, top-k + rerank, return citations.
- `evals/rag/` with question → expected source pairs; measure recall@k.

## 23. Fine-tuning (only if asked and justified)
`training/` folder: dataset prep script (dedupe, PII scrub, split), config (LoRA/PEFT
or provider fine-tune API), eval script comparing base vs tuned, experiment tracking (W&B/MLflow).

---

## 24. File uploads
- Stream with a byte counter and abort at the limit (FastAPI: read chunks; Express: `multer({ limits: { fileSize } })`).
- `uuid4()` + allowed extension for the stored name; sniff type with `file-type` (Node) / `python-magic`.
- Store in S3/R2/Supabase Storage; return a signed URL for private files.
- Presigned uploads: endpoint requires auth, server builds the key (`users/<id>/<uuid>.<ext>`), use `createPresignedPost` with `content-length-range` and fixed `Content-Type`.

## 25. Payments
- Create the order server-side from catalogue prices; send only the order id to the client.
- Webhook handler: verify signature (Stripe `constructEvent`, Razorpay `validateWebhookSignature`), `INSERT … ON CONFLICT DO NOTHING` on the provider event id, then update order state in a transaction.
- Nightly reconciliation job: fetch provider payments for the day, diff with DB, alert on mismatch.

## 26. Serverless
- Rate limit / attempt counters: `@upstash/ratelimit` (Redis) or a DB column/table. Without Redis and without schema changes, an attempt cap can be encoded in an existing expiry column (each failure pulls expiry forward by TTL/N).
- Background work: Vercel → Inngest/QStash/Trigger.dev; AWS → SQS + worker Lambda.
- DB: use the provider's pooled connection string; create the client at module scope.
- Lambda: per-function IAM policy listing exact actions and resource ARNs; API Gateway JWT authorizer (Cognito/Auth0/Supabase JWKS); return 400/404 on bad input.

## 27. Mobile apps
- Move any secret-bearing call to the backend; app holds only a user session token.
- Token storage: Capacitor `@capacitor/preferences` is not encrypted — use a secure-storage plugin (Keychain/Keystore); RN `expo-secure-store`; Flutter `flutter_secure_storage`.
- For `<img>`/file URLs that need auth, have the API return short-lived signed URLs instead of putting the session token in `?t=`.
- Android release: `android:usesCleartextTraffic="false"`, signing config from env/CI secrets, keystore in `.gitignore`.

## 28. Browser extensions
- Backend issues a per-install or per-user token (e.g. sign-in, or an install id registered on first run) and rate limits per token, not per IP.
- Trim `permissions`/`host_permissions` to the sites actually used; no remote scripts.

## 29. Backups & privacy
- Enable PITR/daily backups on the managed DB; write `docs/RUNBOOK.md` with the restore steps and do one test restore.
- Add `DELETE /api/me` that deletes or anonymizes the user's rows and files; log redaction for phone/email.

## 30. Supabase & Firebase
- Supabase migration (new file in `supabase/migrations/`, never edit applied ones):
  ```sql
  alter table public.entries enable row level security;
  create policy "own rows: read"   on public.entries for select using (auth.uid() = user_id);
  create policy "own rows: insert" on public.entries for insert with check (auth.uid() = user_id);
  create policy "own rows: update" on public.entries for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
  create policy "own rows: delete" on public.entries for delete using (auth.uid() = user_id);
  ```
  Test it: as user A, `select` user B's row through the anon client and expect an empty result. Run the Supabase **Security Advisor** (Dashboard → Advisors) after.
- Backend-only tables (accessed with the service role): enable RLS with **no** policies. Anon gets nothing, and the service role still works.
- Move any `service_role` usage into a server route / Edge Function; rotate the key if it was ever in client code or git.
- Firestore rules:
  ```
  match /entries/{id} {
    allow read, update, delete: if request.auth != null && request.auth.uid == resource.data.ownerId;
    allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;
  }
  ```
  Test with the Firebase Emulator + `@firebase/rules-unit-testing`.

## Cross-cutting fixes
- Hardcoded secrets → move to env, add to `.env.example`, and **tell the user to rotate the leaked key** (removing it from code doesn't un-leak it; git history still has it). If the key was used from the browser (e.g. Gemini/OpenAI called from HTML), add a small server endpoint that builds the prompt server-side and holds the key — don't create a general-purpose proxy.
- Encrypting an existing plaintext column: a SQLAlchemy `TypeDecorator`/Prisma middleware that encrypts on write and passes legacy plaintext through on read, plus an idempotent one-off script to encrypt existing rows. Key from env; startup fails without it.
- `npm audit fix` / upgrade vulnerable deps (non-breaking first; ask before majors).
- XSS: remove unsafe `innerHTML`/`dangerouslySetInnerHTML` or sanitize with DOMPurify.
- README: setup, env vars, run, test, deploy sections.
