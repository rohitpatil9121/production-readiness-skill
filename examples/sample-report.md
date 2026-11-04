# Production Readiness Report — notes-api (example)

> This is an illustrative report for a **fictional** project, showing the format
> the skill produces. File names and findings are made up.

Stack: Express 4 + PostgreSQL (Prisma) + OpenAI | Type: backend/full-stack | Stage: MVP, ~200 beta users | Repo: public | Deploy: Vercel (serverless) | **Verdict: Not production ready**
Score: 5/17 applicable areas solid | Scan: regex-only (gitleaks not installed)

## 🔴 Critical (fix before any deploy)

- **[Secrets]** OpenAI key hardcoded in a public repo: `src/ai.js:4`. Rotate it in the OpenAI dashboard now, check usage for spikes, then load it from `OPENAI_API_KEY`.
- **[Authorization]** Any logged-in user can read or delete any note (IDOR). The query filters by `id` only: `src/routes/notes.js:31`, `:58`. Fix: `where: { id, ownerId: req.user.id }`, and return 404 for others' notes.
- **[Rate limiting / LLM cost]** `POST /api/summarize` has no per-user quota or rate limit (`src/routes/ai.js:12`). One script can run up an unbounded OpenAI bill. Fix: `@upstash/ratelimit` (Vercel = serverless, so memory-based limiters won't hold), 20 req/day per user.

## Scorecard

| # | Area | Status | Key finding |
|---|------|--------|-------------|
| 1 | Authentication | ⚠️ | bcrypt + JWT, but tokens never expire (`src/auth.js:22`) |
| 2 | Authorization | 🔴 | IDOR on notes (`src/routes/notes.js:31`) |
| 3 | Rate limiting | 🔴 | none; LLM endpoint unprotected |
| 4 | API integration | ⚠️ | OpenAI call has no timeout or retry (`src/ai.js:15`) |
| 8 | Database & indexing | ⚠️ | no index on `Note.ownerId`, which every list query filters on |
| 11 | System design | ⚠️ | CORS `origin: true` with credentials (`src/app.js:9`) |
| 14 | CI/CD | ❌ | no workflow; deploys from laptop |
| 16 | Testing | ❌ | 0 test files |
| 17 | Monitoring | ❌ | `console.log` only; no error tracking |
| 18 | Queues | ➖ | N/A for now: no slow work besides the OpenAI call, which takes ~3 s |
| 20 | LLM apps | 🔴 | see rate limiting; output rendered with `innerHTML` (`public/app.js:88`) |
| 26 | Serverless | ⚠️ | Prisma without a pooled connection string → connection exhaustion under load |
| 29 | Backups & privacy | ⚠️ | free-tier DB, no backups; no delete-account path |
| … | | | |

## Area details

### Authorization — 🔴 Dangerous
**What exists:** `requireAuth` middleware on every `/api/notes` route.
**Gap:** handlers fetch by `id` alone, so authentication is checked but ownership isn't.
**Fix:**
```js
const note = await prisma.note.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });
if (!note) return res.status(404).json({ error: "Not found" });
```
**Test:** user A creates a note; user B's `GET`/`DELETE` on it returns 404.

*(…one section per applicable area…)*

## Prioritized roadmap
1. **Now:** rotate the OpenAI key, fix the IDOR, add a per-user LLM quota.
2. **Before launch:** token expiry + refresh, CORS allowlist, OpenAI timeout/retry, `ownerId` index, CI with tests, Sentry.
3. **At scale:** pooled DB connections, move summarization to a queue (Inngest/QStash), daily backups + a restore drill.

## Learning pointers
- **CI/CD:** every push should prove the app still builds and passes tests before it can reach users.
- **Testing:** authorization bugs like the IDOR above are invisible in manual testing with one account. A two-user test catches them.
- **Monitoring:** without error tracking, you find out about production errors from users, or not at all.
