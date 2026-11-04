---
name: production-readiness
description: Audit a codebase for production-grade software engineering fundamentals beyond "the code works" — authentication, authorization, rate limiting, API integration robustness, state management, caching/Redis, DB indexing, load balancing, microservices & system design, Docker, Kubernetes, CI/CD, scaling, testing, monitoring/observability, queues & background jobs, websockets, AI agents, MCP servers, RAG, vector DBs, LLM fine-tuning, file uploads, payments, serverless, mobile apps and browser extensions. Use when the user asks "is this production ready?", "audit my project/all my projects", "what's missing before launch", "vibe-coded app review", "production checklist", "security check", or wants a gap report of non-coding engineering concerns. Also implements the missing pieces — use when the user says "make it production ready", "add what's missing", "fix the gaps", "implement auth/rate limiting/caching/etc.".
---

# Production Readiness Audit

Vibe coding gets features working. This skill checks whether the app would
**survive real users, real traffic, and real attackers** — across 29 engineering
areas in `references/checklist.md` — produces a scored gap report, and can then
implement the fixes.

Files:
- `scripts/scan.sh [--deep] <repo>` — profile + signals + risky patterns + routes + git history
- `scripts/routes.py <repo>` — lists HTTP routes and flags ones with no visible auth guard (called by scan.sh)
- `references/checklist.md` — what good looks like, red flags, grep hints per area
- `references/implementation.md` — stack-specific recipes for fixing each area

## Workflow

### 1. Understand the project (don't skip)
- Read README, manifests (`package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, …).
- Run the scan. `<skill-dir>` is the directory containing this SKILL.md — it
  differs by install method (`~/.claude/skills/production-readiness`,
  `<project>/.claude/skills/production-readiness`, or a plugin cache directory):
  ```bash
  bash <skill-dir>/scripts/scan.sh <repo-path>
  ```
  Needs bash, git, grep and python3 (python3 only for the route check).
  Add `--deep` to also run gitleaks / semgrep / npm audit / pip-audit / hadolint
  when they are installed. Without them, secret and vuln detection is regex-only —
  say so in the report.
- Establish three facts — they change severity and what's worth doing:
  1. **Stage**: learning/demo · MVP · live with real users/money. Infer from README,
     deploy config, custom domain, payment code; ask if unclear before implementing.
  2. **Visibility**: public or private repo (`gh repo view --json visibility`, or ask).
     In a public repo any committed secret is already leaked.
  3. **Deploy target**: the scan's `Deploy target` line. Serverless (Vercel, Netlify,
     Lambda) means in-memory limits/caches/counters don't work across requests,
     local disk is ephemeral, and there are no long-running workers.
- **Where to look first** (most bugs live here): route/handler definitions, auth
  middleware, config/env loading, DB schema/migrations, webhook handlers, file
  upload handlers, anything calling an LLM or payment API, Dockerfile, CI workflow.

### 2. Decide which areas apply
Mark each area **Applicable**, **Conditional** (needed at scale/later) or **N/A**
(say why). Never mark something N/A just because it's missing. Start from the
scan's Profile line:
- **static site / frontend SPA / game** — secrets & client-side keys, hosting
  security headers, CI, tests, performance. Keep the report short.
- **browser extension** — checklist §28, plus any backend it talks to.
- **mobile app** — checklist §27, plus its backend.
- **notebook / ML** — reproducibility, data/version tracking, secrets.
- **backend/full-stack** — full audit. `user accounts=yes` → authn, authz and
  auth rate limiting are always Applicable. `LLM=yes` → per-user quota and cost
  controls are always Applicable.

**Many repos at once** ("audit all my projects"): skip forks and repos owned by
others unless asked; scan every repo; deep-audit backends, anything with secret
hits, unguarded write routes or unsigned webhooks; one-line verdict for the
rest; collect every 🔴 from every repo at the top of one combined report.

### 3. Audit each applicable area
For each area in `references/checklist.md`:
1. Open the files the scan pointed to — and search beyond them. Every secret hit,
   risky pattern and unguarded route must be opened and judged (public-by-design
   vs real problem). The scan misses things and over-reports others.
2. Compare against the checklist items.
3. Record evidence as `file_path:line` — no claims without evidence.
4. Score it.

### 4. Score
| Score | Meaning |
|---|---|
| ✅ **Solid** | Implemented correctly, covers the checklist essentials |
| ⚠️ **Partial** | Exists but has gaps or risky defaults |
| ❌ **Missing** | Needed but absent |
| 🔴 **Dangerous** | Actively harmful (see rubric) |
| ➖ **N/A** | Not relevant to this app (with reason) |

**🔴 vs ⚠️ rubric** — 🔴 only if at least one is true:
- A credential is exposed (in code, client bundle, logs, or git history of a public repo).
- An anonymous internet user can, today, read others' data, act as another user,
  change/delete data, run up your bills (unlimited LLM/SMS/payment calls), or
  control infrastructure — on an app that is deployed or meant to be.
- Sensitive data is stored so that one leak exposes everyone (plaintext passwords,
  users' cloud keys).

Otherwise ⚠️ — e.g. needs specific conditions, only breaks at scale, defense-in-depth
gap, or the app is a learning project that isn't deployed (say "fine as a learning
project; don't deploy as-is").

Overall readiness = applicable areas that are Solid / total applicable. Any 🔴 caps
the verdict at **"Not production ready"**.

### 5. Optional: verify at runtime
When the app can be started locally (deps install, no paid services needed),
prove the important findings instead of inferring them — and later prove the fixes:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST localhost:PORT/api/protected   # expect 401
for i in $(seq 1 30); do curl -s -o /dev/null -w "%{http_code} " -X POST localhost:PORT/api/login -d '{}' -H 'content-type: application/json'; done   # expect 429s
curl -sI localhost:PORT/ | grep -iE "strict-transport|content-security|x-frame|x-content-type"
curl -s -H "Origin: https://evil.example" -I localhost:PORT/api/x | grep -i access-control-allow-origin
```
Use test env values (fake keys, local/in-memory DB) — never real credentials.

### 6. Report
```
# Production Readiness Report — <project>
Stack: … | Type: … | Stage: … | Repo: public/private | Deploy: … | Verdict: Not ready / Needs work / Ready with caveats / Ready
Score: X/Y applicable areas solid | Scan: regex-only or --deep (tools: …)

## 🔴 Critical (fix before any deploy)
- [Area] problem — evidence `file:line` — fix — (secrets: "rotate", never the value)

## Scorecard
| # | Area | Status | Key finding |

## Area details
### <Area> — <status>
What exists / Gaps / Fix (stack-specific; snippet if helpful)

## Prioritized roadmap
1. Now (security & data loss) 2. Before launch (reliability) 3. At scale (performance & ops)

## Learning pointers
One line per ❌ area: the concept to learn and why it matters.
```
**The report is itself sensitive** — it's a map of exploitable bugs. Never print
secret values. Never commit it to a public repo or publish it; save it outside the
repo (or in a gitignored path) unless the user explicitly asks otherwise, and
say that it shouldn't be shared until the 🔴 items are fixed.

### 7. Implement the missing pieces
After the report, offer to build what's missing. If the user already asked to
"make it production ready" / "fix everything", go straight to the plan.

1. **Plan** — list the items in roadmap order (🔴 first). For each: files to change,
   new dependencies, new env vars, and whether existing data or other services are
   affected. Get one go-ahead (the user may pick a subset, e.g. "sirf 1-5 karo").
   Skip Conditional items unless asked.
2. **Branch** — one new branch per repo (e.g. `fix/<topic>`), never main. One commit
   per area. Push only if the user wants it; don't open PRs unless asked.
3. **Implement one area at a time** with `references/implementation.md`:
   - Follow the project's existing style and structure; prefer proven libraries.
   - **Respect the deploy target**: on serverless keep counters/limits in the DB or
     Redis, not memory; files in object storage; slow work in a queue service.
   - **Stay compatible with existing data**: e.g. encrypting a column must still read
     old plaintext rows and ship a one-off migration script. Shared DB with another
     service? Avoid schema changes or ask first.
   - **Fail fast, fail closed**: a missing secret in production stops startup; a
     missing webhook secret rejects requests — never "warn and continue".
   - New env vars go in `.env.example` with placeholders; never real values.
4. **Prove it** — for every fix:
   - Write a test for the bug (e.g. "user A can't read user B's data", "6th wrong OTP
     is rejected", "forged token → 401").
   - **Run the new test against the old code and confirm it fails** (`git stash`),
     then against the fix and confirm it passes. A test that passes on both proves nothing.
   - Run the full build/lint/test suite; fix what breaks.
5. **Re-audit** — re-run the scan and re-score touched areas: before → after.
6. **Hand over**:
   - **Deploy order**: env vars/secrets to set on the host *before* merging, or the
     deploy breaks; one-off scripts to run after.
   - **Secret rotation**: for each leaked credential, where to rotate it (provider
     console), and to check that provider's access logs for misuse. Removing a
     secret from code does not un-leak it.
   - What you deliberately didn't do and why (e.g. a bigger redesign).

**Ask first** (don't do silently): switching auth provider, schema changes on
existing data (write a migration, never drop data), adding paid services, deleting
code, large refactors, changing deploy/infra config that's already in use,
anything that logs users out or forces them to redo setup.

## Learning mode
If the user wants to learn (e.g. "samjha ke karo", "explain while fixing"), for
each fix also explain: what the attack/failure looks like in practice, why this
fix works, what the alternatives were, and one question they should be able to
answer afterwards. Keep code the same — only the explanation changes.

## Rules
- Evidence over vibes: every ✅/⚠️/🔴 cites files. Every ❌ states what you searched for.
- Prioritize by blast radius: security > data integrity > availability > performance > DX.
- Be stack-specific in fixes (`express-rate-limit`, `slowapi`, `django-ratelimit`, …).
- Don't pad or over-engineer: say which areas can wait for this app's stage.
- Nothing is "done" until it builds and its tests pass — report failures honestly.
- Match the user's language (Hindi/Hinglish/English) in the report prose.
