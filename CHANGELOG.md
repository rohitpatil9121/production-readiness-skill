# Changelog

## 1.1.0 (2026-11-04)

- **Supabase & Firebase checks** (`baas.py`, checklist §30): tables without Row Level Security, `using (true)` write policies, `service_role` JWTs in the repo (decoded, not pattern-matched), service keys in client code, Firebase test-mode/open rules.
- **Route detection for 10 frameworks**: added NestJS, Django/DRF, Spring, Go (gin/echo/chi/net-http), Laravel and Rails to Express, Next.js, FastAPI and Flask.
- **Possible IDOR**: authenticated routes that load a record by URL id with no owner/user check in the handler.
- **Dependency vulnerabilities** (`deps.py`, `--deps`): npm/yarn/pnpm, pip pins, Pipfile/poetry, Go, Ruby, PHP and Rust lockfiles checked against OSV. No install needed.
- **Runtime probe** (`probe.sh`): security headers, CORS reflection, exposed `.env`/`.git`, stack-trace leaks, open protected routes, login rate limiting.
- **Reports** (`report.py`): text, JSON, SARIF, HTML and Markdown; `--fail-on` for CI; `.production-readiness-ignore`; `--save-history` with a trend chart and "since last scan" diff; `--write` for several formats from one scan.
- **GitHub Action** (`action.yml`): job summary, SARIF upload to code scanning, HTML report artifact, PR failure on critical findings.
- **Repo visibility** detected via `gh` (public repo → every committed secret is already leaked).
- **Evals** (`evals/`): IDOR + leaked key, Supabase without RLS, and a static site that must not get backend advice. Each runs with and without the skill; there's an on-demand CI workflow.
- Stronger skill trigger description; committed credentials always get "rotate it" with no hedging.
- Fixes: publishable keys (`public_`, `pk_live_`) no longer flagged; docs files excluded from risky patterns; the secret regex no longer matches itself.

## 1.0.0 (2026-11-04)

First public release.

- Audit workflow across 29 areas: security, data, reliability, infra, AI/LLM, mobile and browser-extension clients.
- Strict 🔴/⚠️ rubric that takes project stage, repo visibility and deploy target into account.
- Implementation mode: plan → branch → fix → a test that fails on the old code and passes on the new → re-audit → hand-over (env vars before merge, secret rotation).
- `scan.sh`: repo profile (app type, server, DB, accounts, LLM, mobile, deploy target), area signals, infra, secrets & repo hygiene, risky patterns with `file:line`, secrets in git history, optional `--deep` with gitleaks/semgrep/npm audit/pip-audit/hadolint.
- `routes.py`: route inventory for Express-style routers, FastAPI, Flask and Next.js, with unguarded write routes and unsigned webhooks flagged.
- Tested against 49 real-world repositories before release. Fixes from that run: multi-line FastAPI decorators, `re.exec()` false positives, JSON-LD `dangerouslySetInnerHTML`, `[^\n]` regex bug, test files excluded from risky patterns.
- Plugin + marketplace manifests, `install.sh`, CI on Linux and macOS.
