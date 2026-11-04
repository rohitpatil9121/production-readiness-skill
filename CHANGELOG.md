# Changelog

## 1.0.0 (2026-11-04)

First public release.

- Audit workflow across 29 areas: security, data, reliability, infra, AI/LLM, mobile and browser-extension clients.
- Strict 🔴/⚠️ rubric that takes project stage, repo visibility and deploy target into account.
- Implementation mode: plan → branch → fix → a test that fails on the old code and passes on the new → re-audit → hand-over (env vars before merge, secret rotation).
- `scan.sh`: repo profile (app type, server, DB, accounts, LLM, mobile, deploy target), area signals, infra, secrets & repo hygiene, risky patterns with `file:line`, secrets in git history, optional `--deep` with gitleaks/semgrep/npm audit/pip-audit/hadolint.
- `routes.py`: route inventory for Express-style routers, FastAPI, Flask and Next.js, with unguarded write routes and unsigned webhooks flagged.
- Tested against 49 real-world repositories before release. Fixes from that run: multi-line FastAPI decorators, `re.exec()` false positives, JSON-LD `dangerouslySetInnerHTML`, `[^\n]` regex bug, test files excluded from risky patterns.
- Plugin + marketplace manifests, `install.sh`, CI on Linux and macOS.
