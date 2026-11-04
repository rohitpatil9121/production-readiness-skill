# Contributing

Thanks for helping make this better. The most useful contributions are:

1. **False positives**: the scan flagged something that's fine.
2. **Missed issues**: a real problem the scan or checklist didn't catch.
3. **New checks or stacks**: an area, framework or red flag that's missing.

## Layout

```
skills/production-readiness/
  SKILL.md                     # the workflow Claude follows (keep it tight; it's loaded into context)
  scripts/scan.sh              # repo profile + signals + risky patterns + history
  scripts/routes.py            # route list + auth-guard detection (called by scan.sh)
  references/checklist.md      # per-area: what good looks like, red flags, grep hints
  references/implementation.md # per-area fix recipes by stack
tests/run.sh                   # builds fixture apps in a temp dir and asserts on scan output
.claude-plugin/                # plugin + marketplace manifests
```

## Making a change

1. Add a fixture case to `tests/run.sh` that shows the bug: a tiny app plus a `has`/`hasnt` assertion. **Run it first and watch it fail.**
2. Fix `scan.sh` / `routes.py` / the checklist.
3. Run `bash tests/run.sh`. Everything must pass. `KEEP=1 bash tests/run.sh` keeps the fixture repos so you can inspect them.
4. If you can, also run the scan on a few real repos and confirm the change doesn't add noise elsewhere.
5. Add a line to `CHANGELOG.md`.

## Rules for the scanner

- **Never print secret values**, only `file:line`.
- **Never commit secret-looking strings**, not even fake ones. Build them from parts at runtime, like `tests/run.sh` does, so push protection and secret scanners don't fire on this repo.
- Prefer **fewer, precise** patterns over broad ones. Every false positive teaches users to ignore the output.
- Stick to POSIX ERE (`grep -E`): no `\d`, no lookaheads. Watch out for `[^\n]`: inside brackets it means "not a backslash and not the letter n". Use `.*` instead.
- Must run on Linux and macOS (bash 3.2, BSD grep). CI runs both.

## Rules for SKILL.md and references

- Every check needs a *why* a production app needs it, and a concrete red flag.
- Fix recipes should name real, maintained libraries for each stack.
- Keep `SKILL.md` short. Detail belongs in `references/`.

## Releasing

Bump `version` in both `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json`, update `CHANGELOG.md`, then run `claude plugin validate .` and tag `vX.Y.Z`.
