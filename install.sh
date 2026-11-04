#!/usr/bin/env bash
# Install the production-readiness skill for Claude Code without the plugin system.
#
#   ./install.sh                 # user-wide: ~/.claude/skills/production-readiness
#   ./install.sh --project DIR   # one project: DIR/.claude/skills/production-readiness
#   ./install.sh --uninstall [--project DIR]
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/skills/production-readiness"
TARGET_BASE="$HOME/.claude/skills"
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --project) [ $# -ge 2 ] || { echo "--project needs a directory" >&2; exit 2; }
               TARGET_BASE="$(cd "$2" && pwd)/.claude/skills"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n 2,7p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done

DEST="$TARGET_BASE/production-readiness"

if [ "$UNINSTALL" = 1 ]; then
  if [ -d "$DEST" ]; then rm -rf "$DEST"; echo "Removed $DEST"; else echo "Nothing installed at $DEST"; fi
  exit 0
fi

[ -f "$SRC/SKILL.md" ] || { echo "Can't find the skill at $SRC — run this from a clone of the repo." >&2; exit 1; }
for tool in bash git grep; do command -v "$tool" >/dev/null || echo "Warning: '$tool' not found — the scan script needs it." >&2; done
command -v python3 >/dev/null || echo "Warning: python3 not found — the route/auth check will be skipped." >&2

mkdir -p "$TARGET_BASE"
if [ -d "$DEST" ]; then echo "Updating existing install at $DEST"; rm -rf "$DEST"; fi
cp -R "$SRC" "$DEST"
chmod +x "$DEST"/scripts/*
echo "Installed to $DEST"
echo "Open Claude Code and ask: \"is this project production ready?\" — or type /production-readiness"
