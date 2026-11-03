#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v gh >/dev/null 2>&1; then echo 'Install GitHub CLI (gh) first.' >&2; exit 1; fi
if ! gh auth status >/dev/null 2>&1; then echo 'Log in to GitHub CLI first: gh auth login' >&2; exit 1; fi
if [[ -e .env ]]; then echo 'INFO: .env exists locally and is excluded by .gitignore.' >&2; fi
if [[ ! -d .git ]]; then git init -b main; fi
git add .
if git diff --cached --name-only | grep -Eq '(^|/)\.env$'; then echo 'Refusing to commit .env' >&2; exit 1; fi
if ! git diff --cached --quiet; then git commit -m 'Launch Nodekeep real remote monitoring operations service'; fi
if git remote get-url origin >/dev/null 2>&1; then
  echo 'Existing git remote found. Refusing to overwrite or repoint origin.' >&2
  git remote -v
  exit 1
fi
gh repo create nodekeep --private --source=. --remote=origin --push
