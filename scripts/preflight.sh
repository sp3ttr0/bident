#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

bash -n bident.sh

for file in lib/*.sh; do
  bash -n "$file"
done

printf 'Preflight checks passed.\n'
