#!/usr/bin/env bash

set -euo pipefail

DIR="${1:-.}"
EXT="$2"

if [[ -z "${EXT:-}" ]]; then
    echo "Usage: $0 <directory> <extension>"
    exit 1
fi

find "$DIR" -type f -name "*$EXT" | while IFS= read -r file; do
    echo "===== FILE: $file ====="
    cat "$file"
    echo
done
