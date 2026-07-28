#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FISHHOOK_DIR="$ROOT/vendor/fishhook"
FISHHOOK_COMMIT="aadc161ac3b80db07a9908851839a17ba63a9eb1"
FISHHOOK_C_SHA256="48F51E1A36D9013501381FDF31A3E9C838938EBF8BB39E0E3A7AC119AA59B61B"
FISHHOOK_H_SHA256="5432B81BD302956ADCBFC8836AF74E47DD38748D5078495CBE1B5BEA62180120"
FISHHOOK_LICENSE_SHA256="0D6DE56134AC05FFCE391C697BB046C83CAB012A4670114E1F0847ECF59B2C2E"

if [[ -d "$FISHHOOK_DIR/.git" ]]; then
  ACTUAL_COMMIT="$(git -C "$FISHHOOK_DIR" rev-parse HEAD)"
  if [[ "$ACTUAL_COMMIT" != "$FISHHOOK_COMMIT" ]]; then
    echo "fishhook commit mismatch: $ACTUAL_COMMIT" >&2
    exit 1
  fi
elif [[ -f "$FISHHOOK_DIR/fishhook.c" &&
        -f "$FISHHOOK_DIR/fishhook.h" &&
        -f "$FISHHOOK_DIR/LICENSE" ]]; then
  :
elif [[ -e "$FISHHOOK_DIR" ]]; then
  echo "Incomplete fishhook dependency: $FISHHOOK_DIR" >&2
  exit 1
else
  git clone --filter=blob:none \
    https://github.com/facebook/fishhook.git "$FISHHOOK_DIR"
  git -C "$FISHHOOK_DIR" checkout --detach "$FISHHOOK_COMMIT"
fi

test -s "$FISHHOOK_DIR/fishhook.c"
test -s "$FISHHOOK_DIR/fishhook.h"
test -s "$FISHHOOK_DIR/LICENSE"

verify_sha256() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(shasum -a 256 "$path" | awk '{print toupper($1)}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "Dependency hash mismatch: $path" >&2
    exit 1
  fi
}

verify_sha256 "$FISHHOOK_DIR/fishhook.c" "$FISHHOOK_C_SHA256"
verify_sha256 "$FISHHOOK_DIR/fishhook.h" "$FISHHOOK_H_SHA256"
verify_sha256 "$FISHHOOK_DIR/LICENSE" "$FISHHOOK_LICENSE_SHA256"
