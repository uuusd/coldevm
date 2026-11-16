#!/bin/sh
# Runs the interop test: gradle (host) <-> Keystone SDK + ethers (node:22-alpine container).
# Usage: tools/interop/run.sh <dir with node_modules containing @keystonehq/keystone-sdk @ngraveio/bc-ur ethers>
set -e
MODS=$(realpath "$1"); ROOT=$(cd "$(dirname "$0")/../.." && pwd)
X=${KEEP_DIR:-$(mktemp -d)}; [ -z "$KEEP_DIR" ] && trap 'rm -rf "$X"' EXIT
node() { docker run --rm --network none -v "$MODS":/m:ro -v "$ROOT/tools/interop":/s:ro -v "$X":/x -e NODE_PATH=/m/node_modules node:22-alpine node /s/interop.js /x "$1"; }
gradle() { (cd "$ROOT" && COLDEVM_INTEROP_DIR="$X" ./gradlew --no-daemon -q testDebugUnitTest --tests "org.coldevm.signer.InteropTest.$1" --rerun); }
gradle writeSyncUr
node phase1
gradle signJsRequests
node phase2
