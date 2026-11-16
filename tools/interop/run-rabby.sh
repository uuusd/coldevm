#!/bin/sh
# Rabby / MetaMask interop: Keystone base-eth-keyring in a container, ColdEVM signer via gradle on the host.
# Usage: tools/interop/run-rabby.sh <dir with node_modules (keystone-sdk deps + @keystonehq/base-eth-keyring, ethers)>
set -e
MODS=$(realpath "$1"); ROOT=$(cd "$(dirname "$0")/../.." && pwd)
X=$(mktemp -d); chmod 777 "$X"; trap 'rm -rf "$X"' EXIT
gradle() { (cd "$ROOT" && COLDEVM_INTEROP_DIR="$X" ./gradlew --no-daemon -q testDebugUnitTest --tests "org.coldevm.signer.$1" --rerun); }
gradle InteropRabbyTest.writeHdKeyUr
docker run --rm --network none -v "$MODS":/m:ro -v "$ROOT/tools/interop":/s:ro -v "$X":/x -e NODE_PATH=/m/node_modules node:22-alpine node /s/rabby.js /x &
PID=$!
for n in 1 2 3 4 5 6; do
  while [ ! -f "$X/req-rabby-$n.txt" ]; do kill -0 $PID 2>/dev/null || { wait $PID; exit 1; }; sleep 1; done
  sleep 1; gradle InteropTest.signJsRequests
done
wait $PID
