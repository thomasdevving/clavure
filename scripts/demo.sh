#!/usr/bin/env bash
# Clavure end-to-end demo.
#   scripts/demo.sh            model-only (no cluster)
#   scripts/demo.sh --runtime  full closed loop on a disposable k3d cluster
#   scripts/demo.sh --runtime --drift   ... plus the drift fault injection run
set -euo pipefail
cd "$(dirname "$0")/.."

RUNTIME=""; DRIFT=""
for a in "$@"; do
  case "$a" in
    --runtime) RUNTIME="--runtime" ;;
    --drift) DRIFT=1 ;;
    *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done

SCENARIO=demo/scenario.yaml
BASE=demo/manifests/base
CHANGE=demo/manifests/change-analytics

echo "== 1. Permission change introduced by the developer change"
clavure diff --before "$BASE" --after "$BASE" "$CHANGE" --scenario "$SCENARIO" --out artifacts/permission-diff.json

echo "== 2. Security graph and findings"
clavure analyze --manifests "$BASE" "$CHANGE" --scenario "$SCENARIO" --out artifacts

echo "== 3. Remediation candidates"
clavure optimize --manifests "$BASE" "$CHANGE" --scenario "$SCENARIO" --out artifacts/remediation-plan.json --render-dir artifacts/remediated-manifests --show 10

echo "== 4. Closed loop ${RUNTIME:-(model only)}"
if [ -n "$RUNTIME" ]; then scripts/build-demo-image.sh >/dev/null; fi
clavure pipeline $RUNTIME --scenario "$SCENARIO" --baseline "$BASE" --proposed "$BASE" "$CHANGE" --out artifacts || true

if [ -n "$DRIFT" ] && [ -n "$RUNTIME" ]; then
  echo "== 5. Feedback loop with documented drift fault injection"
  clavure pipeline --runtime --inject-drift demo/drift/legacy-finance-export.yaml \
    --scenario "$SCENARIO" --baseline "$BASE" --proposed "$BASE" "$CHANGE" --out artifacts-drift || true
fi
echo "Report: artifacts/clavure-report.html"
