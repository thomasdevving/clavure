# Three-minute demo

Everything shown is produced live by the commands below. The recorded outputs
of real runs are in `docs/evidence/` as a fallback if the cluster cannot be
created during a presentation; present those as recordings, with their
timestamps.

## Prepare (before the talk, ~2 min)

```bash
. .venv/bin/activate
scripts/build-demo-image.sh
clavure cluster up
```

## Script

| t | Show | Command / artifact |
|---|---|---|
| 0:00 | The developer change: reporting gets order-data access, but the selector is `tier: data` | `demo/manifests/change-analytics/30-reporting-data-access.yaml` |
| 0:20 | Clavure detects the permission expansion from the manifests | `clavure diff --before demo/manifests/base --after demo/manifests/base demo/manifests/change-analytics --scenario demo/scenario.yaml` → CRITICAL: newly permits reporting → finance-db:5432 |
| 0:40 | Start the closed loop on the real cluster | `clavure pipeline --runtime --keep-cluster --scenario demo/scenario.yaml --baseline demo/manifests/base --proposed demo/manifests/base demo/manifests/change-analytics --out artifacts` (~2.5 min, so start it here) |
| 0:50 | While it runs: the trade-off space | report section 5: coarse fixes rejected (blocking finance-db ingress breaks checkout payments; quarantining reporting breaks reporting); P-001 selected at cost 22 |
| 1:30 | Runtime evidence, before | report section 3: canary proves enforcement; probe from the real reporting pod reaches finance-db and the database answers `PONG` |
| 2:00 | After | report section 6: forbidden connection BLOCKED; all required connections and both business workflows PASS; independent verifier PASS |
| 2:30 | The GitLab path | `flows/clavure.yaml` (agents only run pinned `clavure`/`git`), `guard:trusted-files`, `verify:trusted` (target-branch verifier) |
| 2:50 | Honesty slide | Duo flow and GitLab CI not yet executed; adversarial extension not implemented |

Optional, if time allows: the drift run (`--inject-drift demo/drift/legacy-finance-export.yaml`).
It shows a remediation that is correct for the git model failing at
runtime, followed by MODEL_MISMATCH → live re-ingestion → a different plan →
verified.

## Cleanup

```bash
clavure cluster down
```
