# Recorded runtime evidence

These directories are the **unmodified JSON artifacts** of two real pipeline runs
executed on 2026-10-08 in a disposable k3d cluster (K3s v1.34.1, embedded
kube-router NetworkPolicy controller), inside the Claude Code cloud sandbox used
to build Clavure. `clavure-report.html` in each directory was re-rendered from
those same JSON files after a layout change to the report template; no JSON
content was edited.

| Run | Command | Final verdict |
|---|---|---|
| `run-clean/` | `clavure pipeline --runtime --scenario demo/scenario.yaml --baseline demo/manifests/base --proposed demo/manifests/base demo/manifests/change-analytics` | `REMEDIATION_VERIFIED` |
| `run-drift/` | same, plus `--inject-drift demo/drift/legacy-finance-export.yaml` (documented fault injection) | `REMEDIATION_VERIFIED` after 2 attempts |

What to look at:

* `verification-report.json` → `stages` (timeline), `runtime[*].checks` (expected vs.
  observed per constraint), `runtime[*].probes` (every probe with timestamp, the pod it
  ran in, the raw result and its interpretation), `runtime[*].preflight.canary` (proof
  that NetworkPolicy enforcement was active).
* `run-drift/verification-report.json` → `runtime[1].mismatches` (model predicted
  BLOCKED, runtime observed ALLOWED), `drift_findings`, and `repair_attempts` showing
  the optimizer selecting a different plan after live state was re-ingested.
* `remediation-plan.json` → every evaluated candidate with hard-constraint results
  and costs.

Environment notes: the sandbox required `CLAVURE_K3S_CA_BUNDLE` (TLS-intercepting
egress proxy), `CLAVURE_K3S_RESTRICT_OOM=1` (no `CAP_SYS_RESOURCE`) and
`K3D_IMAGE_TOOLS=rancher/k3d-tools:latest` (ghcr.io blocked). See
[`docs/runtime-environment.md`](../runtime-environment.md).

`adversarial-results.json` reports `NOT_IMPLEMENTED`: the adversarial extension
is not part of this build and no adversarial results exist.
