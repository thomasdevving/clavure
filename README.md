# Clavure

**What is the least disruptive security change that eliminates an identified
exposure while preserving essential business functionality?**

Clavure answers that question for Kubernetes NetworkPolicies. It derives
effective connectivity from real manifests, finds connections that violate
declared security requirements, searches for the cheapest remediation that
satisfies *every* hard constraint, verifies the result with an independently
written checker and in a disposable k3d cluster, and prepares the change for
review through GitLab CI and a GitLab Duo Agent Platform flow.

> The optimizer determines what should change. The verifiers determine what has
> actually been demonstrated. GitLab Duo orchestrates. No LLM is the authority
> on security correctness.

Built for the GitLab *Life After Code* hackathon (Path A, supervised).

## Status

| Area | Status | Evidence |
|---|---|---|
| NetworkPolicy parser, three-valued semantics engine, security graph, findings, permission diff | **IMPLEMENTED, TESTED** | 55+ unit tests, `tests/unit/test_semantics.py` |
| Independent model verifier (separate code + algorithm) | **IMPLEMENTED, TESTED** | 400-world randomized differential test vs. the engine, mutation-checked |
| Remediation optimizer (bounded exhaustive search, hard constraints H1–H6, cost model) | **IMPLEMENTED, TESTED** | `tests/unit/test_optimizer.py` |
| Runtime verification on disposable k3d (canary, health, probes, workflows) | **IMPLEMENTED, TESTED on a real cluster** | `docs/evidence/run-clean/` |
| Model-mismatch feedback loop (drift re-ingestion, re-optimization) | **IMPLEMENTED, TESTED on a real cluster** | `docs/evidence/run-drift/` |
| HTML report | **IMPLEMENTED, TESTED** | `docs/evidence/*/clavure-report.html` |
| Trusted-file guard, target-branch verification, CI gate | **IMPLEMENTED, TESTED locally** (git simulation) | `tests/unit/test_guard_gate.py` |
| `.gitlab-ci.yml` | **IMPLEMENTED, NOT TESTED** on GitLab (no GitLab project or runner available in the build environment) | — |
| GitLab Duo custom flow `flows/clavure.yaml` | **IMPLEMENTED, NOT EXECUTED** (schema and tool names checked against GitLab's docs and source; requires a GitLab instance with Duo Agent Platform) | `tests/unit/test_flow_config.py` |
| `runtime:k3d` CI job on docker-in-docker | **NOT TESTED** | — |
| Staging deployment job | **NOT TESTED** (manual, protected; no staging cluster) | — |
| Adversarial agent extension (milestone 4) | **NOT IMPLEMENTED** in this build | `adversarial-results.json` reports `NOT_IMPLEMENTED` |
| Application-level RBAC demonstration | **NOT IMPLEMENTED** (optional, depended on milestone 4) | — |

## Quick start

```bash
uv venv --python 3.12 .venv && . .venv/bin/activate
uv pip install -r requirements-dev.lock && uv pip install --no-deps -e .
pytest -q                                   # unit tests (runtime tests are skipped)

# Model-only closed loop on the demo (no cluster needed)
clavure pipeline --scenario demo/scenario.yaml \
  --baseline demo/manifests/base \
  --proposed demo/manifests/base demo/manifests/change-analytics \
  --out artifacts
open artifacts/clavure-report.html          # verdict: MODEL_VERIFIED_ONLY
```

Full runtime loop (needs Docker, `k3d` ≥ 5.7, `kubectl`; see
[docs/runtime-environment.md](docs/runtime-environment.md)):

```bash
scripts/build-demo-image.sh
clavure pipeline --runtime --scenario demo/scenario.yaml \
  --baseline demo/manifests/base \
  --proposed demo/manifests/base demo/manifests/change-analytics \
  --out artifacts                            # verdict: REMEDIATION_VERIFIED
# Feedback-loop demonstration with documented fault injection:
clavure pipeline --runtime --inject-drift demo/drift/legacy-finance-export.yaml ... --out artifacts-drift
```

Clavure creates its own cluster (`clavure-test`) and kubeconfig under
`.clavure/`; it never reads or changes `~/.kube/config` or your current context.

## CLI

| Command | Purpose |
|---|---|
| `clavure analyze --manifests … --scenario …` | `topology.json`, `reachability.json`, `security-findings.json` |
| `clavure diff --before … --after …` | permission changes introduced by a change |
| `clavure optimize --manifests … [--render-dir D]` | `remediation-plan.json` with every evaluated candidate |
| `clavure verify-model --manifests … [--baseline …]` | independent verification + engine cross-check |
| `clavure apply-remediation --plan P [--verify]` | apply the selected plan in place; roll back if verification fails |
| `clavure mr-check --target-ref origin/main [--runtime]` | everything above for a merge request; prints `CLAVURE_RESULT=…` |
| `clavure guard --base-ref SHA` | block automated changes to trusted files |
| `clavure gate --artifacts D` | CI security gate |
| `clavure pipeline … [--runtime] [--inject-drift F]` | closed loop; writes all artifacts and `clavure-report.html` |
| `clavure cluster up\|down\|status` | dedicated disposable k3d cluster |
| `clavure report --artifacts D` | re-render the HTML report from artifacts |

## The demo

Six synthetic services in three namespaces (`clavure-shop`, `clavure-data`,
`clavure-analytics`) with default-deny baselines. A developer change
(`demo/manifests/change-analytics/`) gives the reporting service the order data
it needs but selects `tier: data`, which also matches `finance-db`. Because
NetworkPolicies are additive, reporting can now reach the finance database.
Clavure derives this from the manifests (nothing in the engine knows about the
demo), reproduces it in k3d, rejects coarse fixes that break checkout or
reporting, selects a one-line selector narrowing, and verifies it in the model
and at runtime. See [docs/demo.md](docs/demo.md) for the three-minute script.

## Documentation

* [Architecture](docs/architecture.md)
* [Security model and trust boundaries](docs/security-model.md)
* [Optimization](docs/optimization.md)
* [Verification (model, runtime, feedback loop)](docs/verification.md)
* [Adversarial verification (status)](docs/adversarial-verification.md)
* [GitLab Duo flow and CI](docs/gitlab-duo.md)
* [Runtime environment](docs/runtime-environment.md)
* [Demo script](docs/demo.md)
* [Limitations](docs/limitations.md)
* [Recorded evidence](docs/evidence/README.md)

## Repository layout

```
clavure/
  core/            parser, models, reachability engine, constraints, findings, graph, diff, drift
  optimizer/       actions, candidate generation, solver, cost model, selectors, rendering
  verification/    independent model verifier, runtime verifier, evidence, guard, gate, trusted_ci
  runtime/         k3d cluster controller, scoped kubectl wrapper, test environment
  reporting/       artifact serialization, HTML report generator and template
  pipeline.py      closed-loop orchestration     mrcheck.py   merge-request check
demo/              scenario (trusted requirements), manifests, change, drift fixture, demo app
flows/clavure.yaml GitLab Duo custom flow
.gitlab/           CODEOWNERS, Duo agent-config.yml
tests/             unit tests; integration tests (real k3d, opt-in)
docs/              documentation and recorded evidence
```

## License

MIT. See [LICENSE](LICENSE). One configuration file derived from K3s remains
Apache-2.0; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
