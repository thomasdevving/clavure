# Architecture

```
            trusted inputs                        derived state                      decisions
 ┌───────────────────────────┐   ┌──────────────────────────────────┐   ┌──────────────────────────┐
 │ demo/scenario.yaml         │   │ core.policy_parser → Inventory    │   │ optimizer.solver          │
 │  required / forbidden /    │──▶│ core.reachability (3-valued)      │──▶│  actions from evidence    │
 │  workflows (CODEOWNERS)    │   │ core.security_graph (NetworkX)    │   │  hard constraints H1–H6   │
 │ manifests (git)            │──▶│ core.constraints / findings / diff│   │  cost model (ranking)     │
 └───────────────────────────┘   └──────────────────────────────────┘   └────────────┬─────────────┘
                                                                                      │ selected plan
                         ┌────────────────────────────────────────────────────────────▼──────────┐
                         │ optimizer.remediation: patch manifests (or a copy) + unified diff       │
                         └───────────────┬───────────────────────────────────────┬───────────────┘
                                         │                                       │
                  ┌──────────────────────▼─────────────────┐   ┌─────────────────▼────────────────────┐
                  │ verification.model_verifier (trusted)   │   │ verification.runtime_verifier (trusted)│
                  │  own YAML handling, compiled allow-sets │   │  runtime.cluster: dedicated k3d        │
                  │  cross-check vs engine → fail closed    │   │  canary, health, probes, workflows     │
                  └──────────────────────┬─────────────────┘   └─────────────────┬────────────────────┘
                                         └──────────────┬────────────────────────┘
                                                        ▼
                     pipeline: mismatch? → revert, read live policies (read-only), drift findings,
                               re-optimize with runtime evidence (bounded attempts) → final verdict
                                                        ▼
                     reporting: JSON artifacts + clavure-report.html      CI gate / GitLab Duo flow
```

## Components

**Security analysis engine** (`clavure/core`). `policy_parser` turns manifests
into an `Inventory` (namespaces, workloads, Services, NetworkPolicies) and
records anything it cannot model as an `UnsupportedFeature`. `reachability`
evaluates a (source, destination, port) query on each side: the source's
egress and the destination's ingress. It uses three-valued logic and returns
`ALLOWED`, `BLOCKED`, `UNKNOWN` (e.g. ipBlock vs pod IP, or namespaces with
unknown labels) or `UNSUPPORTED` (foreign policy kinds, hostNetwork). Each
side records the isolating policies and the exact permitting rules and peers,
which is the evidence everything downstream uses.

**Security graph** (`core/security_graph.py`). A NetworkX `MultiDiGraph` with
namespace, workload, Service and policy nodes. Structural edges are membership,
Service routing and policy selection. Connectivity edges carry port, protocol,
verdict, the relevant policies, the evidence and the classification
(REQUIRED / FORBIDDEN / UNDECLARED). `check_consistency` validates the graph
against the constraint evaluations.

**Constraints and findings** (`core/constraints.py`, `core/findings.py`).
Required connections are evaluated through the destination Service: service
port → targetPort, which may be named. Every backend must be reachable.
Forbidden connections with `port: any` are evaluated on every TCP port the
destination pod exposes. Findings carry evidence and an explicit L4-only scope
note.

**Permission diff** (`core/diff.py`). This compares two analyses (MR target vs.
head) and attributes each newly permitted connection to the rules that now
permit it.

**Remediation optimizer** (`clavure/optimizer`). See
[optimization.md](optimization.md).

**Independent verifier** and **runtime verifier** (`clavure/verification`).
See [verification.md](verification.md).

**Closed loop** (`pipeline.py`). Stages are recorded as EXECUTED / SKIPPED /
FAILED. The final verdict is `REMEDIATION_VERIFIED` only when the model
constraints, the runtime connectivity checks and the business workflows all
pass after the remediation. Without a cluster the best possible verdict is
`MODEL_VERIFIED_ONLY`.

**GitLab integration** (`mrcheck.py`, `flows/clavure.yaml`, `.gitlab-ci.yml`).
See [gitlab-duo.md](gitlab-duo.md).

## The five kinds of state, kept apart

| | Where | Written by |
|---|---|---|
| Declared security requirements | `demo/scenario.yaml` | humans (CODEOWNERS); never by Clavure or agents |
| Modelled reachability | `reachability.json` | engine |
| Observed runtime behaviour | `verification-report.json#runtime` | runtime verifier |
| Verified violations | `verification-report.json#verified_violations` | runtime verifier |
| Proposed remediations | `remediation-plan.json` | optimizer |

Observations never become requirements. When runtime and model disagree, the
disagreement is reported as `MODEL_MISMATCH`, and Clavure re-reads the live
state (read-only) to explain it instead of trusting either side.

## Extension points

* New policy systems: add a parser in `core/policy_parser.py`, which today
  reports foreign policy kinds as UNSUPPORTED, and a matching evaluator.
  The optimizer depends only on `Connection` evidence (permitting rule
  references) and the action interface in `optimizer/actions.py`.
* New remediation actions: subclass `Action` (define `touches`, `describe`
  and `apply` on a `PlanState`) and register it in `ACTION_TYPES`.
