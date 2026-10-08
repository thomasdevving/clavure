# Verification

Two independent layers decide what has actually been demonstrated.

## A. Deterministic model verification (`verification/model_verifier.py`)

* **Independent implementation.** The verifier does not import
  `clavure.core` or `clavure.optimizer`. It parses the raw YAML itself and
  *compiles* each pod's ingress and egress allow-sets (peer sets plus port
  specs), then answers queries by set membership. The engine instead walks the
  policies for each query.
* **Checks.** It evaluates every required and forbidden constraint as PASS /
  FAIL / INCONCLUSIVE / UNSUPPORTED, validates the structure of every
  NetworkPolicy, and with `--baseline` lists every connection that becomes
  possible but is not declared as required ("no new connectivity").
* **Cross-check.** `cross_check` compares every observed verdict with the
  engine's verdict, and any disagreement fails verification.
* **Assurance.** `tests/unit/test_differential.py` runs both implementations
  on 400 seeded random worlds (selectors, matchExpressions, AND/OR peers,
  namespaces with unknown labels, ipBlock, named/ranged/UDP ports, implicit
  policyTypes) and requires agreement on every connection. Injecting a bug
  into the verifier (OR instead of AND for namespace+pod peers, or ignoring
  `endPort`) makes 125 and 26 worlds fail respectively, so the test has real
  power.

Remediations are verified **on the rendered files**, not on in-memory
objects: the optimizer's output is written to disk and the verifier reads it
back.

## B. Runtime verification (`verification/runtime_verifier.py`)

All runtime verification runs in a dedicated k3d cluster
(`runtime/cluster.py`), with the steps below.

1. **Preflight.** Cluster identity is checked: the nodes must belong to this
   k3d cluster. The k3s node arguments must not disable the NetworkPolicy
   controller. An **enforcement canary** in `clavure-canary` must show
   allowed → denied after a deny policy → allowed again after deleting it.
   On K3s/kube-router a blocked connection is *refused* (REJECT), which looks
   the same as "no listener", so these proofs are required.
2. **Health.** Every target pod is Ready, its Service has ready endpoints, and
   every port is checked from *inside the target pod* on 127.0.0.1, which
   proves the listener exists independently of policy.
3. **Probes from the real source workload pods.** Required connections are
   probed through Service DNS. Forbidden `port: any` connections are probed on
   every TCP port of the destination pod, both directly by pod IP and through
   any Service port that maps to it. Each probe sends `PING` and records the
   application's answer, so a successful forbidden connection shows the
   database actually answered.
4. **Interpretation.** CONNECTED → ALLOWED. REFUSED, TIMEOUT, RESET or
   UNREACHABLE → BLOCKED *only if* the target is healthy and enforcement is
   confirmed; otherwise INCONCLUSIVE. DNS errors and probe errors →
   INCONCLUSIVE, never BLOCKED.
5. **Settling.** Probe rounds repeat until two consecutive rounds agree (at
   most 5), so propagation delays are not mistaken for results. All samples
   are kept as evidence.
6. **Business workflows.** `WF-CHECKOUT` posts a checkout through the
   storefront with a fresh correlation ID, then confirms the order record
   in orders-db and the ledger entry in finance-db by querying them from
   inside their pods. `WF-REPORTING` requests a report.
7. **Model comparison.** Each probe is compared with the model's prediction
   for the deployed state, and differences are recorded as `MODEL_MISMATCH`.

## Feedback loop (`pipeline.py`)

When a remediation fails at runtime or shows a mismatch:

1. The plan is reverted, restoring exactly the touched policies.
2. The live NetworkPolicies are read (read-only) and compared with the
   manifests (`core/drift.py`). Differences become `CONFIGURATION_DRIFT`
   findings. Live objects refine the model of the current state; they never
   become requirements.
3. Clavure checks whether the refreshed model explains the observation. If it
   does not, the edge is marked as contradicted (hard constraint H6) and the
   model's BLOCKED prediction is no longer trusted for it.
4. The optimizer re-plans, bounded by `--max-repair-attempts`, default 3.
   If no candidate satisfies all constraints, the verdict is
   `NO_VALID_REMEDIATION`.

A remediation is reported as successful only when (1) the model constraints
are satisfied, (2) the runtime connectivity checks pass, and (3) the business
workflows pass.

## Recorded results

See [evidence/README.md](evidence/README.md). Both real runs used K3s v1.34.1;
the enforcement canary was confirmed each time.

| Run | Phase | Outcome |
|---|---|---|
| clean | baseline (change deployed) | FAIL: `FORBID-REPORTING-FINANCEDB` observed ALLOWED (finance-db answered `PONG`) |
| clean | after P-001 | PASS: all 8 constraints, both workflows, 0 mismatches |
| drift | after attempt 1 | FAIL: MODEL_MISMATCH (model BLOCKED, observed ALLOWED) |
| drift | feedback | drift finding `legacy-finance-export`; mismatch explained |
| drift | after attempt 2 (egress narrowing) | PASS |
