# Security model

Clavure is defensive tooling. It analyses declared infrastructure, tests it
only in a disposable cluster that it creates itself, and proposes changes
for human review.

## Trust boundaries

| Component | Trust | Holds | Never |
|---|---|---|---|
| `clavure.core`, `clavure.verification` | trusted, deterministic | manifests, requirements | executes LLM output |
| `clavure.runtime` (cluster controller) | privileged | its own kubeconfig in `.clavure/` | touches `~/.kube/config` or the current context; acts outside the test namespaces |
| Demo workloads / probe commands | restricted | no Kubernetes API token (`automountServiceAccountToken: false`), non-root, read-only root FS, all capabilities dropped, resource limits | receive controller credentials |
| GitLab Duo flow agents | untrusted orchestrators | `run_command` pinned to `clavure` or `git`; no file-editing tools; Developer role | decide security outcomes; change requirements, verifiers, tests or CI (blocked by guard + CODEOWNERS) |
| Merge request under review | untrusted | — | provide the code, requirements or trusted-file list that judge it (security jobs build Clavure from the protected default branch) |

## Runtime safety

* **Dedicated cluster only.** `ClusterController.verify_identity` checks that
  every API-server node is a k3d node of *this* cluster before use.
* **Scoped mutations.** `runtime.kube.Kube` refuses any object outside the
  namespaces listed in the requirements file. Those namespaces must also carry
  `clavure.io/test-env=true` in the live cluster. Cluster-scoped objects other
  than those namespaces are refused.
* **No external targets.** Probes go only to in-cluster Service names and pod
  IPs derived from the deployed manifests.
* **Timeouts and limits** on every kubectl call, probe (3 s), exec (≤ 40 s) and
  pod.
* **Synthetic data only.** The demo databases are in-memory emulators seeded
  with synthetic records.
* **Fault injection is explicit.** Drift is applied only with
  `--inject-drift`, is recorded as a `fault-injection:drift-applied` event,
  and is documented in `demo/drift/`.

## Evaluation integrity

* The requirements file is fingerprinted (`requirements_fingerprint` in every
  artifact).
* Hard constraints (H1–H6) are filters and are never weighted against cost.
  One of them (H5) forbids any new connectivity except explicitly required
  connections, so previously confirmed safety cannot be traded away.
* The model verifier shares no code with the engine. Any disagreement fails
  verification (`cross_check`).
* `apply-remediation --verify` rolls back the files if independent verification
  fails.
* In CI, every security-deciding job installs Clavure, the requirements and the
  trusted-file list from the protected **default branch**. It never uses the
  MR or the MR's *target* branch, which may be unprotected (the Duo flow's
  remediation MRs target the developer's branch). The target branch is used
  only as the comparison baseline.
* The gate blocks forbidden connectivity and regressions. A required
  connection that was already unmet before the change is reported, not
  blocking.

## What protects trusted files (layers)

1. Agents have no file-writing tools, and `run_command` is pinned per
   component.
2. The guard (in `clavure:security-gate:mr`, run with default-branch code
   and the default branch's trusted-file list) fails any MR authored by an
   automated identity (`^ai-`, project/group bots) or on a
   `clavure/remediation-*` branch that touches trusted paths.
3. `.gitlab/CODEOWNERS` requires security owners to approve changes to trusted
   paths. This needs "Require approval from code owners" on the protected
   default branch.
4. Verification uses default-branch code, so weakening the verifier or the
   requirements in the MR, or on its target branch, has no effect on the MR's
   verdict. This was executed locally in `tests/integration/test_ci_jobs_local.py`.
5. The job definitions themselves are enforced by loading them from outside
   the MR: an external CI configuration file in a protected project (all
   tiers) or a pipeline execution policy (Ultimate). Add "Pipelines must
   succeed" and set the pipeline-variable role to `no_one_allowed`. In
   development mode (the root `.gitlab-ci.yml`) an MR can still edit the
   pipeline; see [`ci/trusted/README.md`](../ci/trusted/README.md).
   Instructions to agents are not treated as a boundary.

## Not claimed

* Network reachability is not application authorization or exploitability.
  Findings say so explicitly.
* Multi-hop pivots are not modelled. Only direct forbidden connectivity is
  analysed.
