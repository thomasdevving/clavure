# GitLab Duo flow and CI

**Status: implemented, not executed.** The build environment had no GitLab
project, runner, or Duo Agent Platform access. The flow and CI configuration
were written against GitLab's documentation and the Duo Workflow Service
source as of 2026-10-08:

* `doc/user/duo_agent_platform/flows/custom.md` and `custom_flows_schema.md`
* ai-assist `docs/flow_registry/v1.md` (structure, routers, Tool Options)
* ai-assist `duo_workflow_service/tools/*.py` (exact tool `name` values)
* `doc/user/duo_agent_platform/triggers/_index.md`
* `doc/user/duo_agent_platform/flows/execution/agent-config-yaml.md`

`tests/unit/test_flow_config.py` statically checks the flow against those
rules. Only a real GitLab instance can confirm that GitLab accepts it.

## The flow (`flows/clavure.yaml`)

```
clavure_analyst ──REMEDIATION_AVAILABLE──▶ clavure_implementer ──IMPLEMENTED──▶ clavure_publisher ─▶ clavure_reporter ─▶ end
        └──────────────── any other token ───────────────┴──────── FAILED ─────────────────────────────▲
```

| Component | Runs | Tools |
|---|---|---|
| analyst | `clavure mr-check --target-ref origin/<target> --fetch --out artifacts/duo`, routes on `CLAVURE_RESULT=` | `get_merge_request`, `list_merge_request_diffs`, `read_file`, `run_command` pinned to `clavure` |
| implementer | `clavure apply-remediation --plan artifacts/duo/remediation-plan.json --verify` | `read_file`, `run_command` pinned to `clavure` |
| publisher | `git checkout -b clavure/remediation-<iid>`, commit manifests only, push; `create_merge_request` with `artifacts/duo/mr-description.md` | `read_file`, `get_merge_request`, `create_merge_request`, `run_command` pinned to `git` |
| reporter | posts `artifacts/duo/summary.md` on the triggering MR | `read_file`, `get_merge_request`, `create_merge_request_note` |

Design choices:
* **The agents decide nothing security-relevant.** Every result token comes
  from the deterministic Clavure CLI.
* **Tool Options** pin `run_command`'s `program` per component. The docs
  state that options override LLM-provided values, and tool instances are
  cloned per component.
* **No file-writing tools** (`edit_file`, `create_file_with_contents`) are
  in any component.
* `run_git_command` is deprecated upstream in favour of `run_command` with
  `program="git"`, so the flow uses the latter.
* **Triggers are human actions only**: a *Mention* or *Assign reviewer* of
  the flow service account. GitLab documents that non-human users cannot
  trigger flows, so the flow cannot loop on itself.
* `.gitlab/duo/agent-config.yml` installs Clavure from pinned dependencies.
  The agent environment receives **no cluster credentials**; runtime
  verification happens in CI.

## Repository layout for the demonstration

| Branch | Content | Purpose |
|---|---|---|
| `baseline` | Clavure + the secure demo application; the unsafe change only as a fixture under `demo/changes/` | becomes the GitLab project's protected default branch (`main`) |
| `demo/unsafe-networkpolicy` | `baseline` + `demo/manifests/analytics-access/30-reporting-data-access.yaml` (one file) | source branch of the demonstration merge request |

On the baseline, `REQ-REPORTING-ORDERS` is intentionally unmet: the reporting
feature is what the demonstration MR implements. The security gate reports it
as a pre-existing gap and does not block on it (see `ci/trusted/README.md`).

## Setting it up (GitLab 19.x)

Tier notes from GitLab's documentation:
* Custom flows: Free (with GitLab Credits on GitLab.com), Premium, Ultimate.
* Flow triggers (mention, assign reviewer): **Premium, Ultimate**.
* External CI configuration file: all tiers. Pipeline execution policies:
  Ultimate. Code-owner approval and protected environments: Premium+.

1. Create the GitLab project and push `baseline` as `main`, then
   `demo/unsafe-networkpolicy`. Protect `main`.
2. Enforce the CI configuration (`ci/trusted/README.md`): create the protected
   `<group>/clavure-ci` project with a copy of `ci/trusted/`, set the CI/CD
   configuration file to `ci/trusted/pipeline.yml@<group>/clavure-ci`,
   enable **Pipelines must succeed** (skipped pipelines not successful), and
   set **Minimum role to use pipeline variables** to `no_one_allowed`.
   Ultimate: add the pipeline execution policy as well.
3. Premium+: enable **Require approval from code owners** and replace
   `@clavure-security-owners` in `.gitlab/CODEOWNERS` with a real group.
4. **AI > Flows > New flow**: paste `flows/clavure.yaml`, visibility
   Private. **Enable** it in the project with triggers *Mention* and
   *Assign reviewer*. The service account `ai-<flow>-<group>` is added as
   Developer.
5. Open the MR `demo/unsafe-networkpolicy` → `main`. Expected:
   `clavure:security-gate:mr` fails with `FORBID-REPORTING-FINANCEDB`.
6. Mention the flow service account on the MR. Expected: the flow opens
   `clavure/remediation-<iid>` → `demo/unsafe-networkpolicy`, whose
   pipeline passes. Merging it into the demo branch makes the demo MR's
   pipeline pass.
7. Optional: register a runner tagged `clavure-privileged` (privileged
   docker-in-docker) and set the project variable `CLAVURE_RUNTIME_RUNNER=true`
   to run `clavure:runtime:k3d`.

## CI

Defined in `ci/trusted/pipeline.yml` (the root `.gitlab-ci.yml` only includes
it); strategy and job table in [`ci/trusted/README.md`](../ci/trusted/README.md).

What has been executed (locally, **not** on GitLab):
`tests/integration/test_ci_jobs_local.py` takes the job definitions as
GitLab composes them and runs their scripts in the digest-pinned job image
against a simulated repository:

* `clavure:security-gate:mr` blocks the demo MR, passes the remediation MR,
  and blocks a tampering MR that patches `guard.py` and weakens the
  requirements;
* `clavure:security-gate:branch` passes on the baseline and refuses an
  unprotected ref;
* `deploy:staging` refuses without a gate record for the same commit and
  pipeline, and with one it deploys to a local disposable k3d "staging"
  cluster;
* `clavure:runtime:k3d` runs with the host Docker daemon standing in for
  the dind service: checksum-verified tools, real cluster, correct verdicts.

`tests/unit/test_ci_config.py` checks the composed configuration for every
pipeline type (MR, default branch with and without staging, tags, runtime
runner): `needs` consistency, digest pinning, checksum verification,
hash-checked installs, and default-branch tooling in security jobs.

## What requires GitLab access (not possible from this environment)

| Step | Needs |
|---|---|
| Create the project, push `baseline` as `main` and the demo branch | GitLab account; token with `api` + `write_repository` (or SSH); your authorization to push to a new remote |
| Protect `main`, Pipelines must succeed, pipeline-variable role, CI configuration file path | **Maintainer** (pipeline-variable setting at `no_one_allowed`: **Owner**) on the project |
| Create `<group>/clavure-ci` and restrict write access | permission to create projects in the group; Maintainer/Owner there |
| Code-owner approvals, protected `staging` environment, deployment approvals | **Premium or Ultimate**; Maintainer |
| Pipeline execution policy | **Ultimate**; Owner/Maintainer of the group to link a security policy project |
| Create and enable the custom flow, add triggers | GitLab Duo Agent Platform turned on; **Maintainer**; custom flows allowed by a group Owner; triggers need **Premium/Ultimate**; GitLab Credits |
| Trigger the flow (mention / assign reviewer) | a **human** user with Developer+ (non-human users cannot trigger flows) |
| Run the pipelines | GitLab.com shared runners or your own runner (`python:3.12` image, network access to PyPI, dl.k8s.io, GitHub releases, download.docker.com) |
| `clavure:runtime:k3d` | a runner tagged `clavure-privileged` with **privileged** docker-in-docker; project variable `CLAVURE_RUNTIME_RUNNER=true` |
| `deploy:staging` | a reachable staging cluster; masked/protected variable `STAGING_KUBECONFIG` (file type); explicit approval to deploy |

## Not yet demonstrated

* A genuine Duo flow execution and the MR it would create.
* Any pipeline run on GitLab: workflow and rule evaluation by GitLab itself,
  the GitLab-managed SAST/Secret Detection templates, artifacts and `needs`
  across real jobs, and the dind service networking (`CLAVURE_K3D_API_HOST`).
* A deployment to any environment other than the local disposable cluster.
