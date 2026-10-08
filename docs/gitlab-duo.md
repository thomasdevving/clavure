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

## Setting it up (GitLab 19.x, Premium/Ultimate or Free with credits)

1. Push this repository to a GitLab project. For the MR storyline, make
   `main` contain everything except `demo/manifests/change-analytics/`, and
   open the developer MR that adds it.
2. **AI > Flows > New flow**: paste `flows/clavure.yaml`, visibility
   Private, then **Enable** it in the project with triggers *Mention* and
   *Assign reviewer*.
3. Protect `main`: enable "Require approval from code owners" and
   "Pipelines must succeed". Replace `@clavure-security-owners` in
   `.gitlab/CODEOWNERS` with a real group.
4. Optional: register a runner tagged `clavure-privileged` with privileged
   docker-in-docker and set `CLAVURE_RUNTIME_RUNNER=true` to enable
   `runtime:k3d`.
5. Recommended: enforce `guard:trusted-files` and `verify:trusted` through a
   pipeline execution policy so that an MR cannot remove them.

## CI (`.gitlab-ci.yml`)

| Job | When | Blocks? |
|---|---|---|
| `lint` | all | yes |
| `test:policy-parsing`, `test:k8s-semantics`, `test:graph-consistency`, `test:optimizer`, `test:remediation-verification` | all | yes |
| SAST, Secret Detection (GitLab templates) | all | per template |
| `guard:trusted-files` | MR | yes: automated identity or remediation branch touching trusted files |
| `analyze:mr` | MR | no (produces artifacts) |
| `verify:trusted` | MR | yes: target-branch verifier and requirements judge the MR |
| `runtime:k3d` | MR/default, only if `CLAVURE_RUNTIME_RUNNER=true` | yes when it runs |
| `gate:security` | MR | yes: forbidden connectivity, undecidable constraints, failed verification, guard block |
| `pipeline:model`, `gate:release` | default branch / tags | release gate blocks tags |
| `package:wheel`, `report:html` | default / all | — |
| `deploy:staging` | default branch, **manual**, protected environment | — |

The adversarial regression job from the brief is absent because that
extension is not implemented.

## Not yet demonstrated

* A genuine Duo flow execution and the MR it would create.
* Any GitLab pipeline run, including the docker-in-docker `runtime:k3d` job
  (its `CLAVURE_K3D_API_HOST` kubeconfig rewrite is implemented but untested).
* Staging deployment.
