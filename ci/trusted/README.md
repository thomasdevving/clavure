# Trusted CI configuration

Clavure's merge-request decision must not be changeable by the merge request
it judges. Two things have to be trusted:

1. **The job definitions**, i.e. which jobs run and with which scripts.
2. **The code and data those jobs use**: Clavure itself, the requirements
   (`demo/scenario.yaml`), the trusted-file list and manifest roots
   (`.clavure.yaml`).

(2) is handled inside the jobs, in every mode. `jobs.yml` builds Clavure from
the protected **default branch** (`origin/$CI_DEFAULT_BRANCH`), never from the
MR and never from the MR's *target* branch, which may be unprotected. Only
the manifests under test come from the MR. Locally executed proof:
`tests/integration/test_ci_jobs_local.py` (an MR that patches `guard.py` and
weakens the requirements is still blocked).

(1) depends on where the job definitions are loaded from:

| Mode | Tier | Job definitions | MR can change the gate? |
|---|---|---|---|
| Development: `.gitlab-ci.yml` includes `ci/trusted/pipeline.yml` | any | MR branch | **yes** (not enforced) |
| **External CI config file** in a protected project | **Free, Premium, Ultimate** | `ci/trusted/pipeline.yml@<group>/clavure-ci` | no |
| **Pipeline execution policy** (`inject_policy`) | **Ultimate** | `ci/trusted/policy-pipeline.yml` in the policy's CI project | no, and stronger (see below) |

## Recommended setup by tier

### Free or Premium: external CI configuration file

1. Create a project `<group>/clavure-ci`. Copy `ci/trusted/` into it at the
   same path (`ci/trusted/pipeline.yml`, `ci/trusted/jobs.yml`). Give write
   access only to security owners, and protect its default branch.
2. In the application project, open **Settings > CI/CD > General pipelines >
   CI/CD configuration file** and set it to
   `ci/trusted/pipeline.yml@<group>/clavure-ci`. GitLab now ignores the
   project's own `.gitlab-ci.yml`. `include: local` inside the trusted file
   resolves in `clavure-ci`, because GitLab evaluates includes relative to the
   file that contains them. Changing this setting needs the Maintainer role.
3. **Settings > Merge requests > Merge checks**: enable **Pipelines must
   succeed**, and keep **Skipped pipelines are considered successful** OFF.
   With that, a pipeline skipped with `[skip ci]`, or a missing pipeline,
   blocks the merge.
4. **Settings > CI/CD > Variables > Minimum role to use pipeline variables**:
   `no_one_allowed` (the GitLab.com default for new projects in new
   namespaces). Otherwise `git push -o ci.variable=...` or a manual pipeline
   could override job variables.
5. Protect the default branch. Protect tags if tag pipelines are used for
   releases.
6. Add the Duo flow service account as **Developer** only, so it cannot
   change any of the settings above.
7. Premium only: enable **Require approval from code owners** on the
   protected branch (CODEOWNERS covers `ci/`, the requirements and the
   verifiers). Make `staging` a **protected environment**, optionally with
   **deployment approvals**.

Residual risk on Free: Maintainers and Owners can change the CI configuration
file setting, and on Free, merge approvals are not enforced. Treat those roles
as part of the trusted computing base.

### Ultimate: pipeline execution policy

Do everything above, and additionally link a security policy project with
`ci/trusted/security-policy.yml` as `.gitlab/security-policies/policy.yml`
(edit the project path and project ID). With `inject_policy`:

* policy jobs run from an isolated YAML; project CI cannot override them;
* jobs in `.pipeline-policy-pre` always run; if they fail, every later job is
  skipped, including the project's own deployment jobs and jobs with
  `needs: []` or `when: always`;
* `skip_ci` and `no_pipeline` are disallowed, and `variables_override` is
  disabled.

## What the pipeline enforces (`pipeline.yml`)

| Job | Pipelines | Decides | Code it runs |
|---|---|---|---|
| `lint`, `test:*`, `package:wheel`, `report:html` | MR / default | nothing security-relevant | the MR's |
| `clavure:security-gate:mr` | MR | guard + independent verification + gate | default branch |
| `clavure:security-gate:branch` | default branch, tags | gate; writes `gate-passed.json` | default branch |
| `clavure:runtime:k3d` | MR / default, with `CLAVURE_RUNTIME_RUNNER=true` and a runner tagged `clavure-privileged` | runtime gate | default branch (including the probe image) |
| `deploy:staging` | default branch, **manual** | — | `needs` the branch gate, and re-checks that `gate-passed.json` matches this commit and pipeline before calling kubectl |

The gate blocks forbidden connectivity, regressions of required connections,
new undeclared connectivity, structural errors, engine/verifier disagreement,
and the trusted-file guard. A required connection that was already unmet
before the change is reported but does not block unrelated changes.

## Supply chain

* Images are pinned by digest: `python:3.12`, `docker:27.5.1-dind`,
  `k3d-tools`, `k3s`, and the Dockerfile bases.
* k3d and kubectl are verified against their vendors' published SHA-256.
  The static Docker CLI has no vendor checksum; its SHA-256 was recorded at
  pin time (trust on first use).
* Python packages are installed with `--require-hashes`, and the build
  backend is pinned (`requirements-build.lock`).
