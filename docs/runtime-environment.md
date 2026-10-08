# Runtime environment

## Requirements

* Docker (daemon running), [k3d](https://k3d.io) v5.7+, kubectl v1.31+
* The demo image: `scripts/build-demo-image.sh` builds `clavure-demo:0.1.0`
  locally. The image is imported straight into the node's containerd; no
  registry is involved.

```bash
clavure cluster up       # creates k3d cluster "clavure-test" (K3s v1.34.1)
clavure cluster status
clavure cluster down
```

Clavure writes its kubeconfig to `.clavure/kubeconfig-<name>.yaml` (mode 0600).
It passes it explicitly to every kubectl call and never modifies
`~/.kube/config` or the current context.

## Environment variables

| Variable | Purpose |
|---|---|
| `CLAVURE_K3S_IMAGE` | k3s image (default `rancher/k3s:v1.34.1-k3s1`) |
| `CLAVURE_K3S_CA_BUNDLE` | CA bundle mounted as the node trust store, for TLS-intercepting egress proxies |
| `CLAVURE_K3S_RESTRICT_OOM=1` | install a containerd template with `restrict_oom_score_adj = true`, for nested sandboxes without `CAP_SYS_RESOURCE` |
| `CLAVURE_K3D_API_HOST` | host under which the k3d API is reachable (e.g. `docker` in GitLab docker-in-docker); adds a TLS SAN and rewrites the kubeconfig |
| `K3D_IMAGE_TOOLS` | k3d helper image override, passed through to k3d |
| `CLAVURE_BASE_IMAGE` | base image for the demo app, e.g. `mirror.gcr.io/library/python:3.12-alpine` when Docker Hub rate-limits |
| `CLAVURE_RUNTIME_TESTS=1` | enables `tests/integration` (real cluster) |

## Notes from the build sandbox

The recorded evidence was produced in a nested container sandbox that needed:

```bash
dockerd &                                          # daemon was not running
export CLAVURE_K3S_CA_BUNDLE=/root/.ccr/ca-bundle.crt
export CLAVURE_K3S_RESTRICT_OOM=1                  # runc failed: oom_score_adj -998 denied
export K3D_IMAGE_TOOLS=rancher/k3d-tools:latest    # ghcr.io blocked by egress policy
export CLAVURE_BASE_IMAGE=mirror.gcr.io/library/python:3.12-alpine
```

The OOM issue was diagnosed from runc's debug log
(`failed to update /proc/self/oom_score_adj: Permission denied`). The sandbox
drops `CAP_SYS_RESOURCE`, and kubelet requests `-998` for pod sandboxes. On a
normal workstation or CI runner none of these settings are needed.

## NetworkPolicy enforcement

K3s ships an embedded kube-router NetworkPolicy controller. Clavure does not
assume it works: every runtime run starts with the enforcement canary and the
controller-configuration check (see [verification.md](verification.md)).
Blocked connections on this controller are *rejected* (ECONNREFUSED). That is
why target listener health is checked separately before a refusal counts as
BLOCKED.

## Clavure CLI image (`Dockerfile`)

Validated in the build sandbox except for the `apt-get install git` layer:
the sandbox's egress returns 403 for Debian mirrors. A validation build
without that layer, with the sandbox CA supplied as a BuildKit secret (not
committed), installed the pinned dependencies and ran `clavure verify-model`
as uid 10001 with the expected result. A normal CI runner needs no extra
settings.

## Running the CI job scripts locally

`tests/integration/test_ci_jobs_local.py` runs the trusted CI jobs' scripts in
their digest-pinned image against a simulated repository (see
[`ci/trusted/README.md`](../ci/trusted/README.md)).

```bash
CLAVURE_CI_JOB_TESTS=1 pytest -q tests/integration/test_ci_jobs_local.py
# also deploy to a local disposable "staging" k3d cluster:
CLAVURE_TEST_STAGING=1 ...
# also run clavure:runtime:k3d with the host Docker daemon in place of dind:
CLAVURE_TEST_RUNTIME_JOB=1 ...
```

Sandbox-only knobs: `CLAVURE_TEST_REGISTRY_MIRROR` (pull official images via
a mirror), `CLAVURE_TEST_CA_BUNDLE` (CA for a TLS-intercepting proxy) and
`CLAVURE_TEST_K3D_TOOLS` (k3d helper image when ghcr.io is unreachable).
