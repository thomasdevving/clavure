"""Execute the trusted CI job scripts locally, in the pinned job image.

This is NOT a GitLab pipeline run. It takes the job definitions exactly as
GitLab would compose them (include/extends/!reference, see
tests/unit/test_ci_config.py), writes their before_script + script to a file
and runs it with bash inside the digest-pinned job image, against a simulated
repository:

  origin (bare)  main                      clean baseline (this working tree)
                 demo/unsafe-networkpolicy main + the unsafe NetworkPolicy
                 clavure/remediation-1     demo branch + Clavure's remediation
                 clavure/remediation-2     demo branch + tampering with trusted files

Opt-in: CLAVURE_CI_JOB_TESTS=1. Requires Docker and network access to PyPI
(hash-checked installs) and dl.k8s.io (checksum-verified kubectl download).

Environment knobs for restricted sandboxes (not needed on normal machines):
  CLAVURE_TEST_REGISTRY_MIRROR  e.g. mirror.gcr.io/library (pull official images via a mirror)
  CLAVURE_TEST_CA_BUNDLE        CA bundle for TLS-intercepting proxies (mounted as PIP_CERT)
  CLAVURE_TEST_STAGING=1        also deploy to a local disposable k3d "staging" cluster
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from clavure.cli import main as cli
from tests.conftest import CHANGE, ROOT
from tests.unit.test_ci_config import PIPELINE, expand, resolve

pytestmark = pytest.mark.skipif(
    os.environ.get("CLAVURE_CI_JOB_TESTS") != "1", reason="set CLAVURE_CI_JOB_TESTS=1"
)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def commit_all(repo: Path, msg: str, author: str = "Developer <dev@example.com>") -> str:
    git(repo, "add", "-A")
    git(
        repo,
        "-c",
        "user.name=ci-test",
        "-c",
        "user.email=ci@example.com",
        "commit",
        "-q",
        "--author",
        author,
        "-m",
        msg,
    )
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    base = tmp_path_factory.mktemp("ciworld")
    src = base / "src"
    src.mkdir()
    for f in git(ROOT, "ls-files").splitlines():
        if (
            f.startswith(("docs/evidence/", "demo/manifests/analytics-access/"))
            or not (ROOT / f).exists()
        ):
            continue
        dest = src / f
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / f, dest)
    git(src, "init", "-q", "-b", "main")
    shas = {"main": commit_all(src, "Clean baseline")}
    git(src, "checkout", "-q", "-b", "demo/unsafe-networkpolicy")
    shutil.copytree(CHANGE, src / "demo/manifests/analytics-access")
    shas["demo"] = commit_all(src, "Give the reporting service read access to order data")

    # Remediation exactly as the Duo flow would produce it.
    git(src, "checkout", "-q", "-b", "clavure/remediation-1")
    cwd = Path.cwd()
    os.chdir(src)
    try:
        assert cli(["mr-check", "--target-ref", "main", "--out", str(base / "duo")]) == 0
        assert (
            cli(
                ["apply-remediation", "--plan", str(base / "duo/remediation-plan.json"), "--verify"]
            )
            == 0
        )
    finally:
        os.chdir(cwd)
    shas["remediation"] = commit_all(src, "Clavure remediation", "ai-clavure <ai@example.com>")

    # Tampering: weaken requirements AND the guard/verifier code in the MR.
    git(src, "checkout", "-q", "-b", "clavure/remediation-2", "demo/unsafe-networkpolicy")
    scen = src / "demo/scenario.yaml"
    scen.write_text(
        scen.read_text().replace(
            "port: any\n      description: Analytics", "port: 9187\n      description: Analytics"
        )
    )
    guard = src / "clavure/verification/guard.py"
    guard.write_text(guard.read_text().replace('"ok": not blocked,', '"ok": True,'))
    shas["tamper"] = commit_all(src, "make checks pass", "ai-clavure <ai@example.com>")

    origin = base / "origin.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(src), str(origin)], check=True)
    return {"base": base, "origin": origin, "shas": shas}


def checkout(world, ref: str, name: str) -> Path:
    proj = world["base"] / f"proj-{name}"
    if proj.exists():
        shutil.rmtree(proj)
    subprocess.run(["git", "clone", "-q", str(world["origin"]), str(proj)], check=True)
    git(proj, "checkout", "-q", ref)
    git(proj, "remote", "set-url", "origin", "/origin")
    return proj


def image_ref(job: dict) -> str:
    image = job["image"]
    mirror = os.environ.get("CLAVURE_TEST_REGISTRY_MIRROR")
    if mirror and image.startswith("python:"):
        image = f"{mirror}/python@{image.split('@', 1)[1]}"
    return image


def run_job(
    world,
    name: str,
    proj: Path,
    env: dict,
    extra_mounts: list[str] = (),
    overrides: dict | None = None,
    same_path: bool = False,
) -> subprocess.CompletedProcess:
    job = resolve(PIPELINE, name)
    lines = expand(PIPELINE, job.get("before_script", [])) + expand(PIPELINE, job.get("script", []))
    exports = [f'export {k}="{v}"' for k, v in (job.get("variables") or {}).items()]
    # Local-only substitutions (e.g. the host Docker socket instead of a dind
    # service), applied after the job's own variables.
    exports += [f'export {k}="{v}"' for k, v in (overrides or {}).items()]
    script = "\n".join(["set -eo pipefail", *exports, *lines])
    (proj.parent / f"{proj.name}.sh").write_text(script)
    # same_path: mount the project at its host path so that volume paths
    # passed to the host Docker daemon (by k3d) resolve identically.
    project_dir = str(proj) if same_path else "/builds/project"
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "host",
        "-v",
        f"{proj}:{project_dir}",
        "-v",
        f"{world['origin']}:/origin",
        "-v",
        f"{proj.parent / (proj.name + '.sh')}:/job.sh:ro",
        "-w",
        project_dir,
    ]
    ca = os.environ.get("CLAVURE_TEST_CA_BUNDLE")
    if ca:
        cmd += [
            "-v",
            f"{ca}:/ca.crt:ro",
            "-e",
            "PIP_CERT=/ca.crt",
            "-e",
            "CURL_CA_BUNDLE=/ca.crt",
            "-e",
            "SSL_CERT_FILE=/ca.crt",
        ]
    for m in extra_mounts:
        cmd += ["-v", m]
    full_env = {
        "CI_PROJECT_DIR": project_dir,
        "CI_DEFAULT_BRANCH": "main",
        "CI_PIPELINE_ID": "4242",
        "CI_JOB_ID": "1",
        **env,
    }
    for k, v in full_env.items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [image_ref(job), "bash", "/job.sh"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    (proj.parent / f"{proj.name}.log").write_text(proc.stdout + "\n--- stderr ---\n" + proc.stderr)
    return proc


def mr_env(world, source: str, target: str, actor: str) -> dict:
    return {
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_MERGE_REQUEST_ID": "7",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": target,
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": source,
        "CI_MERGE_REQUEST_DIFF_BASE_SHA": world["shas"]["main" if target == "main" else "demo"],
        "GITLAB_USER_LOGIN": actor,
    }


def load(proj: Path, name: str) -> dict:
    return json.loads((proj / "artifacts/trusted" / name).read_text())


def test_unsafe_demo_mr_is_blocked(world):
    proj = checkout(world, "demo/unsafe-networkpolicy", "unsafe")
    p = run_job(
        world,
        "clavure:security-gate:mr",
        proj,
        mr_env(world, "demo/unsafe-networkpolicy", "main", "developer"),
    )
    assert p.returncode != 0, p.stdout[-3000:]
    t = load(proj, "trusted-model-verification.json")
    assert t["gate_outcome"] == "FAIL" and t["forbidden_failures"] == ["FORBID-REPORTING-FINANCEDB"]
    assert load(proj, "guard.json")["ok"] is True  # a human change to manifests only
    assert "Trusted Clavure: origin/main" in p.stdout
    plan = json.loads((proj / "artifacts/trusted/mr-check/remediation-plan.json").read_text())
    assert plan["selected"] is not None


def test_remediation_mr_into_unprotected_branch_passes(world):
    proj = checkout(world, "clavure/remediation-1", "remediation")
    p = run_job(
        world,
        "clavure:security-gate:mr",
        proj,
        mr_env(
            world,
            "clavure/remediation-1",
            "demo/unsafe-networkpolicy",
            "ai-clavure-remediation-demo",
        ),
    )
    assert p.returncode == 0, p.stdout[-3000:] + p.stderr[-2000:]
    t = load(proj, "trusted-model-verification.json")
    assert t["gate_outcome"] == "PASS" and t["requirements"].startswith("/tmp/trusted")


def test_tampering_mr_is_blocked_by_trusted_tooling(world):
    proj = checkout(world, "clavure/remediation-2", "tamper")
    p = run_job(
        world,
        "clavure:security-gate:mr",
        proj,
        mr_env(
            world,
            "clavure/remediation-2",
            "demo/unsafe-networkpolicy",
            "ai-clavure-remediation-demo",
        ),
    )
    assert p.returncode != 0
    guard = load(proj, "guard.json")
    assert guard["ok"] is False  # the MR's patched guard.py was never executed
    assert "demo/scenario.yaml" in guard["trusted_files_touched"]
    assert "clavure/verification/guard.py" in guard["trusted_files_touched"]
    assert (
        "FORBID-REPORTING-FINANCEDB"
        in load(proj, "trusted-model-verification.json")["forbidden_failures"]
    )


@pytest.fixture(scope="module")
def branch_gate(world):
    proj = checkout(world, "main", "main")
    env = {
        "CI_PIPELINE_SOURCE": "push",
        "CI_COMMIT_BRANCH": "main",
        "CI_COMMIT_REF_NAME": "main",
        "CI_COMMIT_REF_PROTECTED": "true",
        "CI_COMMIT_SHA": world["shas"]["main"],
    }
    return proj, run_job(world, "clavure:security-gate:branch", proj, env), env


def test_branch_gate_passes_on_clean_baseline(branch_gate):
    proj, p, _ = branch_gate
    assert p.returncode == 0, p.stdout[-3000:]
    rec = load(proj, "gate-passed.json")
    assert rec == {"pass": True, "commit": rec["commit"], "pipeline": "4242"}
    t = load(proj, "trusted-model-verification.json")
    assert t["preexisting_required_failures"] == ["REQ-REPORTING-ORDERS"]


def test_branch_gate_refuses_unprotected_ref(world):
    proj = checkout(world, "main", "unprotected")
    env = {
        "CI_PIPELINE_SOURCE": "push",
        "CI_COMMIT_BRANCH": "main",
        "CI_COMMIT_REF_NAME": "main",
        "CI_COMMIT_REF_PROTECTED": "false",
        "CI_COMMIT_SHA": world["shas"]["main"],
    }
    p = run_job(world, "clavure:security-gate:branch", proj, env)
    assert p.returncode != 0 and "is not protected" in p.stdout + p.stderr


def test_deploy_refuses_without_matching_gate_record(world, branch_gate):
    proj, _, env = branch_gate
    deploy_env = {**env, "STAGING_KUBECONFIG": "/nonexistent"}
    # Same commit, different pipeline: the record does not authorize this run.
    p = run_job(world, "deploy:staging", proj, {**deploy_env, "CI_PIPELINE_ID": "9999"})
    assert p.returncode != 0 and "Refusing: no passing security gate" in p.stdout + p.stderr
    # No record at all.
    rec = proj / "artifacts/trusted/gate-passed.json"
    saved = rec.read_text()
    rec.unlink()
    p = run_job(world, "deploy:staging", proj, deploy_env)
    rec.write_text(saved)
    assert p.returncode != 0


@pytest.mark.skipif(
    os.environ.get("CLAVURE_TEST_STAGING") != "1", reason="set CLAVURE_TEST_STAGING=1"
)
def test_deploy_to_local_staging_cluster(world, branch_gate):
    from clavure.runtime.cluster import ClusterController

    proj, _, env = branch_gate
    ctl = ClusterController.from_env(name="clavure-staging")
    ctl.create()
    try:
        ctl.import_image("clavure-demo:0.1.0")
        p = run_job(
            world,
            "deploy:staging",
            proj,
            {**env, "STAGING_KUBECONFIG": "/kubeconfig"},
            extra_mounts=[f"{ctl.kubeconfig}:/kubeconfig:ro"],
        )
        assert p.returncode == 0, p.stdout[-3000:] + p.stderr[-2000:]
        assert "networkpolicy.networking.k8s.io/orders-db-ingress" in p.stdout
        out = subprocess.run(
            [*ctl.kubectl_base(), "get", "networkpolicy", "-A", "-o", "name"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        assert "allow-analytics-to-data-tier" not in out  # baseline only
    finally:
        ctl.delete()


def test_job_scripts_are_written_for_review(world):
    """Keep the rendered scripts next to their logs for inspection."""
    assert list(world["base"].glob("proj-*.sh"))
    print("\n".join(shlex.quote(str(p)) for p in world["base"].glob("proj-*.log")))


def runtime_overrides() -> dict:
    keys = ("CLAVURE_K3S_CA_BUNDLE", "CLAVURE_K3S_RESTRICT_OOM", "CLAVURE_BASE_IMAGE")
    out = {"DOCKER_HOST": "unix:///var/run/docker.sock", "CLAVURE_K3D_API_HOST": ""}
    out.update({k: os.environ[k] for k in keys if k in os.environ})
    if os.environ.get("CLAVURE_TEST_K3D_TOOLS"):
        out["K3D_IMAGE_TOOLS"] = os.environ["CLAVURE_TEST_K3D_TOOLS"]
    return out


@pytest.mark.skipif(
    os.environ.get("CLAVURE_TEST_RUNTIME_JOB") != "1", reason="set CLAVURE_TEST_RUNTIME_JOB=1"
)
@pytest.mark.parametrize(
    ("branch", "target", "actor", "expect_verdict", "expect_pass"),
    [
        ("demo/unsafe-networkpolicy", "main", "developer", "REMEDIATION_VERIFIED", False),
        (
            "clavure/remediation-1",
            "demo/unsafe-networkpolicy",
            "ai-clavure-remediation-demo",
            "NO_VIOLATION",
            True,
        ),
    ],
)
def test_runtime_job(world, branch, target, actor, expect_verdict, expect_pass):
    """clavure:runtime:k3d with the host Docker daemon standing in for the dind service."""
    proj = checkout(world, branch, "runtime-" + branch.replace("/", "-"))
    p = run_job(
        world,
        "clavure:runtime:k3d",
        proj,
        mr_env(world, branch, target, actor),
        extra_mounts=["/var/run/docker.sock:/var/run/docker.sock"],
        overrides=runtime_overrides(),
        same_path=True,
    )
    subprocess.run(["k3d", "cluster", "delete", "clavure-ci-1"], capture_output=True)
    log = p.stdout + p.stderr
    for artifact in ("k3d: OK", "kubectl: OK", "docker.tgz: OK"):
        assert artifact in log, artifact
    report = json.loads((proj / "artifacts/runtime/verification-report.json").read_text())
    assert report["final_verdict"] == expect_verdict, report["stages"]
    assert report["runtime"], "runtime stages did not execute"
    assert (p.returncode == 0) is expect_pass, log[-3000:]
