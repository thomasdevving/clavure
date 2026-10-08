"""Static model of the GitLab CI configuration.

The configuration is loaded the way GitLab composes it, then the invariants
the security design depends on are checked for each pipeline type:

* ``include: local`` resolved relative to the including file (GitLab
  semantics: "always evaluated based on the location of the file containing
  the include keyword"), ``extends`` deep-merged, ``!reference`` expanded;
* ``workflow:rules`` and job ``rules`` evaluated for MR, default-branch, tag
  and runtime-runner contexts.

This cannot replace a real GitLab pipeline run; it does catch the class of
errors that would make GitLab refuse to create the pipeline (``needs`` on a
job that is absent from that pipeline), as well as regressions of the
supply-chain and trust rules.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest
import yaml

from tests.conftest import ROOT

CI_DIR = ROOT / "ci" / "trusted"
RESERVED = {".pre", ".post", ".pipeline-policy-pre", ".pipeline-policy-post"}
SECURITY_JOBS = {
    "clavure:security-gate:mr",
    "clavure:security-gate:branch",
    "clavure:runtime:k3d",
    "deploy:staging",
}


class Ref(list):
    """A ``!reference [job, key]`` placeholder."""


class CILoader(yaml.SafeLoader):
    pass


CILoader.add_constructor("!reference", lambda loader, node: Ref(loader.construct_sequence(node)))


def load_ci(path: Path) -> dict:
    doc = yaml.load(path.read_text(), Loader=CILoader) or {}
    merged: dict = {}
    for inc in doc.pop("include", []) or []:
        if isinstance(inc, dict) and "local" in inc:
            merged = deep_merge(merged, load_ci(ROOT / inc["local"].lstrip("/")))
        # GitLab-managed templates (SAST, Secret Detection) are not modelled.
    return deep_merge(merged, doc)


def deep_merge(a: dict, b: dict) -> dict:
    out = copy.deepcopy(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def resolve(config: dict, name: str, seen=()) -> dict:
    job = config[name]
    parents = job.get("extends", [])
    parents = [parents] if isinstance(parents, str) else parents
    base: dict = {}
    for p in parents:
        assert p not in seen, f"extends cycle at {name}"
        base = deep_merge(base, resolve(config, p, (*seen, name)))
    return deep_merge(base, {k: v for k, v in job.items() if k != "extends"})


def expand(config: dict, value):
    if isinstance(value, Ref):
        target = resolve(config, value[0])
        for key in value[1:]:
            target = target[key]
        return expand(config, target)
    if isinstance(value, list):
        out = []
        for v in value:
            e = expand(config, v)
            if isinstance(v, Ref) and isinstance(e, list):
                out.extend(e)
            else:
                out.append(e)
        return out
    return value


def evaluate(expr: str, env: dict) -> bool:
    """Evaluate the rule-expression subset used by this repository."""

    def value(tok: str):
        tok = tok.strip()
        if tok.startswith("$"):
            return env.get(tok[1:])
        if tok.startswith('"') and tok.endswith('"'):
            return tok[1:-1]
        raise ValueError(f"unsupported token {tok!r}")

    result = True
    for clause in expr.split("&&"):
        clause = clause.strip()
        m = re.fullmatch(r"(.+?)\s*(==|!=)\s*(.+)", clause)
        if m:
            left, op, right = value(m.group(1)), m.group(2), value(m.group(3))
            ok = (left == right) if op == "==" else (left != right)
        else:
            ok = bool(value(clause))
        result = result and ok
    return result


def rule_outcome(rules: list | None, env: dict) -> str | None:
    """Return the job's `when` if it is added to the pipeline, else None."""
    if rules is None:
        return "on_success"
    for r in rules:
        if "if" not in r or evaluate(r["if"], env):
            when = r.get("when", "on_success")
            return None if when == "never" else when
    return None


BASE_ENV = {"CI_DEFAULT_BRANCH": "main", "CI_PROJECT_PATH": "g/clavure"}
CONTEXTS = {
    "merge_request": {
        **BASE_ENV,
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_MERGE_REQUEST_ID": "1",
    },
    "merge_request+runtime": {
        **BASE_ENV,
        "CI_PIPELINE_SOURCE": "merge_request_event",
        "CI_MERGE_REQUEST_ID": "1",
        "CLAVURE_RUNTIME_RUNNER": "true",
    },
    "default_branch": {**BASE_ENV, "CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "main"},
    "default_branch+staging": {
        **BASE_ENV,
        "CI_PIPELINE_SOURCE": "push",
        "CI_COMMIT_BRANCH": "main",
        "STAGING_KUBECONFIG": "/tmp/kc",
    },
    "tag": {**BASE_ENV, "CI_PIPELINE_SOURCE": "push", "CI_COMMIT_TAG": "v0.1.0"},
    "feature_branch_push": {
        **BASE_ENV,
        "CI_PIPELINE_SOURCE": "push",
        "CI_COMMIT_BRANCH": "feature",
    },
}

PIPELINE = load_ci(CI_DIR / "pipeline.yml")
JOB_NAMES = [
    k
    for k, v in PIPELINE.items()
    if isinstance(v, dict)
    and not k.startswith(".")
    and k not in {"workflow", "variables", "default", "stages", "include"}
]


def jobs_in(context: str) -> dict[str, dict]:
    env = CONTEXTS[context]
    if rule_outcome(PIPELINE["workflow"]["rules"], env) is None:
        return {}
    out = {}
    for name in JOB_NAMES:
        job = resolve(PIPELINE, name)
        when = rule_outcome(job.get("rules"), env)
        if when is not None:
            job["_when"] = when
            out[name] = job
    return out


def script_text(job: dict) -> str:
    parts = []
    for key in ("before_script", "script", "after_script"):
        v = expand(PIPELINE, job.get(key, []))
        parts.extend(v if isinstance(v, list) else [v])
    return "\n".join(map(str, parts))


def test_root_config_includes_shared_pipeline():
    root = yaml.load((ROOT / ".gitlab-ci.yml").read_text(), Loader=CILoader)
    assert root == {"include": [{"local": "/ci/trusted/pipeline.yml"}]}


@pytest.mark.parametrize("context", list(CONTEXTS))
def test_needs_and_stages_are_consistent(context):
    jobs = jobs_in(context)
    stages = PIPELINE["stages"]
    for name, job in jobs.items():
        assert job.get("stage", "test") in stages, (name, job.get("stage"))
        for need in job.get("needs", []) or []:
            need = need if isinstance(need, dict) else {"job": need}
            if need.get("optional"):
                continue
            assert need["job"] in jobs, (
                f"[{context}] {name} needs {need['job']}, absent from this pipeline"
            )
            assert stages.index(jobs[need["job"]]["stage"]) <= stages.index(job["stage"])


def test_pipeline_types():
    assert jobs_in("feature_branch_push") == {}  # no duplicate branch pipelines for MRs
    mr = jobs_in("merge_request")
    assert "clavure:security-gate:mr" in mr and "deploy:staging" not in mr
    assert "clavure:runtime:k3d" not in mr  # only with a capable runner
    assert "clavure:runtime:k3d" in jobs_in("merge_request+runtime")
    assert "deploy:staging" not in jobs_in("default_branch")  # no staging target configured
    staging = jobs_in("default_branch+staging")
    assert staging["deploy:staging"]["_when"] == "manual"
    assert "clavure:security-gate:branch" in jobs_in("tag")


def test_staging_cannot_bypass_the_security_gate():
    job = jobs_in("default_branch+staging")["deploy:staging"]
    needs = {n["job"]: n for n in job["needs"]}
    assert needs["clavure:security-gate:branch"].get("artifacts") is True
    assert not needs["clavure:security-gate:branch"].get("optional")
    text = script_text(job)
    assert "gate-passed.json" in text and "CI_COMMIT_SHA" in text and "CI_PIPELINE_ID" in text
    assert 'CI_COMMIT_REF_PROTECTED:-false}" = "true"' in text
    assert job["allow_failure"] is False
    gate = jobs_in("default_branch+staging")["clavure:security-gate:branch"]
    assert "gate-passed.json" in script_text(gate)
    # The record is written only after `clavure gate` succeeded (set -e).
    gtext = script_text(gate)
    assert gtext.index("clavure gate") < gtext.index("gate-passed.json")


@pytest.mark.parametrize("name", sorted(SECURITY_JOBS))
def test_security_jobs_use_only_default_branch_tooling(name):
    jobs = {**jobs_in("merge_request+runtime"), **jobs_in("default_branch+staging")}
    job = jobs[name]
    text = script_text(job)
    assert job["allow_failure"] is False
    if name == "deploy:staging":
        assert "clavure " not in text.replace("Clavure", "")
        return
    # Tooling, requirements and the trusted-file list come from the default branch.
    assert 'worktree add --detach /tmp/trusted "origin/$CI_DEFAULT_BRANCH"' in text
    for line in text.splitlines():
        if re.search(r"\bclavure\b(?!\.)", line) and "/tmp/trusted-venv/bin/clavure" not in line:
            assert not re.match(r"\s*clavure ", line), f"{name} runs untrusted clavure: {line}"
    assert "pip install -e" not in text and "-e ." not in text
    assert "--trusted-root /tmp/trusted" in text
    assert 'CI_MERGE_REQUEST_TARGET_BRANCH_NAME" ' not in text.split("trusted-venv")[0]


def all_jobs() -> dict[str, dict]:
    out = {}
    for ctx in CONTEXTS:
        out.update(jobs_in(ctx))
    return out


def test_images_are_pinned_by_digest():
    for name, job in all_jobs().items():
        image = job.get("image")
        image = image["name"] if isinstance(image, dict) else image
        assert image and re.search(r"@sha256:[0-9a-f]{64}$", image), (name, image)
        for svc in job.get("services", []) or []:
            ref = svc["name"] if isinstance(svc, dict) else svc
            assert re.search(r"@sha256:[0-9a-f]{64}$", ref), (name, ref)
        for k, v in (job.get("variables") or {}).items():
            if k == "K3D_IMAGE_TOOLS":
                assert re.search(r"@sha256:[0-9a-f]{64}$", v)


def test_every_download_is_checksum_verified():
    for name, job in all_jobs().items():
        lines = [ln.strip() for ln in script_text(job).splitlines()]
        for i, line in enumerate(lines):
            m = re.search(r"curl [^\n]*-o (\S+)", line)
            if not m:
                continue
            target = m.group(1)
            check = next((ln for ln in lines[i + 1 : i + 3] if "sha256sum -c" in ln), None)
            assert check, f"{name}: download of {target} not verified"
            assert re.match(
                rf'echo "[0-9a-f]{{64}}  {re.escape(target)}" \| sha256sum -c -', check
            ), check


def test_python_installs_are_hash_checked():
    for name, job in all_jobs().items():
        for line in script_text(job).splitlines():
            if "pip install" not in line or "pip install --quiet --no-deps" in line:
                continue
            if " -r " in line or line.rstrip().endswith("\\"):
                assert "--require-hashes" in line, (name, line)
            else:
                assert "--no-deps" in line, (name, line)


def test_policy_pipeline_uses_reserved_pre_stage():
    policy = load_ci(CI_DIR / "policy-pipeline.yml")
    jobs = [k for k in policy if k.startswith("clavure-policy:")]
    assert jobs
    for name in jobs:
        assert policy[name]["stage"] == ".pipeline-policy-pre"
    spec = yaml.safe_load((CI_DIR / "security-policy.yml").read_text())
    pol = spec["pipeline_execution_policy"][0]
    assert pol["pipeline_config_strategy"] == "inject_policy"
    assert pol["skip_ci"] == {"allowed": False} and pol["no_pipeline"] == {"allowed": False}
    assert pol["variables_override"] == {"allowed": False}
    assert pol["content"]["include"][0]["file"] == "ci/trusted/policy-pipeline.yml"


def test_trusted_files_cover_ci_definitions():
    trusted = yaml.safe_load((ROOT / ".clavure.yaml").read_text())["trusted"]
    for path in ("ci/", ".gitlab-ci.yml", "requirements.lock", "requirements-build.lock"):
        assert path in trusted, path
