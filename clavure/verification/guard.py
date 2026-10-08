"""Trusted-file guard (runs in CI; trusted component).

Fails when a change touches trusted files (requirements, verifiers, CI and
flow configuration, reference tests) and the change was produced by an
automated identity or on a remediation branch. Human changes to trusted files
are reported so that CODEOWNERS approval can be enforced by GitLab.

This is one layer of several (see docs/security-model.md): instructions given
to an agent are not a security boundary, so the guard does not depend on the
agent's cooperation.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import yaml


def load_config(path: str | Path = ".clavure.yaml") -> dict:
    return yaml.safe_load(Path(path).read_text())


def changed_files(base_ref: str, repo: str | Path = ".") -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), "diff", "--name-only", f"{base_ref}...HEAD"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed: {proc.stderr.strip()}")
    return [line for line in proc.stdout.splitlines() if line.strip()]


def is_trusted(path: str, trusted: list[str]) -> bool:
    for t in trusted:
        if t.endswith("/") and path.startswith(t):
            return True
        if path == t:
            return True
    return False


def check_trusted_files(
    base_ref: str,
    config_path: str | Path = ".clavure.yaml",
    *,
    repo: str | Path = ".",
    actor: str | None = None,
    branch: str | None = None,
    files: list[str] | None = None,
) -> dict:
    cfg = load_config(Path(repo) / config_path)
    actor = actor if actor is not None else os.environ.get("GITLAB_USER_LOGIN", "")
    branch = (
        branch if branch is not None else os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "")
    )
    files = files if files is not None else changed_files(base_ref, repo)
    touched = sorted(f for f in files if is_trusted(f, cfg.get("trusted", [])))
    automated = any(re.match(p, actor or "") for p in cfg.get("automated_identity_patterns", []))
    remediation_branch = bool(branch) and branch.startswith(
        cfg.get("remediation_branch_prefix", "\0")
    )
    blocked = bool(touched) and (automated or remediation_branch)
    return {
        "ok": not blocked,
        "base_ref": base_ref,
        "actor": actor,
        "automated_identity": automated,
        "source_branch": branch,
        "remediation_branch": remediation_branch,
        "changed_files": files,
        "trusted_files_touched": touched,
        "decision": (
            "BLOCK: automated change touches trusted files"
            if blocked
            else "REVIEW: human change to trusted files requires code-owner approval"
            if touched
            else "PASS: no trusted files touched"
        ),
    }
