from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from clavure.core.constraints import load_scenario
from clavure.core.models import SourceRef
from clavure.core.policy_parser import parse_documents

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
BASE = DEMO / "manifests" / "base"
CHANGE = DEMO / "changes" / "unsafe-reporting-access"
DRIFT = DEMO / "drift"
SCENARIO = DEMO / "scenario.yaml"


def inv_from_yaml(text: str, *, allow_duplicates: bool = False):
    docs = [
        (d, SourceRef(origin="manifest", path="inline.yaml", document=i))
        for i, d in enumerate(yaml.safe_load_all(textwrap.dedent(text)))
        if d is not None
    ]
    return parse_documents(docs, allow_duplicates=allow_duplicates)


def pod(
    name: str,
    ns: str,
    labels: dict,
    ports: list[tuple[str | None, int]] | None = None,
    host_network: bool = False,
) -> str:
    ports = ports if ports is not None else [("http", 8080)]
    lines = [
        "apiVersion: v1",
        "kind: Pod",
        "metadata:",
        f"  name: {name}",
        f"  namespace: {ns}",
        "  labels:",
    ]
    lines += [f'    {k}: "{v}"' for k, v in labels.items()]
    lines += ["spec:"]
    if host_network:
        lines += ["  hostNetwork: true"]
    lines += ["  containers:", "    - name: c", "      image: x", "      ports:"]
    for pname, num in ports:
        lines.append(f"        - containerPort: {num}")
        if pname:
            lines.append(f"          name: {pname}")
    return "\n".join(lines) + "\n"


def ns(name: str, labels: dict | None = None) -> str:
    lines = ["apiVersion: v1", "kind: Namespace", "metadata:", f"  name: {name}"]
    if labels:
        lines.append("  labels:")
        lines += [f'    {k}: "{v}"' for k, v in labels.items()]
    return "\n".join(lines) + "\n"


def docs(*parts: str) -> str:
    return "\n---\n".join(textwrap.dedent(p).strip() for p in parts) + "\n"


@pytest.fixture(scope="session")
def scenario():
    return load_scenario(SCENARIO)
