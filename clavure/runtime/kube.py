"""Scoped kubectl wrapper used by the trusted runtime controller.

Every mutating call is restricted to namespaces that (a) are listed in the
trusted requirements file and (b) carry the label
``clavure.io/test-env=true`` in the live cluster. Cluster-scoped objects
other than those Namespaces are refused.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass

import yaml

from clavure.runtime.cluster import ClusterController


class ScopeError(PermissionError):
    """A runtime operation would leave the authorized test scope."""


class KubeError(RuntimeError):
    pass


@dataclass
class ExecResult:
    returncode: int
    stdout: str
    stderr: str
    command: list[str]


class Kube:
    def __init__(
        self,
        cluster: ClusterController,
        allowed_namespaces: list[str],
        required_label: str = "clavure.io/test-env=true",
        timeout: int = 60,
    ):
        self.cluster = cluster
        self.allowed = set(allowed_namespaces)
        key, _, value = required_label.partition("=")
        self.label_key, self.label_value = key, value
        self.timeout = timeout

    # ------------------------------------------------------------------
    def run(
        self,
        args: list[str],
        *,
        input: str | None = None,
        timeout: int | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        cmd = [*self.cluster.kubectl_base(), *args]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, input=input, timeout=timeout or self.timeout
        )
        if check and proc.returncode != 0:
            raise KubeError(f"kubectl {' '.join(args)} failed: {proc.stderr.strip()[-1500:]}")
        return proc

    def get_json(self, *args: str) -> dict:
        return json.loads(self.run(["get", *args, "-o", "json"]).stdout)

    # ------------------------------------------------------------------
    def _check_namespace_doc(self, doc: dict) -> None:
        name = doc["metadata"]["name"]
        if name not in self.allowed:
            raise ScopeError(f"namespace {name} is not an authorized test namespace")
        labels = doc["metadata"].get("labels") or {}
        if labels.get(self.label_key) != self.label_value:
            raise ScopeError(f"namespace {name} must carry {self.label_key}={self.label_value}")

    def assert_namespace_authorized(self, ns: str) -> None:
        if ns not in self.allowed:
            raise ScopeError(f"namespace {ns} is not an authorized test namespace")
        proc = self.run(["get", "namespace", ns, "-o", "json"], check=False)
        if proc.returncode != 0:
            raise ScopeError(f"namespace {ns} does not exist")
        labels = json.loads(proc.stdout)["metadata"].get("labels") or {}
        if labels.get(self.label_key) != self.label_value:
            raise ScopeError(f"live namespace {ns} lacks {self.label_key}={self.label_value}")

    def apply_docs(self, docs: list[dict]) -> None:
        namespaces = [d for d in docs if d.get("kind") == "Namespace"]
        others = [d for d in docs if d.get("kind") != "Namespace"]
        for d in namespaces:
            self._check_namespace_doc(d)
        for d in others:
            ns = (d.get("metadata") or {}).get("namespace")
            if not ns:
                raise ScopeError(f"refusing cluster-scoped or namespace-less {d.get('kind')}")
            if ns not in self.allowed:
                raise ScopeError(f"namespace {ns} of {d.get('kind')} is not authorized")
        if namespaces:
            self.run(["apply", "-f", "-"], input=yaml.safe_dump_all(namespaces))
        checked = set()
        for d in others:
            ns = d["metadata"]["namespace"]
            if ns not in checked:
                self.assert_namespace_authorized(ns)
                checked.add(ns)
        if others:
            self.run(["apply", "-f", "-"], input=yaml.safe_dump_all(others))

    def delete_network_policy(self, ns: str, name: str) -> None:
        self.assert_namespace_authorized(ns)
        self.run(["delete", "networkpolicy", name, "-n", ns, "--ignore-not-found"])

    def live_network_policies(self, namespaces: list[str]) -> list[dict]:
        out = []
        for ns in namespaces:
            if ns not in self.allowed:
                raise ScopeError(ns)
            out.extend(self.get_json("networkpolicies", "-n", ns).get("items", []))
        return out

    # ------------------------------------------------------------------
    def wait_rollout(self, ns: str, deployment: str, timeout: int = 180) -> None:
        self.run(
            ["rollout", "status", f"deployment/{deployment}", "-n", ns, f"--timeout={timeout}s"],
            timeout=timeout + 30,
        )

    def ready_pod(self, ns: str, selector: dict[str, str], timeout: int = 120) -> dict:
        sel = ",".join(f"{k}={v}" for k, v in sorted(selector.items()))
        deadline = time.monotonic() + timeout
        while True:
            items = self.get_json("pods", "-n", ns, "-l", sel).get("items", [])
            for pod in sorted(items, key=lambda p: p["metadata"]["name"]):
                conds = {
                    c["type"]: c["status"] for c in pod.get("status", {}).get("conditions", [])
                }
                if (
                    pod["status"].get("phase") == "Running"
                    and conds.get("Ready") == "True"
                    and not pod["metadata"].get("deletionTimestamp")
                ):
                    return pod
            if time.monotonic() > deadline:
                raise KubeError(f"no ready pod for {sel} in {ns}")
            time.sleep(2)

    def exec(self, ns: str, pod: str, command: list[str], timeout: int = 30) -> ExecResult:
        if ns not in self.allowed:
            raise ScopeError(f"exec outside authorized namespaces: {ns}")
        args = ["exec", "-n", ns, pod, "--", *command]
        try:
            proc = self.run(args, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return ExecResult(124, "", "kubectl exec timed out", args)
        return ExecResult(proc.returncode, proc.stdout, proc.stderr, args)

    def endpoints_ready(self, ns: str, service: str) -> int:
        data = self.get_json(
            "endpointslices", "-n", ns, "-l", f"kubernetes.io/service-name={service}"
        )
        n = 0
        for es in data.get("items", []):
            for ep in es.get("endpoints") or []:
                if (ep.get("conditions") or {}).get("ready"):
                    n += 1
        return n
