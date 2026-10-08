"""Disposable test environment lifecycle on the dedicated cluster (trusted).

Applying a remediation follows GitOps semantics: changed/added objects are
applied and deleted objects are deleted, but nothing else is pruned. Objects
that exist only in the live cluster (drift) therefore stay in place, exactly
as they would in a real rollout, which is what lets runtime verification
expose model mismatches.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from clavure.core.constraints import Scenario
from clavure.core.policy_parser import load_documents
from clavure.optimizer.solver import CandidatePlan
from clavure.runtime.cluster import ClusterController
from clavure.runtime.kube import Kube
from clavure.verification.evidence import now

CANARY_NAMESPACE = "clavure-canary"
DEMO_IMAGE = "clavure-demo:0.1.0"


@dataclass
class TestEnvironment:
    __test__ = False  # not a pytest test class

    controller: ClusterController
    scenario: Scenario
    kube: Kube = field(init=False)
    events: list[dict] = field(default_factory=list)
    baseline_policy_docs: dict[str, dict] = field(default_factory=dict)

    def __post_init__(self):
        self.kube = Kube(
            self.controller,
            [*self.scenario.test_namespaces, CANARY_NAMESPACE],
            self.scenario.required_namespace_label,
        )

    def log(self, event: str, **detail) -> None:
        self.events.append({"timestamp": now(), "event": event, **detail})

    # ------------------------------------------------------------------
    def deploy(self, manifest_paths: list[Path], image: str = DEMO_IMAGE) -> None:
        self.controller.verify_identity()
        self.controller.import_image(image)
        docs = [d for d, _ in load_documents(manifest_paths)]
        self.kube.apply_docs(docs)
        for d in docs:
            if d["kind"] == "NetworkPolicy":
                self.baseline_policy_docs[
                    f"{d['metadata']['namespace']}/{d['metadata']['name']}"
                ] = d
        for d in docs:
            if d["kind"] == "Deployment":
                self.kube.wait_rollout(d["metadata"]["namespace"], d["metadata"]["name"])
        self.log(
            "deployed",
            manifests=[str(p) for p in manifest_paths],
            objects=len(docs),
            policies=sorted(self.baseline_policy_docs),
        )

    def inject_drift(self, path: Path) -> list[str]:
        """FAULT INJECTION: apply objects out-of-band (not part of any manifest set)."""
        docs = [d for d, _ in load_documents([path])]
        self.kube.apply_docs(docs)
        ids = [f"{d['metadata'].get('namespace')}/{d['metadata']['name']}" for d in docs]
        self.log("fault-injection:drift-applied", objects=ids, source=str(path))
        return ids

    def apply_plan(self, plan: CandidatePlan) -> list[str]:
        """Apply a plan's in-git changes. Returns out-of-band changes NOT applied."""
        skipped = []
        to_apply = []
        for ch in plan.changes:
            if ch.origin == "live-cluster":
                skipped.append(f"{ch.change} {ch.policy}")
                continue
            if ch.change in ("added", "modified") and ch.manifest:
                to_apply.append(ch.manifest)
            elif ch.change == "deleted":
                ns, name = ch.policy.split("/", 1)
                self.kube.delete_network_policy(ns, name)
        if to_apply:
            self.kube.apply_docs(to_apply)
        self.log("plan-applied", plan=plan.id, summary=plan.summary(), skipped_out_of_band=skipped)
        return skipped

    def revert_plan(self, plan: CandidatePlan) -> None:
        """Return the touched policies to their deployed (baseline) state."""
        restore = []
        for ch in plan.changes:
            if ch.origin == "live-cluster":
                continue
            ns, name = ch.policy.split("/", 1)
            if ch.change == "added":
                self.kube.delete_network_policy(ns, name)
            elif ch.policy in self.baseline_policy_docs:
                restore.append(self.baseline_policy_docs[ch.policy])
        if restore:
            self.kube.apply_docs(restore)
        self.log("plan-reverted", plan=plan.id)

    def live_policies(self) -> list[dict]:
        return self.kube.live_network_policies(self.scenario.test_namespaces)

    def teardown_namespaces(self) -> None:
        for ns in [*self.scenario.test_namespaces, CANARY_NAMESPACE]:
            self.kube.run(
                ["delete", "namespace", ns, "--ignore-not-found", "--wait=false"], check=False
            )
        self.log("namespaces-deleted")

    # ------------------------------------------------------------------
    def canary(self, timeout: int = 40) -> dict:
        """Prove that NetworkPolicy is enforced: allowed -> denied -> allowed."""
        ns = CANARY_NAMESPACE
        k = self.kube
        k.apply_docs(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {"name": ns, "labels": {k.label_key: k.label_value}},
                }
            ]
        )
        pods = [
            _canary_pod("canary-server", "orders-db", ns),
            _canary_pod("canary-client", "idle", ns),
        ]
        k.apply_docs(pods)
        server = k.ready_pod(ns, {"clavure.io/canary": "canary-server"}, timeout=120)
        client = k.ready_pod(ns, {"clavure.io/canary": "canary-client"}, timeout=120)
        ip = server["status"]["podIP"]
        cname = client["metadata"]["name"]

        def probe() -> dict:
            r = k.exec(
                ns,
                cname,
                [
                    "python",
                    "/app/app.py",
                    "probe",
                    "--host",
                    ip,
                    "--port",
                    "5432",
                    "--timeout",
                    "2",
                    "--send",
                    "PING",
                ],
                timeout=20,
            )
            return (
                json.loads(r.stdout)
                if r.returncode == 0 and r.stdout.strip()
                else {"status": "EXEC_ERROR"}
            )

        def wait_for(pred) -> tuple[bool, list[dict]]:
            samples = []
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                s = probe()
                samples.append(s)
                if pred(s):
                    return True, samples
                time.sleep(1.5)
            return False, samples

        result: dict = {"namespace": ns, "server_ip": ip}
        ok1, s1 = wait_for(lambda s: s.get("status") == "CONNECTED")
        result["baseline_connected"] = ok1
        deny = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "canary-deny", "namespace": ns},
            "spec": {
                "podSelector": {"matchLabels": {"clavure.io/canary": "canary-server"}},
                "policyTypes": ["Ingress"],
            },
        }
        k.apply_docs([deny])
        ok2, s2 = wait_for(
            lambda s: s.get("status") in ("REFUSED", "TIMEOUT", "UNREACHABLE", "RESET")
        )
        result["blocked_after_deny"] = ok2
        k.delete_network_policy(ns, "canary-deny")
        ok3, s3 = wait_for(lambda s: s.get("status") == "CONNECTED")
        result["restored_after_delete"] = ok3
        result["blocked_status"] = s2[-1].get("status") if s2 else None
        result["samples"] = {"baseline": s1[-1:], "deny": s2[-1:], "restore": s3[-1:]}
        result["confirmed"] = ok1 and ok2 and ok3
        k.run(
            ["delete", "namespace", ns, "--ignore-not-found", "--wait=true", "--timeout=90s"],
            check=False,
            timeout=120,
        )
        self.log("enforcement-canary", confirmed=result["confirmed"])
        return result


def _canary_pod(name: str, role: str, ns: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": ns, "labels": {"clavure.io/canary": name}},
        "spec": {
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 10001,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "app",
                    "image": DEMO_IMAGE,
                    "imagePullPolicy": "Never",
                    "args": ["idle" if role == "idle" else "serve"],
                    "env": [{"name": "CLAVURE_ROLE", "value": role}],
                    "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }
            ],
        },
    }
