"""Re-ingest the live cluster's NetworkPolicies and report drift.

Runtime observations that contradict the model are first explained by
looking at what is actually enforced. The live objects (read-only, fetched by
the trusted controller) replace the modelled policies for the namespaces in
scope, and every difference is reported as CONFIGURATION_DRIFT. Live objects
never become *requirements*; they only refine the model of the current state.
"""

from __future__ import annotations

from clavure.core.findings import Finding, FindingCategory, Severity
from clavure.core.models import Inventory, SourceRef
from clavure.core.policy_parser import parse_documents

_VOLATILE_META = {
    "uid",
    "resourceVersion",
    "generation",
    "creationTimestamp",
    "managedFields",
    "selfLink",
    "deletionTimestamp",
    "deletionGracePeriodSeconds",
    "ownerReferences",
    "finalizers",
}
_VOLATILE_ANNOTATIONS = {"kubectl.kubernetes.io/last-applied-configuration"}


def clean_live_object(doc: dict) -> dict:
    meta = {k: v for k, v in (doc.get("metadata") or {}).items() if k not in _VOLATILE_META}
    if "annotations" in meta:
        ann = {
            k: v for k, v in (meta["annotations"] or {}).items() if k not in _VOLATILE_ANNOTATIONS
        }
        if ann:
            meta["annotations"] = ann
        else:
            meta.pop("annotations")
    out = {k: v for k, v in doc.items() if k not in ("status", "metadata")}
    out["metadata"] = meta
    out.setdefault("apiVersion", "networking.k8s.io/v1")
    out.setdefault("kind", "NetworkPolicy")
    return out


def ingest_live_policies(
    manifest_inv: Inventory, live_policy_docs: list[dict], namespaces: list[str]
) -> tuple[Inventory, list[Finding]]:
    live_inv = parse_documents(
        [(clean_live_object(d), SourceRef(origin="live-cluster")) for d in live_policy_docs]
    )
    scope = set(namespaces)
    policies = {pid: p for pid, p in manifest_inv.policies.items() if p.namespace not in scope}
    findings: list[Finding] = []
    for pid, live in sorted(live_inv.policies.items()):
        if live.namespace not in scope:
            continue
        declared = manifest_inv.policies.get(pid)
        if declared is None:
            policies[pid] = live
            findings.append(
                _drift(pid, "exists in the live cluster but not in the manifests", Severity.HIGH)
            )
        elif _spec(declared) != _spec(live):
            # Keep the manifest source so a git patch overwrites the drift.
            policies[pid] = live.model_copy(update={"source": declared.source})
            findings.append(_drift(pid, "live spec differs from the manifest", Severity.HIGH))
        else:
            policies[pid] = declared
    for pid, declared in sorted(manifest_inv.policies.items()):
        if declared.namespace in scope and pid not in live_inv.policies:
            findings.append(
                _drift(
                    pid, "declared in manifests but missing from the live cluster", Severity.MEDIUM
                )
            )
    inv = manifest_inv.with_policies(policies)
    inv.unsupported = list(manifest_inv.unsupported) + list(live_inv.unsupported)
    return inv, findings


def _spec(p) -> dict:
    return p.to_k8s()["spec"]


def _drift(pid: str, what: str, severity: Severity) -> Finding:
    return Finding(
        id=f"CONFIGURATION_DRIFT:{pid}",
        category=FindingCategory.CONFIGURATION_DRIFT,
        severity=severity,
        provenance="runtime",
        title=f"NetworkPolicy {pid} {what}",
        policies=[pid],
        evidence=[f"{pid}: {what} (read-only comparison of live cluster state with manifests)"],
    )
