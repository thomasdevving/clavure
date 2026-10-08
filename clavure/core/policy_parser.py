"""Parse Kubernetes manifests into a Clavure :class:`Inventory`.

Design rules:

* Structural errors raise :class:`ManifestError` — Clavure never analyses a
  manifest set that the API server would reject.
* Objects or fields that could influence connectivity but are not modelled are
  recorded as :class:`UnsupportedFeature` (and later downgrade verdicts to
  ``UNSUPPORTED``) instead of being ignored.
* Objects irrelevant to L3/L4 connectivity (ConfigMaps, ServiceAccounts, ...)
  are counted in ``Inventory.ignored_kinds``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import yaml

from clavure.core.models import (
    ContainerPort,
    Direction,
    Inventory,
    IPBlock,
    LabelSelector,
    LabelSelectorRequirement,
    Namespace,
    NetworkPolicy,
    PolicyPeer,
    PolicyPort,
    PolicyRule,
    Service,
    ServicePort,
    SourceRef,
    UnsupportedFeature,
    Workload,
)


class ManifestError(ValueError):
    """A manifest is structurally invalid."""


# Policy-like objects from other enforcement systems. They can allow or deny
# traffic in ways NetworkPolicy semantics cannot express, so their presence
# makes affected verdicts UNSUPPORTED rather than silently trusted.
_FOREIGN_POLICY_KINDS: dict[tuple[str, str], str] = {
    ("cilium.io", "CiliumNetworkPolicy"): "namespace",
    ("cilium.io", "CiliumClusterwideNetworkPolicy"): "cluster",
    ("projectcalico.org", "NetworkPolicy"): "namespace",
    ("crd.projectcalico.org", "NetworkPolicy"): "namespace",
    ("projectcalico.org", "GlobalNetworkPolicy"): "cluster",
    ("crd.projectcalico.org", "GlobalNetworkPolicy"): "cluster",
    ("policy.networking.k8s.io", "AdminNetworkPolicy"): "cluster",
    ("policy.networking.k8s.io", "BaselineAdminNetworkPolicy"): "cluster",
    ("policy.networking.k8s.io", "ClusterNetworkPolicy"): "cluster",
    ("security.istio.io", "AuthorizationPolicy"): "namespace",
}

_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}

_DNS1123_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
_DNS1123_SUBDOMAIN = re.compile(
    r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
)
_LABEL_NAME = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$")
_PORT_NAME = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")

_NP_SPEC_KEYS = {"podSelector", "policyTypes", "ingress", "egress"}
_RULE_KEYS = {Direction.INGRESS: {"from", "ports"}, Direction.EGRESS: {"to", "ports"}}
_PEER_KEYS = {"podSelector", "namespaceSelector", "ipBlock"}
_PORT_KEYS = {"protocol", "port", "endPort"}
_SELECTOR_KEYS = {"matchLabels", "matchExpressions"}


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def iter_manifest_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files.extend(sorted(q for q in p.rglob("*") if q.suffix in (".yaml", ".yml")))
        elif p.is_file():
            files.append(p)
        else:
            raise ManifestError(f"manifest path does not exist: {p}")
    return files


def load_documents(paths: Iterable[str | Path]) -> list[tuple[dict, SourceRef]]:
    docs: list[tuple[dict, SourceRef]] = []
    for f in iter_manifest_files(paths):
        try:
            loaded = list(yaml.safe_load_all(f.read_text()))
        except yaml.YAMLError as exc:
            raise ManifestError(f"{f}: invalid YAML: {exc}") from exc
        for i, doc in enumerate(loaded):
            if doc is None:
                continue
            docs.append((doc, SourceRef(origin="manifest", path=str(f), document=i)))
    return docs


def _expand_lists(doc: Any, src: SourceRef) -> Iterator[tuple[dict, SourceRef]]:
    if not isinstance(doc, dict):
        raise ManifestError(f"{src.describe()}: document is not a mapping")
    if doc.get("kind") == "List" or (doc.get("kind", "").endswith("List") and "items" in doc):
        for item in doc.get("items") or []:
            yield from _expand_lists(item, src)
    else:
        yield doc, src


def parse_manifests(paths: Iterable[str | Path]) -> Inventory:
    paths = list(paths)
    inv = parse_documents(load_documents(paths))
    inv.sources = [str(p) for p in paths]
    return inv


def parse_documents(
    docs: Iterable[tuple[dict, SourceRef]], *, allow_duplicates: bool = False
) -> Inventory:
    inv = Inventory()
    seen: set[tuple[str, str, str]] = set()
    expanded = [item for doc, src in docs for item in _expand_lists(doc, src)]
    for doc, src in expanded:
        kind = doc.get("kind")
        api = str(doc.get("apiVersion", ""))
        meta = doc.get("metadata") or {}
        if not kind or not isinstance(meta, dict) or not meta.get("name"):
            raise ManifestError(f"{src.describe()}: object without kind or metadata.name")
        ns = meta.get("namespace") or "default"
        key = (kind, "" if kind == "Namespace" else ns, meta["name"])
        if key in seen and not allow_duplicates:
            raise ManifestError(f"{src.describe()}: duplicate object {kind} {ns}/{meta['name']}")
        seen.add(key)

        group = api.split("/")[0] if "/" in api else ""
        if kind == "Namespace":
            n = _parse_namespace(doc, src)
            inv.namespaces[n.name] = n
        elif kind == "NetworkPolicy" and api == "networking.k8s.io/v1":
            np_obj, notes = parse_network_policy(doc, src)
            inv.policies[np_obj.id] = np_obj
            inv.unsupported.extend(notes)
        elif (group, kind) in _FOREIGN_POLICY_KINDS:
            scope = _FOREIGN_POLICY_KINDS[(group, kind)]
            inv.unsupported.append(
                UnsupportedFeature(
                    object_ref=f"{kind} {ns + '/' if scope == 'namespace' else ''}{meta['name']}",
                    feature=f"{api} {kind}",
                    detail=(
                        "Policy object from another enforcement system; it may allow or deny "
                        "traffic beyond Kubernetes NetworkPolicy semantics."
                    ),
                    affected_namespaces=("*",) if scope == "cluster" else (ns,),
                    source=src,
                )
            )
        elif kind in _WORKLOAD_KINDS:
            w, notes = _parse_workload(doc, src)
            inv.workloads[w.id] = w
            inv.unsupported.extend(notes)
        elif kind == "Service":
            s, notes = _parse_service(doc, src)
            inv.services[s.id] = s
            inv.unsupported.extend(notes)
        else:
            inv.ignored_kinds[kind] = inv.ignored_kinds.get(kind, 0) + 1

    # Namespaces referenced but not declared: only the automatic
    # kubernetes.io/metadata.name label is known.
    referenced = {w.namespace for w in inv.workloads.values()} | {
        p.namespace for p in inv.policies.values()
    }
    for ns in sorted(referenced - set(inv.namespaces)):
        inv.namespaces[ns] = Namespace(
            name=ns,
            labels=(("kubernetes.io/metadata.name", ns),),
            labels_known=False,
            source=SourceRef(origin="generated"),
        )
    return inv


# --------------------------------------------------------------------------
# Object parsers
# --------------------------------------------------------------------------


def _parse_namespace(doc: dict, src: SourceRef) -> Namespace:
    meta = doc["metadata"]
    name = meta["name"]
    if not _DNS1123_LABEL.match(name) or len(name) > 63:
        raise ManifestError(f"{src.describe()}: invalid namespace name {name!r}")
    labels = _validate_labels(meta.get("labels") or {}, src, "metadata.labels")
    # Kubernetes (>=1.21) always sets this label; it cannot be overridden.
    labels["kubernetes.io/metadata.name"] = name
    return Namespace(name=name, labels=tuple(sorted(labels.items())), source=src)


def _pod_template(doc: dict) -> tuple[dict, dict]:
    kind = doc["kind"]
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return doc.get("metadata") or {}, spec
    if kind == "CronJob":
        tmpl = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
    else:
        tmpl = spec.get("template") or {}
    return tmpl.get("metadata") or {}, tmpl.get("spec") or {}


def _parse_workload(doc: dict, src: SourceRef) -> tuple[Workload, list[UnsupportedFeature]]:
    meta = doc["metadata"]
    ns = meta.get("namespace") or "default"
    tmeta, tspec = _pod_template(doc)
    labels = _validate_labels(tmeta.get("labels") or {}, src, "pod template labels")
    notes: list[UnsupportedFeature] = []

    if doc["kind"] in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
        sel = (doc.get("spec") or {}).get("selector") or {}
        selector = parse_selector(sel, src, "spec.selector")
        if not selector.matches(labels):
            raise ManifestError(
                f"{src.describe()}: {doc['kind']} {ns}/{meta['name']} selector does not match "
                "its pod template labels"
            )

    ports: list[ContainerPort] = []
    containers = list(tspec.get("containers") or []) + list(tspec.get("initContainers") or [])
    for c in containers:
        for p in c.get("ports") or []:
            number = p.get("containerPort")
            if not isinstance(number, int) or not 1 <= number <= 65535:
                raise ManifestError(f"{src.describe()}: invalid containerPort {number!r}")
            name = p.get("name")
            if name is not None and (not _PORT_NAME.match(str(name)) or len(str(name)) > 15):
                raise ManifestError(f"{src.describe()}: invalid port name {name!r}")
            proto = p.get("protocol", "TCP")
            if proto not in ("TCP", "UDP", "SCTP"):
                raise ManifestError(f"{src.describe()}: invalid protocol {proto!r}")
            ports.append(ContainerPort(container_port=number, name=name, protocol=proto))

    host_network = bool(tspec.get("hostNetwork", False))
    if host_network:
        notes.append(
            UnsupportedFeature(
                object_ref=f"{doc['kind']} {ns}/{meta['name']}",
                feature="hostNetwork",
                detail="Pods on the host network are not isolated by NetworkPolicy in the "
                "usual way; connectivity involving them is UNSUPPORTED.",
                affected_namespaces=(),
                source=src,
            )
        )
    annotations = {str(k): str(v) for k, v in (meta.get("annotations") or {}).items()}
    w = Workload(
        kind=doc["kind"],
        name=meta["name"],
        namespace=ns,
        labels=tuple(sorted(labels.items())),
        ports=tuple(ports),
        host_network=host_network,
        annotations=tuple(sorted(annotations.items())),
        source=src,
    )
    return w, notes


def _parse_service(doc: dict, src: SourceRef) -> tuple[Service, list[UnsupportedFeature]]:
    meta = doc["metadata"]
    ns = meta.get("namespace") or "default"
    spec = doc.get("spec") or {}
    notes: list[UnsupportedFeature] = []
    stype = spec.get("type", "ClusterIP")
    selector = spec.get("selector")
    if stype == "ExternalName" or selector is None:
        notes.append(
            UnsupportedFeature(
                object_ref=f"Service {ns}/{meta['name']}",
                feature="ExternalName service"
                if stype == "ExternalName"
                else "selector-less service",
                detail="Endpoints are not derived from pod labels; traffic through this "
                "Service is not modelled.",
                affected_namespaces=(),
                source=src,
            )
        )
    ports = []
    for p in spec.get("ports") or []:
        port = p.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ManifestError(f"{src.describe()}: invalid service port {port!r}")
        target = p.get("targetPort", port)
        ports.append(
            ServicePort(
                port=port, target_port=target, name=p.get("name"), protocol=p.get("protocol", "TCP")
            )
        )
    sel = (
        None
        if selector is None
        else tuple(sorted({str(k): str(v) for k, v in selector.items()}.items()))
    )
    return (
        Service(
            name=meta["name"],
            namespace=ns,
            selector=sel,
            ports=tuple(ports),
            type=stype,
            source=src,
        ),
        notes,
    )


def parse_network_policy(
    doc: dict, src: SourceRef
) -> tuple[NetworkPolicy, list[UnsupportedFeature]]:
    """Parse and strictly validate a networking.k8s.io/v1 NetworkPolicy."""
    meta = doc.get("metadata") or {}
    name = meta.get("name", "")
    ns = meta.get("namespace") or "default"
    where = f"{src.describe()} NetworkPolicy {ns}/{name}"
    if not _DNS1123_SUBDOMAIN.match(name) or len(name) > 253:
        raise ManifestError(f"{where}: invalid name")
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        raise ManifestError(f"{where}: missing spec")
    notes: list[UnsupportedFeature] = []
    for key in sorted(set(spec) - _NP_SPEC_KEYS):
        notes.append(
            UnsupportedFeature(
                object_ref=f"NetworkPolicy {ns}/{name}",
                feature=f"spec.{key}",
                detail="Unknown NetworkPolicy field; its effect is not modelled.",
                affected_namespaces=(ns,),
                source=src,
            )
        )
    if "podSelector" not in spec:
        raise ManifestError(f"{where}: spec.podSelector is required")
    pod_selector = parse_selector(spec["podSelector"] or {}, src, "spec.podSelector")

    raw_types = spec.get("policyTypes")
    if raw_types is None:
        # Kubernetes default: Ingress always, Egress only if egress rules exist.
        types = [Direction.INGRESS]
        if spec.get("egress"):
            types.append(Direction.EGRESS)
    else:
        if not isinstance(raw_types, list) or not raw_types:
            raise ManifestError(f"{where}: policyTypes must be a non-empty list")
        types = []
        for t in raw_types:
            if t not in ("Ingress", "Egress"):
                raise ManifestError(f"{where}: invalid policyType {t!r}")
            if Direction(t) not in types:
                types.append(Direction(t))

    rules: dict[Direction, list[PolicyRule]] = {Direction.INGRESS: [], Direction.EGRESS: []}
    for direction, field in ((Direction.INGRESS, "ingress"), (Direction.EGRESS, "egress")):
        raw_rules = spec.get(field)
        if raw_rules is None:
            continue
        if not isinstance(raw_rules, list):
            raise ManifestError(f"{where}: spec.{field} must be a list")
        if direction not in types and raw_rules:
            # The API server accepts this, but the rules have no effect.
            notes.append(
                UnsupportedFeature(
                    object_ref=f"NetworkPolicy {ns}/{name}",
                    feature=f"spec.{field} without policyType {direction}",
                    detail="Rules are ignored by Kubernetes because the policy type is not listed.",
                    affected_namespaces=(),
                    source=src,
                )
            )
        for i, raw in enumerate(raw_rules):
            rules[direction].append(
                _parse_rule(raw or {}, direction, src, f"{where} {field}[{i}]", notes, ns, name)
            )

    labels = {str(k): str(v) for k, v in (meta.get("labels") or {}).items()}
    annotations = {str(k): str(v) for k, v in (meta.get("annotations") or {}).items()}
    return (
        NetworkPolicy(
            name=name,
            namespace=ns,
            pod_selector=pod_selector,
            policy_types=tuple(types),
            ingress=tuple(rules[Direction.INGRESS]) if Direction.INGRESS in types else (),
            egress=tuple(rules[Direction.EGRESS]) if Direction.EGRESS in types else (),
            labels=tuple(sorted(labels.items())),
            annotations=tuple(sorted(annotations.items())),
            source=src,
        ),
        notes,
    )


def _parse_rule(raw, direction, src, where, notes, ns, name) -> PolicyRule:
    if not isinstance(raw, dict):
        raise ManifestError(f"{where}: rule must be a mapping")
    for key in sorted(set(raw) - _RULE_KEYS[direction]):
        if key in ("from", "to"):
            raise ManifestError(f"{where}: '{key}' is not valid in a {direction} rule")
        notes.append(
            UnsupportedFeature(
                object_ref=f"NetworkPolicy {ns}/{name}",
                feature=f"rule field {key}",
                detail="Unknown rule field; its effect is not modelled.",
                affected_namespaces=(ns,),
                source=src,
            )
        )
    peer_field = "from" if direction == Direction.INGRESS else "to"
    peers = []
    for j, peer in enumerate(raw.get(peer_field) or []):
        peers.append(_parse_peer(peer, src, f"{where} {peer_field}[{j}]"))
    ports = []
    for j, port in enumerate(raw.get("ports") or []):
        ports.append(_parse_port(port, src, f"{where} ports[{j}]"))
    return PolicyRule(peers=tuple(peers), ports=tuple(ports))


def _parse_peer(raw, src, where) -> PolicyPeer:
    if not isinstance(raw, dict):
        raise ManifestError(f"{where}: peer must be a mapping")
    unknown = set(raw) - _PEER_KEYS
    if unknown:
        raise ManifestError(f"{where}: unknown peer fields {sorted(unknown)}")
    if not raw:
        raise ManifestError(f"{where}: peer must set podSelector, namespaceSelector or ipBlock")
    if "ipBlock" in raw:
        if len(raw) > 1:
            raise ManifestError(f"{where}: ipBlock cannot be combined with selectors")
        block = raw["ipBlock"] or {}
        cidr = block.get("cidr")
        if not isinstance(cidr, str) or "/" not in cidr:
            raise ManifestError(f"{where}: ipBlock.cidr must be a CIDR")
        return PolicyPeer(ip_block=IPBlock(cidr=cidr, except_=tuple(block.get("except") or ())))
    pod = (
        parse_selector(raw["podSelector"] or {}, src, f"{where}.podSelector")
        if "podSelector" in raw
        else None
    )
    nss = (
        parse_selector(raw["namespaceSelector"] or {}, src, f"{where}.namespaceSelector")
        if "namespaceSelector" in raw
        else None
    )
    return PolicyPeer(pod_selector=pod, namespace_selector=nss)


def _parse_port(raw, src, where) -> PolicyPort:
    if not isinstance(raw, dict):
        raise ManifestError(f"{where}: port must be a mapping")
    unknown = set(raw) - _PORT_KEYS
    if unknown:
        raise ManifestError(f"{where}: unknown port fields {sorted(unknown)}")
    proto = raw.get("protocol", "TCP")
    if proto not in ("TCP", "UDP", "SCTP"):
        raise ManifestError(f"{where}: invalid protocol {proto!r}")
    port = raw.get("port")
    end = raw.get("endPort")
    if isinstance(port, bool):
        raise ManifestError(f"{where}: invalid port {port!r}")
    if isinstance(port, int):
        if not 1 <= port <= 65535:
            raise ManifestError(f"{where}: port out of range")
    elif isinstance(port, str):
        if port.isdigit():
            port = int(port)
        elif not _PORT_NAME.match(port) or len(port) > 15:
            raise ManifestError(f"{where}: invalid named port {port!r}")
    elif port is not None:
        raise ManifestError(f"{where}: invalid port {port!r}")
    if end is not None:
        if not isinstance(port, int):
            raise ManifestError(f"{where}: endPort requires a numeric port")
        if not isinstance(end, int) or not port <= end <= 65535:
            raise ManifestError(f"{where}: endPort must be >= port and <= 65535")
    return PolicyPort(protocol=proto, port=port, end_port=end)


def parse_selector(raw, src: SourceRef, where: str) -> LabelSelector:
    if not isinstance(raw, dict):
        raise ManifestError(f"{src.describe()} {where}: selector must be a mapping")
    unknown = set(raw) - _SELECTOR_KEYS
    if unknown:
        raise ManifestError(f"{src.describe()} {where}: unknown selector fields {sorted(unknown)}")
    labels = _validate_labels(raw.get("matchLabels") or {}, src, where)
    exprs = []
    for e in raw.get("matchExpressions") or []:
        op = e.get("operator")
        key = e.get("key")
        values = e.get("values") or []
        if op not in ("In", "NotIn", "Exists", "DoesNotExist"):
            raise ManifestError(f"{src.describe()} {where}: invalid operator {op!r}")
        if not isinstance(key, str) or not _valid_label_key(key):
            raise ManifestError(f"{src.describe()} {where}: invalid key {key!r}")
        if op in ("In", "NotIn") and not values:
            raise ManifestError(f"{src.describe()} {where}: operator {op} requires values")
        if op in ("Exists", "DoesNotExist") and values:
            raise ManifestError(f"{src.describe()} {where}: operator {op} must not have values")
        for v in values:
            if not _valid_label_value(str(v)):
                raise ManifestError(f"{src.describe()} {where}: invalid label value {v!r}")
        exprs.append(
            LabelSelectorRequirement(key=key, operator=op, values=tuple(str(v) for v in values))
        )
    return LabelSelector.of(labels, exprs)


def _valid_label_key(key: str) -> bool:
    if "/" in key:
        prefix, name = key.split("/", 1)
        if not prefix or len(prefix) > 253 or not _DNS1123_SUBDOMAIN.match(prefix):
            return False
    else:
        name = key
    return 0 < len(name) <= 63 and bool(_LABEL_NAME.match(name))


def _valid_label_value(value: str) -> bool:
    return value == "" or (len(value) <= 63 and bool(_LABEL_NAME.match(value)))


def _validate_labels(raw, src: SourceRef, where: str) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise ManifestError(f"{src.describe()} {where}: labels must be a mapping")
    out: dict[str, str] = {}
    for k, v in raw.items():
        k = str(k)
        v = "" if v is None else str(v).lower() if isinstance(v, bool) else str(v)
        if not _valid_label_key(k):
            raise ManifestError(f"{src.describe()} {where}: invalid label key {k!r}")
        if not _valid_label_value(v):
            raise ManifestError(f"{src.describe()} {where}: invalid label value {v!r}")
        out[k] = v
    return out


def validate_policy_document(doc: dict) -> list[str]:
    """Return validation errors for a generated NetworkPolicy document."""
    if doc.get("apiVersion") != "networking.k8s.io/v1" or doc.get("kind") != "NetworkPolicy":
        return ["not a networking.k8s.io/v1 NetworkPolicy"]
    try:
        _, notes = parse_network_policy(doc, SourceRef(origin="generated"))
    except ManifestError as exc:
        return [str(exc)]
    return [f"unsupported: {n.feature}" for n in notes if n.affected_namespaces]
