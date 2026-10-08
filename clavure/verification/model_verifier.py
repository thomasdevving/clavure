"""Independent deterministic model verifier (trusted component).

INDEPENDENCE RULE: this module must not import anything from ``clavure.core``,
``clavure.optimizer`` or ``clavure.adversarial``. It re-reads the raw YAML
manifests and the raw requirements file and re-implements the
NetworkPolicy semantics with a different algorithm:

* the reachability engine evaluates one (source, destination, port) query at
  a time by walking policies;
* this verifier first *compiles* every pod's ingress and egress allow-sets
  (sets of peer pods and port numbers) and then answers queries by set
  membership.

A bug in one implementation is therefore unlikely to be reproduced in the
other, and any disagreement between them fails verification closed
(see :func:`cross_check`).

Outcomes: PASS, FAIL, INCONCLUSIVE (the semantics cannot decide, e.g.
ipBlock), UNSUPPORTED (objects outside NetworkPolicy semantics present).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ALLOW, DENY, MAYBE, UNSUP = "ALLOW", "DENY", "INDETERMINATE", "UNSUPPORTED"
PASS, FAIL, INCONCLUSIVE, UNSUPPORTED = "PASS", "FAIL", "INCONCLUSIVE", "UNSUPPORTED"

_WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}
_FOREIGN_GROUPS = {
    "cilium.io",
    "projectcalico.org",
    "crd.projectcalico.org",
    "policy.networking.k8s.io",
    "security.istio.io",
}
_CLUSTER_SCOPED_FOREIGN = {
    "CiliumClusterwideNetworkPolicy",
    "GlobalNetworkPolicy",
    "AdminNetworkPolicy",
    "BaselineAdminNetworkPolicy",
    "ClusterNetworkPolicy",
}
_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
_LABEL_RE = re.compile(r"^([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?$")


@dataclass
class Pod:
    ns: str
    name: str
    labels: dict[str, str]
    ports: list[tuple[str | None, int, str]]

    @property
    def id(self) -> str:
        return f"{self.ns}/{self.name}"

    def tcp_ports(self) -> list[int]:
        return sorted({n for _, n, proto in self.ports if proto == "TCP"})

    def named(self, name: str, proto: str) -> int | None:
        for pname, n, pproto in self.ports:
            if pname == name and pproto == proto:
                return n
        return None


@dataclass
class World:
    ns_labels: dict[str, dict[str, str]] = field(default_factory=dict)
    declared_ns: set[str] = field(default_factory=set)
    pods: list[Pod] = field(default_factory=list)
    services: dict[str, dict] = field(default_factory=dict)
    policies: list[dict] = field(default_factory=list)
    unsupported_ns: set[str] = field(default_factory=set)
    unsupported_cluster: bool = False
    structural_errors: list[str] = field(default_factory=list)
    host_network: set[str] = field(default_factory=set)

    def pod(self, pid: str) -> Pod:
        return next(p for p in self.pods if p.id == pid)


def _docs(paths: list[str | Path]) -> list[dict]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw)
        files.extend(
            sorted(x for x in p.rglob("*") if x.suffix in (".yaml", ".yml")) if p.is_dir() else [p]
        )
    out: list[dict] = []

    def expand(d):
        if isinstance(d, dict) and str(d.get("kind", "")).endswith("List") and "items" in d:
            for i in d["items"] or []:
                expand(i)
        elif isinstance(d, dict):
            out.append(d)

    for f in files:
        for d in yaml.safe_load_all(f.read_text()):
            if d is not None:
                expand(d)
    return out


def load_world(paths: list[str | Path], extra_docs: list[dict] | None = None) -> World:
    w = World()
    for d in _docs(paths) + list(extra_docs or []):
        kind, api = d.get("kind"), str(d.get("apiVersion", ""))
        meta = d.get("metadata") or {}
        ns = meta.get("namespace") or "default"
        group = api.split("/")[0] if "/" in api else ""
        if kind == "Namespace":
            labels = {str(k): str(v) for k, v in (meta.get("labels") or {}).items()}
            labels["kubernetes.io/metadata.name"] = meta["name"]
            w.ns_labels[meta["name"]] = labels
            w.declared_ns.add(meta["name"])
        elif kind == "NetworkPolicy" and api == "networking.k8s.io/v1":
            w.structural_errors.extend(_check_policy(d))
            unknown = set(d.get("spec") or {}) - {
                "podSelector",
                "policyTypes",
                "ingress",
                "egress",
            }
            if unknown:
                w.unsupported_ns.add(ns)
            w.policies.append(d)
        elif group in _FOREIGN_GROUPS:
            if kind in _CLUSTER_SCOPED_FOREIGN:
                w.unsupported_cluster = True
            else:
                w.unsupported_ns.add(ns)
        elif kind in _WORKLOADS:
            spec = d.get("spec") or {}
            if kind == "Pod":
                tmeta, tspec = meta, spec
            elif kind == "CronJob":
                t = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
                tmeta, tspec = t.get("metadata") or {}, t.get("spec") or {}
            else:
                t = spec.get("template") or {}
                tmeta, tspec = t.get("metadata") or {}, t.get("spec") or {}
            ports = []
            for c in (tspec.get("containers") or []) + (tspec.get("initContainers") or []):
                for p in c.get("ports") or []:
                    ports.append((p.get("name"), int(p["containerPort"]), p.get("protocol", "TCP")))
            pod = Pod(
                ns,
                meta["name"],
                {str(k): str(v) for k, v in (tmeta.get("labels") or {}).items()},
                ports,
            )
            w.pods.append(pod)
            if tspec.get("hostNetwork"):
                w.host_network.add(pod.id)
        elif kind == "Service":
            w.services[f"{ns}/{meta['name']}"] = d.get("spec") or {}
    for p in w.pods:
        w.ns_labels.setdefault(p.ns, {"kubernetes.io/metadata.name": p.ns})
    return w


def _check_policy(d: dict) -> list[str]:
    errs = []
    meta = d.get("metadata") or {}
    name = f"{meta.get('namespace', 'default')}/{meta.get('name')}"
    if not meta.get("name") or not _NAME_RE.match(str(meta.get("name"))):
        errs.append(f"{name}: invalid metadata.name")
    spec = d.get("spec")
    if not isinstance(spec, dict) or "podSelector" not in spec:
        return [*errs, f"{name}: spec.podSelector missing"]
    for t in spec.get("policyTypes") or []:
        if t not in ("Ingress", "Egress"):
            errs.append(f"{name}: invalid policyType {t}")
    for field_name, peer_key in (("ingress", "from"), ("egress", "to")):
        for i, rule in enumerate(spec.get(field_name) or []):
            if not isinstance(rule, dict):
                errs.append(f"{name}: {field_name}[{i}] not a mapping")
                continue
            for peer in rule.get(peer_key) or []:
                if not peer or (("ipBlock" in peer) and len(peer) > 1):
                    errs.append(f"{name}: {field_name}[{i}] invalid peer {peer}")
                for sk in ("podSelector", "namespaceSelector"):
                    for k, v in ((peer.get(sk) or {}).get("matchLabels") or {}).items():
                        if not _LABEL_RE.match(str(v)) or len(str(v)) > 63:
                            errs.append(f"{name}: invalid label value {k}={v}")
            for port in rule.get("ports") or []:
                num = port.get("port")
                if isinstance(num, int) and not 1 <= num <= 65535:
                    errs.append(f"{name}: port {num} out of range")
                if port.get("endPort") is not None and not isinstance(num, int):
                    errs.append(f"{name}: endPort without numeric port")
                if port.get("protocol", "TCP") not in ("TCP", "UDP", "SCTP"):
                    errs.append(f"{name}: invalid protocol")
    return errs


# --------------------------------------------------------------------------
# Selector semantics (re-implemented)
# --------------------------------------------------------------------------


def _match(selector: dict, labels: dict[str, str]) -> bool:
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(str(k)) != str(v):
            return False
    for e in selector.get("matchExpressions") or []:
        k, op, vals = e["key"], e["operator"], [str(x) for x in (e.get("values") or [])]
        has = k in labels
        ok = {
            "In": has and labels.get(k) in vals,
            "NotIn": not has or labels.get(k) not in vals,
            "Exists": has,
            "DoesNotExist": not has,
        }.get(op)
        if not ok:
            return False
    return True


def _ns_match(w: World, selector: dict, ns: str) -> bool | None:
    keys = set(selector.get("matchLabels") or {}) | {
        e["key"] for e in selector.get("matchExpressions") or []
    }
    if ns not in w.declared_ns and keys - {"kubernetes.io/metadata.name"}:
        return None
    return _match(selector, w.ns_labels.get(ns, {"kubernetes.io/metadata.name": ns}))


def _types(spec: dict) -> set[str]:
    if spec.get("policyTypes"):
        return set(spec["policyTypes"])
    return {"Ingress", "Egress"} if spec.get("egress") else {"Ingress"}


@dataclass
class CompiledRule:
    peers_all: bool
    definite: set[str]
    maybe: set[str]
    ports: list[dict] | None  # None = all ports


@dataclass
class Compiled:
    isolated: dict[tuple[str, str], bool]
    rules: dict[tuple[str, str], list[CompiledRule]]


def compile_world(w: World) -> Compiled:
    isolated: dict[tuple[str, str], bool] = {}
    rules: dict[tuple[str, str], list[CompiledRule]] = {}
    for pod in w.pods:
        for direction in ("Ingress", "Egress"):
            isolated[(pod.id, direction)] = False
            rules[(pod.id, direction)] = []
    for pol in w.policies:
        meta, spec = pol.get("metadata") or {}, pol.get("spec") or {}
        pns = meta.get("namespace") or "default"
        types = _types(spec)
        targets = [
            p for p in w.pods if p.ns == pns and _match(spec.get("podSelector") or {}, p.labels)
        ]
        for direction, field_name, peer_key in (
            ("Ingress", "ingress", "from"),
            ("Egress", "egress", "to"),
        ):
            if direction not in types:
                continue
            compiled = []
            for rule in spec.get(field_name) or []:
                rule = rule or {}
                peers = rule.get(peer_key) or []
                definite: set[str] = set()
                maybe: set[str] = set()
                for peer in peers:
                    if "ipBlock" in peer:
                        maybe |= {p.id for p in w.pods}
                        continue
                    for cand in w.pods:
                        if "namespaceSelector" in peer:
                            ns_ok = _ns_match(w, peer["namespaceSelector"] or {}, cand.ns)
                        else:
                            ns_ok = cand.ns == pns
                        pod_ok = (
                            _match(peer["podSelector"] or {}, cand.labels)
                            if "podSelector" in peer
                            else True
                        )
                        if ns_ok is True and pod_ok:
                            definite.add(cand.id)
                        elif ns_ok is None and pod_ok:
                            maybe.add(cand.id)
                compiled.append(
                    CompiledRule(
                        peers_all=not peers,
                        definite=definite,
                        maybe=maybe - definite,
                        ports=rule.get("ports") or None,
                    )
                )
            for t in targets:
                isolated[(t.id, direction)] = True
                rules[(t.id, direction)].extend(compiled)
    return Compiled(isolated, rules)


def _port_ok(specs: list[dict] | None, port: int, dst: Pod) -> bool:
    if specs is None:
        return True
    for s in specs:
        if s.get("protocol", "TCP") != "TCP":
            continue
        p = s.get("port")
        if p is None:
            return True
        if isinstance(p, str) and not p.isdigit():
            if dst.named(p, "TCP") == port:
                return True
            continue
        p = int(p)
        end = s.get("endPort")
        if (end is not None and p <= port <= int(end)) or (end is None and p == port):
            return True
    return False


def query(w: World, c: Compiled, src: Pod, dst: Pod, port: int) -> str:
    if w.unsupported_cluster or src.ns in w.unsupported_ns or dst.ns in w.unsupported_ns:
        return UNSUP
    if src.id in w.host_network or dst.id in w.host_network:
        return UNSUP
    results = []
    for local, remote, direction in ((src, dst, "Egress"), (dst, src, "Ingress")):
        if not c.isolated[(local.id, direction)]:
            results.append(ALLOW)
            continue
        side = DENY
        for r in c.rules[(local.id, direction)]:
            if not _port_ok(r.ports, port, dst):
                continue
            if r.peers_all or remote.id in r.definite:
                side = ALLOW
                break
            if remote.id in r.maybe:
                side = MAYBE
        results.append(side)
    if DENY in results:
        return DENY
    if results == [ALLOW, ALLOW]:
        return ALLOW
    return MAYBE


# --------------------------------------------------------------------------
# Constraint verification
# --------------------------------------------------------------------------


@dataclass
class Check:
    constraint_id: str
    kind: str
    outcome: str
    expected: str
    observations: list[dict]
    detail: str = ""


@dataclass
class ModelVerificationReport:
    verifier: str = "clavure.verification.model_verifier (independent implementation)"
    manifest_sources: list[str] = field(default_factory=list)
    structural_errors: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    new_connectivity: list[str] = field(default_factory=list)
    baseline_compared: bool = False
    engine_disagreements: list[str] = field(default_factory=list)
    cross_checked: bool = False

    @property
    def outcome(self) -> str:
        if self.structural_errors or self.new_connectivity or self.engine_disagreements:
            return FAIL
        outcomes = {c.outcome for c in self.checks}
        for o in (FAIL, UNSUPPORTED, INCONCLUSIVE):
            if o in outcomes:
                return o
        return PASS

    def to_dict(self) -> dict:
        return {
            "verifier": self.verifier,
            "outcome": self.outcome,
            "manifest_sources": self.manifest_sources,
            "structural_errors": self.structural_errors,
            "checks": [c.__dict__ for c in self.checks],
            "baseline_compared": self.baseline_compared,
            "new_connectivity": self.new_connectivity,
            "cross_checked_against_engine": self.cross_checked,
            "engine_disagreements": self.engine_disagreements,
        }


def _scenario(path: str | Path) -> dict:
    doc = yaml.safe_load(Path(path).read_text())
    return doc["spec"]


def _resolve(spec: dict, w: World, logical: str) -> tuple[Pod | None, dict | None]:
    ref = spec["workloads"][logical]
    pid = f"{ref['namespace']}/{ref['deployment']}"
    pod = next((p for p in w.pods if p.id == pid), None)
    svc = w.services.get(f"{ref['namespace']}/{ref.get('service')}") if ref.get("service") else None
    return pod, svc


def _service_targets(w: World, svc: dict, svc_ns: str, port: int) -> list[tuple[Pod, int | None]]:
    sp = next((p for p in svc.get("ports") or [] if p.get("port") == port), None)
    if sp is None or svc.get("selector") is None:
        return []
    out = []
    for pod in w.pods:
        if pod.ns == svc_ns and all(
            pod.labels.get(k) == str(v) for k, v in svc["selector"].items()
        ):
            tp = sp.get("targetPort", port)
            if isinstance(tp, int) or (isinstance(tp, str) and tp.isdigit()):
                out.append((pod, int(tp)))
            else:
                out.append((pod, pod.named(tp, sp.get("protocol", "TCP"))))
    return out


def required_and_forbidden_pairs(spec: dict, w: World) -> tuple[list, list]:
    req_pairs, forb_pairs = [], []
    for r in spec.get("required") or []:
        src, _ = _resolve(spec, w, r["source"])
        dst, svc = _resolve(spec, w, r["destination"])
        if src is None or dst is None:
            req_pairs.append((r, src, []))
            continue
        if r.get("viaService", True) and svc is not None:
            ns_ = spec["workloads"][r["destination"]]["namespace"]
            req_pairs.append((r, src, _service_targets(w, svc, ns_, int(r["port"]))))
        else:
            req_pairs.append((r, src, [(dst, int(r["port"]))]))
    for f in spec.get("forbidden") or []:
        src, _ = _resolve(spec, w, f["source"])
        dst, _ = _resolve(spec, w, f["destination"])
        ports = (
            []
            if dst is None
            else (dst.tcp_ports() if f.get("port", "any") == "any" else [int(f["port"])])
        )
        forb_pairs.append((f, src, [(dst, p) for p in ports] if dst else []))
    return req_pairs, forb_pairs


def all_pairs(w: World, c: Compiled) -> dict[tuple[str, str, int], str]:
    out = {}
    for s in w.pods:
        for d in w.pods:
            if s.id == d.id:
                continue
            for port in d.tcp_ports():
                out[(s.id, d.id, port)] = query(w, c, s, d, port)
    return out


def verify(
    manifest_paths: list[str | Path],
    scenario_path: str | Path,
    *,
    baseline_paths: list[str | Path] | None = None,
    extra_docs: list[dict] | None = None,
    baseline_extra_docs: list[dict] | None = None,
) -> ModelVerificationReport:
    spec = _scenario(scenario_path)
    w = load_world(manifest_paths, extra_docs)
    comp = compile_world(w)
    rep = ModelVerificationReport(manifest_sources=[str(p) for p in manifest_paths])
    rep.structural_errors = list(w.structural_errors)
    req_pairs, forb_pairs = required_and_forbidden_pairs(spec, w)
    required_keys: set[tuple[str, str, int]] = set()

    for r, src, targets in req_pairs:
        obs = []
        if src is None or not targets or any(t[1] is None for t in targets):
            rep.checks.append(
                Check(
                    r["id"], "required", FAIL, "ALLOW", [], "unresolvable source/destination/port"
                )
            )
            continue
        for dst, port in targets:
            v = query(w, comp, src, dst, port)
            required_keys.add((src.id, dst.id, port))
            obs.append({"source": src.id, "destination": dst.id, "port": port, "result": v})
        results = {o["result"] for o in obs}
        outcome = (
            PASS
            if results == {ALLOW}
            else FAIL
            if DENY in results
            else UNSUPPORTED
            if UNSUP in results
            else INCONCLUSIVE
        )
        rep.checks.append(Check(r["id"], "required", outcome, "ALLOW", obs))

    for f, src, targets in forb_pairs:
        if src is None or not targets:
            rep.checks.append(
                Check(f["id"], "forbidden", FAIL, "DENY", [], "unresolvable source/destination")
            )
            continue
        obs = []
        for dst, port in targets:
            obs.append(
                {
                    "source": src.id,
                    "destination": dst.id,
                    "port": port,
                    "result": query(w, comp, src, dst, port),
                }
            )
        results = {o["result"] for o in obs}
        outcome = (
            PASS
            if results == {DENY}
            else FAIL
            if ALLOW in results
            else UNSUPPORTED
            if UNSUP in results
            else INCONCLUSIVE
        )
        rep.checks.append(Check(f["id"], "forbidden", outcome, "DENY", obs))

    if baseline_paths is not None:
        bw = load_world(baseline_paths, baseline_extra_docs)
        before = all_pairs(bw, compile_world(bw))
        after = all_pairs(w, comp)
        rep.baseline_compared = True
        for key, v in sorted(after.items()):
            prev = before.get(key, DENY)
            if key in required_keys:
                continue
            if (prev == DENY and v != DENY) or (prev in (MAYBE, UNSUP) and v == ALLOW):
                rep.new_connectivity.append(f"{key[0]} -> {key[1]}:{key[2]} ({prev} -> {v})")
    return rep


def cross_check(
    report: ModelVerificationReport, engine_verdicts: dict[tuple[str, str, int], str]
) -> None:
    """Compare against the primary engine. Any disagreement fails closed."""
    mapping = {"ALLOWED": ALLOW, "BLOCKED": DENY, "UNKNOWN": MAYBE, "UNSUPPORTED": UNSUP}
    report.cross_checked = True
    for check in report.checks:
        for o in check.observations:
            key = (o["source"], o["destination"], o["port"])
            ev = engine_verdicts.get(key)
            if ev is None:
                report.engine_disagreements.append(f"{key}: engine has no verdict")
            elif mapping[ev] != o["result"]:
                report.engine_disagreements.append(f"{key}: engine={ev} verifier={o['result']}")
