"""Runtime verification on the disposable cluster (trusted component).

For every declared constraint the verifier runs real TCP probes *from the
actual source workload pod* and interprets them conservatively:

* a refused/timed-out connection only counts as BLOCKED when the target
  listener is confirmed healthy (checked from inside the target pod) and
  NetworkPolicy enforcement is confirmed by the canary test;
* DNS failures and probe errors are INCONCLUSIVE, never BLOCKED;
* results are sampled until two consecutive rounds agree, so a policy change
  that is still propagating is not mistaken for the final state.

Observations are compared with the model's prediction for the same state;
disagreements are reported as MODEL_MISMATCH and are never silently resolved
in favour of either side.
"""

from __future__ import annotations

import json
import time
import uuid

from pydantic import BaseModel, Field

from clavure.core.analysis import Analysis
from clavure.core.constraints import Scenario
from clavure.core.models import Verdict
from clavure.runtime.environment import TestEnvironment
from clavure.verification.evidence import (
    Observed,
    Outcome,
    ProbeRecord,
    interpret_probe,
    now,
    outcome_for,
)

PROBE = ["python", "/app/app.py", "probe"]


class RuntimeCheck(BaseModel):
    constraint_id: str
    kind: str
    source: str
    destination: str
    expected: Observed
    observed: Observed
    outcome: Outcome
    probe_ids: list[str]
    model_verdicts: dict[str, str] = Field(default_factory=dict)
    detail: str = ""


class Mismatch(BaseModel):
    source: str
    destination: str
    port: int
    model_verdict: str
    observed: Observed
    probe_ids: list[str]
    explanation: str


class StateCheckResult(BaseModel):
    workload: str
    table: str
    found: bool
    raw: str


class WorkflowResult(BaseModel):
    id: str
    outcome: Outcome
    timestamp: str = Field(default_factory=now)
    correlation_id: str
    http_status: int | None
    response: dict | None
    state_checks: list[StateCheckResult]
    detail: str = ""


class RuntimeReport(BaseModel):
    phase: str
    timestamp: str = Field(default_factory=now)
    preflight: dict
    health: dict
    checks: list[RuntimeCheck]
    workflows: list[WorkflowResult]
    mismatches: list[Mismatch]
    probes: list[ProbeRecord]
    settle_rounds: int
    outcome: Outcome

    def check(self, cid: str) -> RuntimeCheck:
        return next(c for c in self.checks if c.constraint_id == cid)


class RuntimeVerifier:
    def __init__(self, env: TestEnvironment, scenario: Scenario, probe_timeout: float = 3.0):
        self.env = env
        self.kube = env.kube
        self.scenario = scenario
        self.probe_timeout = probe_timeout
        self.preflight_result: dict | None = None

    # ------------------------------------------------------------------
    @property
    def enforcement_confirmed(self) -> bool:
        return bool(self.preflight_result and self.preflight_result["enforcement_confirmed"])

    def preflight(self) -> dict:
        identity = self.env.controller.verify_identity()
        configured = "--disable-network-policy" not in identity["k3s_node_args"]
        canary = self.env.canary()
        self.preflight_result = {
            "timestamp": now(),
            "cluster_identity": identity,
            "network_policy_controller": "k3s embedded (kube-router) network policy controller",
            "controller_configured": configured,
            "canary": canary,
            "enforcement_confirmed": configured and canary["confirmed"],
        }
        return self.preflight_result

    def _pod(self, logical: str) -> dict:
        ref = self.scenario.workloads[logical]
        dep = self.kube.get_json("deployment", ref.deployment, "-n", ref.namespace)
        return self.kube.ready_pod(ref.namespace, dep["spec"]["selector"]["matchLabels"])

    def _service(self, logical: str) -> dict | None:
        ref = self.scenario.workloads[logical]
        if not ref.service:
            return None
        return self.kube.get_json("service", ref.service, "-n", ref.namespace)

    def health(self) -> dict:
        out = {}
        for logical, ref in self.scenario.workloads.items():
            entry: dict = {"workload": ref.workload_id}
            try:
                pod = self._pod(logical)
            except Exception as exc:
                entry.update(ready=False, error=str(exc))
                out[logical] = entry
                continue
            name = pod["metadata"]["name"]
            ports = sorted(
                {
                    p["containerPort"]
                    for c in pod["spec"]["containers"]
                    for p in c.get("ports", [])
                    if p.get("protocol", "TCP") == "TCP"
                }
            )
            listeners = {}
            for port in ports:
                r = self.kube.exec(
                    ref.namespace,
                    name,
                    [*PROBE, "--host", "127.0.0.1", "--port", str(port), "--timeout", "2"],
                    timeout=20,
                )
                raw = _parse(r.stdout)
                listeners[str(port)] = raw.get("status") == "CONNECTED"
            entry.update(
                ready=True,
                pod=name,
                pod_ip=pod["status"]["podIP"],
                listeners=listeners,
                endpoints=self.kube.endpoints_ready(ref.namespace, ref.service)
                if ref.service
                else None,
            )
            out[logical] = entry
        return out

    # ------------------------------------------------------------------
    def _probe(
        self,
        src_logical: str,
        src_pod: dict,
        dst_logical: str,
        host: str,
        port: int,
        via: str,
        healthy: bool,
    ) -> ProbeRecord:
        ns = self.scenario.workloads[src_logical].namespace
        cmd = [
            *PROBE,
            "--host",
            host,
            "--port",
            str(port),
            "--timeout",
            str(self.probe_timeout),
            "--send",
            "PING",
        ]
        r = self.kube.exec(
            ns, src_pod["metadata"]["name"], cmd, timeout=int(self.probe_timeout) + 20
        )
        raw = (
            _parse(r.stdout)
            if r.returncode == 0
            else {"status": "EXEC_ERROR", "error": r.stderr[-300:]}
        )
        obs, reason = interpret_probe(
            raw, target_healthy=healthy, enforcement_confirmed=self.enforcement_confirmed
        )
        return ProbeRecord(
            actor=self.scenario.workloads[src_logical].workload_id,
            identity_kind="workload-pod",
            executed_in=f"{ns}/{src_pod['metadata']['name']}",
            target=self.scenario.workloads[dst_logical].workload_id,
            target_host=host,
            port=port,
            via=via,
            command=cmd,
            exec_returncode=r.returncode,
            raw=raw,
            interpretation=obs,
            reason=reason,
        ).finalize()

    def _plan_probes(self, health: dict) -> list[tuple]:
        """(constraint, src, dst, host, port, via, target_port, healthy) tuples."""
        plan = []
        for c in self.scenario.required:
            dst_ref = self.scenario.workloads[c.destination]
            svc = self._service(c.destination)
            h = health[c.destination]
            sp = next(
                (p for p in (svc or {}).get("spec", {}).get("ports", []) if p["port"] == c.port),
                None,
            )
            target_port = _target_port(sp, self._pod(c.destination)) if sp else c.port
            healthy = h.get("ready") and h.get("listeners", {}).get(str(target_port), False)
            host = f"{dst_ref.service}.{dst_ref.namespace}.svc.cluster.local"
            plan.append(
                (c.id, c.source, c.destination, host, c.port, "service-dns", target_port, healthy)
            )
        for c in self.scenario.forbidden:
            h = health[c.destination]
            dst_pod = self._pod(c.destination)
            ports = (
                sorted(
                    {
                        p["containerPort"]
                        for ct in dst_pod["spec"]["containers"]
                        for p in ct.get("ports", [])
                        if p.get("protocol", "TCP") == "TCP"
                    }
                )
                if c.port == "any"
                else [c.port]
            )
            svc = self._service(c.destination)
            ref = self.scenario.workloads[c.destination]
            for port in ports:
                healthy = h.get("ready") and h.get("listeners", {}).get(str(port), False)
                plan.append(
                    (
                        c.id,
                        c.source,
                        c.destination,
                        dst_pod["status"]["podIP"],
                        port,
                        "pod-ip",
                        port,
                        healthy,
                    )
                )
                for sp in (svc or {}).get("spec", {}).get("ports", []):
                    if _target_port(sp, dst_pod) == port:
                        host = f"{ref.service}.{ref.namespace}.svc.cluster.local"
                        plan.append(
                            (
                                c.id,
                                c.source,
                                c.destination,
                                host,
                                sp["port"],
                                "service-dns",
                                port,
                                healthy,
                            )
                        )
        return plan

    def _round(self, plan: list[tuple]) -> list[tuple[tuple, ProbeRecord]]:
        pods: dict[str, dict] = {}
        out = []
        for item in plan:
            _, src, dst, host, port, via, _, healthy = item
            if src not in pods:
                pods[src] = self._pod(src)
            out.append((item, self._probe(src, pods[src], dst, host, port, via, healthy)))
        return out

    def verify(
        self,
        phase: str,
        model: Analysis | None = None,
        *,
        max_rounds: int = 5,
        settle_delay: float = 2.0,
    ) -> RuntimeReport:
        if self.preflight_result is None:
            self.preflight()
        time.sleep(settle_delay)
        health = self.health()
        plan = self._plan_probes(health)
        rounds: list[list[tuple[tuple, ProbeRecord]]] = []
        while len(rounds) < max_rounds:
            rounds.append(self._round(plan))
            if len(rounds) >= 2 and [p.interpretation for _, p in rounds[-1]] == [
                p.interpretation for _, p in rounds[-2]
            ]:
                break
            time.sleep(settle_delay)
        final = rounds[-1]
        probes = [p for r in rounds for _, p in r]

        checks: list[RuntimeCheck] = []
        mismatches: list[Mismatch] = []
        model_conn = {}
        if model is not None:
            model_conn = {(c.source, c.destination, c.port): c for c in model.matrix}
        kinds = {c.id: "required" for c in self.scenario.required} | {
            c.id: "forbidden" for c in self.scenario.forbidden
        }
        for cid, kind in kinds.items():
            items = [(it, p) for it, p in final if it[0] == cid]
            interps = {p.interpretation for _, p in items}
            if kind == "required":
                expected = Observed.ALLOWED
                observed = (
                    Observed.ALLOWED
                    if interps == {Observed.ALLOWED}
                    else (
                        Observed.BLOCKED if Observed.BLOCKED in interps else Observed.INCONCLUSIVE
                    )
                )
            else:
                expected = Observed.BLOCKED
                observed = (
                    Observed.ALLOWED
                    if Observed.ALLOWED in interps
                    else (
                        Observed.BLOCKED if interps == {Observed.BLOCKED} else Observed.INCONCLUSIVE
                    )
                )
            mv = {}
            for it, p in items:
                src_id = self.scenario.workloads[it[1]].workload_id
                dst_id = self.scenario.workloads[it[2]].workload_id
                conn = model_conn.get((src_id, dst_id, it[6]))
                if conn is None:
                    continue
                mv[f"{it[2]}:{it[6]}"] = str(conn.verdict)
                p.relevant_policies = conn.policies()
                predicted = {
                    Verdict.ALLOWED: Observed.ALLOWED,
                    Verdict.BLOCKED: Observed.BLOCKED,
                }.get(conn.verdict)
                if (
                    predicted
                    and p.interpretation != Observed.INCONCLUSIVE
                    and p.interpretation != predicted
                ):
                    mismatches.append(
                        Mismatch(
                            source=src_id,
                            destination=dst_id,
                            port=it[6],
                            model_verdict=str(conn.verdict),
                            observed=p.interpretation,
                            probe_ids=[p.id],
                            explanation=(
                                f"model predicted {conn.verdict} for {src_id} -> {dst_id}:{it[6]}, "
                                f"runtime observed {p.interpretation} via {p.via} {p.target_host}:{p.port}"
                            ),
                        )
                    )
            checks.append(
                RuntimeCheck(
                    constraint_id=cid,
                    kind=kind,
                    source=self.scenario.workload_id(items[0][0][1]) if items else "",
                    destination=self.scenario.workload_id(items[0][0][2]) if items else "",
                    expected=expected,
                    observed=observed,
                    outcome=outcome_for(expected, observed),
                    probe_ids=[p.id for _, p in items],
                    model_verdicts=mv,
                    detail="; ".join(
                        sorted(
                            {
                                f"{p.via} {p.target_host}:{p.port} -> {p.interpretation}"
                                for _, p in items
                            }
                        )
                    ),
                )
            )
        workflows = [self.run_workflow(wf.id) for wf in self.scenario.workflows]
        outcomes = {c.outcome for c in checks} | {w.outcome for w in workflows}
        overall = (
            Outcome.FAIL
            if Outcome.FAIL in outcomes
            else (Outcome.INCONCLUSIVE if Outcome.INCONCLUSIVE in outcomes else Outcome.PASS)
        )
        if not self.enforcement_confirmed and overall == Outcome.PASS:
            overall = Outcome.INCONCLUSIVE
        return RuntimeReport(
            phase=phase,
            preflight=self.preflight_result or {},
            health=health,
            checks=checks,
            workflows=workflows,
            mismatches=_dedupe(mismatches),
            probes=probes,
            settle_rounds=len(rounds),
            outcome=overall,
        )

    # ------------------------------------------------------------------
    def run_workflow(self, wf_id: str) -> WorkflowResult:
        wf = next(w for w in self.scenario.workflows if w.id == wf_id)
        cid = f"wf-{uuid.uuid4().hex[:10]}"
        ep = wf.entrypoint
        ref = self.scenario.workloads[ep.workload]
        pod = self._pod(ep.workload)
        cmd = [
            "python",
            "/app/app.py",
            "http",
            "--method",
            ep.method,
            "--url",
            f"http://127.0.0.1:8080{ep.path}",
        ]
        if ep.method == "POST":
            cmd += [
                "--data",
                json.dumps({"correlation_id": cid, "item": "synthetic-item", "amount": 12.5}),
            ]
        r = self.kube.exec(ref.namespace, pod["metadata"]["name"], cmd, timeout=40)
        resp = _parse(r.stdout)
        status = resp.get("status")
        body = resp.get("body") if isinstance(resp.get("body"), dict) else None
        ok = status == 200 and bool(body and body.get("ok"))
        state = []
        for sc in wf.state_checks:
            sref = self.scenario.workloads[sc.workload]
            spod = self._pod(sc.workload)
            q = self.kube.exec(
                sref.namespace,
                spod["metadata"]["name"],
                ["python", "/app/app.py", "dbquery", "--cmd", f"FIND {sc.table} {cid}"],
                timeout=20,
            )
            try:
                found = q.returncode == 0 and len(json.loads(q.stdout or "[]")) > 0
            except ValueError:
                found = False
            state.append(
                StateCheckResult(
                    workload=sref.workload_id,
                    table=sc.table,
                    found=found,
                    raw=q.stdout.strip()[:300],
                )
            )
        if r.returncode != 0 and status is None:
            outcome, detail = Outcome.INCONCLUSIVE, f"workflow driver failed: {r.stderr[-200:]}"
        elif ok and all(s.found for s in state):
            outcome, detail = Outcome.PASS, "HTTP 200 and every expected state change observed"
        else:
            missing = [f"{s.workload}:{s.table}" for s in state if not s.found]
            outcome = Outcome.FAIL
            detail = f"http_status={status}; ok={ok}; missing state changes={missing}"
        return WorkflowResult(
            id=wf.id,
            outcome=outcome,
            correlation_id=cid,
            http_status=status,
            response=body,
            state_checks=state,
            detail=detail,
        )


def _parse(stdout: str) -> dict:
    try:
        return json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else {}
    except (ValueError, IndexError):
        return {"status": "PARSE_ERROR", "error": stdout[-200:]}


def _target_port(service_port: dict, pod: dict) -> int | None:
    tp = service_port.get("targetPort", service_port["port"])
    if isinstance(tp, int):
        return tp
    if str(tp).isdigit():
        return int(tp)
    for c in pod["spec"]["containers"]:
        for p in c.get("ports", []):
            if p.get("name") == tp:
                return p["containerPort"]
    return None


def _dedupe(ms: list[Mismatch]) -> list[Mismatch]:
    merged: dict[tuple, Mismatch] = {}
    for m in ms:
        key = (m.source, m.destination, m.port, m.observed)
        if key in merged:
            merged[key].probe_ids.extend(m.probe_ids)
        else:
            merged[key] = m
    return list(merged.values())
