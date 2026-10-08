"""Standalone HTML report generated exclusively from Clavure's JSON artifacts.

Nothing in this module computes security results; it only renders what the
engine, optimizer and verifiers wrote. Missing artifacts are shown as
"not executed" rather than filled in.
"""

from __future__ import annotations

import html
import json
from importlib import resources
from pathlib import Path

ARTIFACTS = [
    "topology.json",
    "reachability.json",
    "security-findings.json",
    "permission-diff.json",
    "remediation-plan.json",
    "verification-report.json",
    "adversarial-results.json",
]


def _load(d: Path, name: str) -> dict | None:
    p = d / name
    return json.loads(p.read_text()) if p.exists() else None


def e(x) -> str:
    return html.escape("" if x is None else str(x))


def badge(text: str, kind: str | None = None) -> str:
    kind = kind or {
        "PASS": "ok",
        "SATISFIED": "ok",
        "ALLOWED": "info",
        "BLOCKED": "muted",
        "VALID": "ok",
        "FAIL": "bad",
        "VIOLATED": "bad",
        "REJECTED": "muted",
        "CRITICAL": "bad",
        "HIGH": "warn",
        "MEDIUM": "warn",
        "INFO": "muted",
        "LOW": "muted",
        "INCONCLUSIVE": "warn",
        "UNSUPPORTED": "warn",
        "UNDECIDED": "warn",
        "UNKNOWN": "warn",
        "EXECUTED": "ok",
        "SKIPPED": "muted",
        "FAILED": "bad",
        "REMEDIATION_VERIFIED": "ok",
        "NO_VIOLATION": "ok",
        "MODEL_VERIFIED_ONLY": "warn",
        "NO_VALID_REMEDIATION": "bad",
        "VERIFICATION_FAILED": "bad",
        "NOT_IMPLEMENTED": "muted",
    }.get(str(text), "muted")
    return f'<span class="badge {kind}">{e(text)}</span>'


# --------------------------------------------------------------------------
# Graph rendering
# --------------------------------------------------------------------------


def _short(wid: str) -> str:
    return wid.split("/", 1)[-1]


def graph_svg(topology: dict, edges: list[dict], title: str) -> str:
    """Namespace columns, workloads as boxes, connectivity as arrows.

    ``edges`` items: {source, destination, port, style, label}
    style in: required, forbidden-allowed, new, remediated, allowed
    """
    workloads = [n for n in topology["nodes"] if n.get("type") == "workload"]
    namespaces: list[str] = []
    for n in workloads:
        if n["namespace"] not in namespaces:
            namespaces.append(n["namespace"])
    order = {"clavure-shop": 0, "clavure-data": 1, "clavure-analytics": 2}
    namespaces.sort(key=lambda ns: (order.get(ns, 9), ns))
    col_w, row_h, box_w, box_h, top = 260, 92, 170, 46, 70
    pos: dict[str, tuple[float, float]] = {}
    max_rows = 1
    for ci, ns in enumerate(namespaces):
        members = sorted((n for n in workloads if n["namespace"] == ns), key=lambda n: n["name"])
        max_rows = max(max_rows, len(members))
        for ri, n in enumerate(members):
            pos[n["id"]] = (40 + ci * col_w + box_w / 2, top + ri * row_h + box_h / 2)
    width = 40 + len(namespaces) * col_w
    height = top + max_rows * row_h + 20
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{e(title)}" class="graph">'
    ]
    parts.append(
        "<defs>"
        + "".join(
            f'<marker id="arrow-{s}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
            f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="ah-{s}"/></marker>'
            for s in ("required", "forbidden", "new", "remediated", "allowed")
        )
        + "</defs>"
    )
    for ci, ns in enumerate(namespaces):
        x = 40 + ci * col_w - 18
        parts.append(
            f'<rect x="{x}" y="22" width="{box_w + 36}" height="{height - 30}" rx="10" class="ns"/>'
        )
        parts.append(f'<text x="{x + 12}" y="42" class="ns-label">{e(ns)}</text>')
    pair_count: dict[tuple, int] = {}
    for ed in edges:
        s, d = ed["source"], ed["destination"]
        if s not in pos or d not in pos:
            continue
        k = (s, d)
        idx = pair_count.get(k, 0)
        pair_count[k] = idx + 1
        (x1, y1), (x2, y2) = pos[s], pos[d]
        bend = 40 + idx * 18
        if abs(x1 - x2) < 1:  # same column: arc to the right
            sx, sy, ex, ey = x1 + box_w / 2, y1, x2 + box_w / 2, y2
            c1x, c2x = sx + bend + 30, ex + bend + 30
            path = f"M{sx},{sy} C{c1x},{sy} {c2x},{ey} {ex},{ey}"
            lx, ly = max(c1x, c2x) - 22, (sy + ey) / 2
        else:
            dirx = 1 if x2 > x1 else -1
            sx, ex = x1 + dirx * box_w / 2, x2 - dirx * box_w / 2
            off = (idx - 0.5) * 10 if pair_count[k] > 1 else 0
            mx = (sx + ex) / 2
            path = f"M{sx},{y1 + off} C{mx},{y1 + off - bend / 3} {mx},{y2 + off + bend / 3} {ex},{y2 + off}"
            lx, ly = mx, (y1 + y2) / 2 + off - 6
        style = ed["style"]
        marker = {"forbidden-allowed": "forbidden"}.get(style, style)
        parts.append(
            f'<path d="{path}" class="edge {style}" marker-end="url(#arrow-{marker})">'
            f"<title>{e(ed.get('tooltip', ''))}</title></path>"
        )
        if ed.get("label"):
            parts.append(
                f'<text x="{lx}" y="{ly}" class="edge-label {style}">{e(ed["label"])}</text>'
            )
    for n in workloads:
        x, y = pos[n["id"]]
        cls = "node protected" if n.get("protected") else "node"
        parts.append(
            f'<g class="{cls}"><rect x="{x - box_w / 2}" y="{y - box_h / 2}" width="{box_w}" '
            f'height="{box_h}" rx="8"/><text x="{x}" y="{y - 2}" class="node-label">'
            f'{e(n.get("logical_name") or n["name"])}</text><text x="{x}" y="{y + 14}" class="node-sub">'
            f"{'protected · ' if n.get('protected') else ''}{e(n.get('criticality', ''))}</text>"
            f"<title>{e(n['id'])}\nlabels: {e(json.dumps(n.get('labels', {})))}</title></g>"
        )
    parts.append("</svg>")
    return "".join(parts)


def _edge_key(src: str, dst: str, port) -> tuple:
    return (src, dst, int(port))


def _parse_edge(text: str) -> tuple:
    # "src -> dst:port/TCP"
    src, rest = text.split(" -> ")
    dst, portproto = rest.rsplit(":", 1)
    return (src, dst, int(portproto.split("/")[0]))


def before_after_edges(reach: dict, diff: dict | None, plan: dict | None) -> tuple[list, list]:
    constraint_kind: dict[tuple, str] = {}
    for c in reach.get("constraints", []):
        for conn in c["connections"]:
            constraint_kind[_edge_key(conn["source"], conn["destination"], conn["port"])] = c[
                "kind"
            ]
    new = set()
    if diff:
        new = {
            _edge_key(x["source"], x["destination"], x["port"]) for x in diff.get("expansions", [])
        }
    allowed = [c for c in reach["connections"] if c["verdict"] == "ALLOWED"]
    removed, added = set(), set()
    if plan and plan.get("selected"):
        removed = {_parse_edge(x) for x in plan["selected"]["connectivity_removed"]}
        added = {_parse_edge(x) for x in plan["selected"]["connectivity_added"]}

    def style_for(k, phase):
        kind = constraint_kind.get(k)
        if phase == "after" and k in removed:
            return "remediated"
        if kind == "forbidden":
            return "forbidden-allowed"
        if k in new and phase == "before":
            return "new"
        return "required" if kind == "required" else "allowed"

    before, after = [], []
    for c in allowed:
        k = _edge_key(c["source"], c["destination"], c["port"])
        tip = " | ".join([c["egress"]["explanation"], c["ingress"]["explanation"]])
        label = f":{c['port']}"
        sty = style_for(k, "before")
        if sty == "forbidden-allowed":
            label = f"FORBIDDEN :{c['port']}"
        elif sty == "new":
            label = f"NEW :{c['port']}"
        before.append(
            {
                "source": c["source"],
                "destination": c["destination"],
                "port": c["port"],
                "style": sty,
                "label": label,
                "tooltip": tip,
            }
        )
        sty_a = style_for(k, "after")
        after.append(
            {
                "source": c["source"],
                "destination": c["destination"],
                "port": c["port"],
                "style": sty_a,
                "label": f"blocked :{c['port']}" if sty_a == "remediated" else f":{c['port']}",
                "tooltip": tip,
            }
        )
    for k in added:
        after.append(
            {
                "source": k[0],
                "destination": k[1],
                "port": k[2],
                "style": "new",
                "label": f"NEW :{k[2]}",
            }
        )
    return before, after


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


def _findings_table(findings: list[dict]) -> str:
    if not findings:
        return '<p class="muted">No findings.</p>'
    rows = []
    for f in findings:
        ev = "".join(f"<li>{e(x)}</li>" for x in f.get("evidence", []))
        rules = "".join(f"<li><code>{e(x)}</code></li>" for x in f.get("permitting_rules", []))
        rows.append(
            f"<tr><td>{badge(f['severity'])}</td><td>{e(f['category'])}</td><td>{e(f['title'])}"
            f"<details><summary>Evidence</summary><ul>{ev}</ul>"
            + (f"<p>Permitting rules:</p><ul>{rules}</ul>" if rules else "")
            + f'<p class="muted small">{e(f.get("scope_note", ""))}</p></details></td></tr>'
        )
    return (
        "<table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _runtime_table(rt: dict) -> str:
    rows = []
    for c in rt["checks"]:
        model = ", ".join(f"{k}={v}" for k, v in c.get("model_verdicts", {}).items())
        rows.append(
            f"<tr><td><code>{e(c['constraint_id'])}</code></td><td>{e(_short(c['source']))} → "
            f"{e(_short(c['destination']))}</td><td>{badge(c['expected'], 'muted')}</td>"
            f"<td>{badge(c['observed'])}</td><td>{badge(c['outcome'])}</td><td class='small'>{e(model)}</td></tr>"
        )
    for w in rt["workflows"]:
        states = ", ".join(
            f"{_short(s['workload'])}.{s['table']}={'found' if s['found'] else 'MISSING'}"
            for s in w["state_checks"]
        )
        rows.append(
            f"<tr><td><code>{e(w['id'])}</code></td><td>business workflow</td><td>{badge('PASS', 'muted')}</td>"
            f"<td class='small'>HTTP {e(w['http_status'])}; {e(states)}</td><td>{badge(w['outcome'])}</td>"
            f"<td class='small'>{e(w['detail'])}</td></tr>"
        )
    table = (
        "<table><thead><tr><th>Check</th><th>Connection</th><th>Expected</th><th>Observed</th>"
        "<th>Outcome</th><th>Model / detail</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )
    mism = "".join(
        f"<li>{badge('MODEL MISMATCH', 'bad')} {e(m['explanation'])}</li>" for m in rt["mismatches"]
    )
    probes = "".join(
        f"<tr><td class='small'>{e(p['timestamp'])}</td><td class='small'>{e(p['executed_in'])}</td>"
        f"<td class='small'>{e(p['via'])} {e(p['target_host'])}:{e(p['port'])}</td><td>{badge(p['interpretation'])}</td>"
        f"<td class='small'>{e(p['raw'].get('status'))} — {e(p['reason'])}</td></tr>"
        for p in rt["probes"]
    )
    return (
        table
        + (f"<ul>{mism}</ul>" if mism else "")
        + f"<details><summary>{len(rt['probes'])} probe records ({rt['settle_rounds']} settling rounds)</summary>"
        "<table><thead><tr><th>Time</th><th>Executed in</th><th>Target</th><th>Result</th><th>Raw / reason</th>"
        f"</tr></thead><tbody>{probes}</tbody></table></details>"
    )


def _candidates(plan: dict) -> str:
    rows = []
    shown = [c for c in plan["candidates"] if c["valid"]][:8]
    shown += [c for c in plan["candidates"] if not c["valid"] and len(c["actions"]) == 1]
    sel = (plan.get("selected") or {}).get("id")
    for c in shown:
        acts = "<br>".join(e(a["description"]) for a in c["actions"])
        status = "VALID" if c["valid"] else "REJECTED"
        broken = [k for k, v in c.get("constraint_status", {}).items() if v != "SATISFIED"]
        impact = "all constraints satisfied" if not broken else "unsatisfied: " + ", ".join(broken)
        reasons = "<br>".join(e(r) for r in c["rejection_reasons"])
        cls = ' class="selected"' if c["id"] == sel else ""
        tag = " (coarse)" if c.get("coarse") else ""
        rows.append(
            f"<tr{cls}><td><code>{e(c['id'])}</code>{' ★' if c['id'] == sel else ''}</td><td>{badge(status)}</td>"
            f"<td>{c['cost']['total']}</td><td>{acts}{e(tag)}</td><td class='small'>{e(impact)}"
            f"{'<br>' + reasons if reasons else ''}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Plan</th><th>Verdict</th><th>Cost</th><th>Actions</th>"
        "<th>Constraint impact</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def generate_report(artifacts_dir: Path, out: Path | None = None) -> Path:
    d = Path(artifacts_dir)
    a = {name: _load(d, name) for name in ARTIFACTS}
    topo, reach, findings = a["topology.json"], a["reachability.json"], a["security-findings.json"]
    if not topo or not reach or not findings:
        raise FileNotFoundError(
            "topology.json, reachability.json and security-findings.json are required"
        )
    diff, plan, ver, adv = (
        a["permission-diff.json"],
        a["remediation-plan.json"],
        a["verification-report.json"],
        a["adversarial-results.json"],
    )
    before_edges, after_edges = before_after_edges(reach, diff, plan)
    verdict = (ver or {}).get("final_verdict", "ANALYSIS ONLY")
    sel = (plan or {}).get("selected")
    runtime = (ver or {}).get("runtime", [])

    sections = []
    cards = [
        ("Final verdict", badge(verdict)),
        ("Constraints violated", e(findings["summary"].get("constraints_violated"))),
        (
            "Selected remediation",
            e(sel["id"] + " — " + " + ".join(x["description"] for x in sel["actions"]))
            if sel
            else "none",
        ),
        (
            "Model verification",
            badge(
                (ver or {}).get("model_verification", {}).get("outcome", "NOT EXECUTED")
                if (ver or {}).get("model_verification")
                else "NOT EXECUTED"
            ),
        ),
        (
            "Runtime verification",
            badge(runtime[-1]["outcome"]) if runtime else badge("NOT EXECUTED", "muted"),
        ),
    ]
    sections.append(
        '<div class="cards">'
        + "".join(
            f'<div class="card"><div class="card-k">{k}</div><div class="card-v">{v}</div></div>'
            for k, v in cards
        )
        + "</div>"
    )

    legend = (
        '<p class="legend"><span class="sw required"></span>required <span class="sw allowed"></span>other allowed '
        '<span class="sw forbidden-allowed"></span>forbidden but allowed <span class="sw new"></span>newly '
        'introduced by the change <span class="sw remediated"></span>remediated (now blocked)</p>'
    )
    sections.append(
        '<section id="before"><h2>1 · Before — infrastructure and exposure</h2>'
        "<p>Allowed TCP connectivity derived from the manifests (hover an arrow for the policy evidence).</p>"
        + legend
        + graph_svg(topo, before_edges, "Before")
        + "<h3>Security findings</h3>"
        + _findings_table(findings["findings"])
        + "</section>"
    )
    if diff:
        rows = "".join(
            f"<tr><td>{e(_short(x['source']))} → {e(_short(x['destination']))}:{x['port']}</td><td>{badge(x['classification'], 'bad' if x['classification'] == 'FORBIDDEN' else 'muted')}</td>"
            f"<td>{e(x['before'])} → {e(x['after'])}</td><td class='small'>{'<br>'.join(e(r) for r in x['introduced_by'])}</td></tr>"
            for x in diff["expansions"]
        )
        sections.append(
            '<section id="change"><h2>2 · Permission change under review</h2>'
            f"<p>Policies added: {e(', '.join(diff['added_policies']) or 'none')}; modified: "
            f"{e(', '.join(diff['modified_policies']) or 'none')}; removed: {e(', '.join(diff['removed_policies']) or 'none')}.</p>"
            "<table><thead><tr><th>Newly permitted</th><th>Declared as</th><th>Verdict</th><th>Introduced by</th>"
            f"</tr></thead><tbody>{rows}</tbody></table></section>"
        )
    if runtime:
        pf = runtime[0]["preflight"]
        can = pf.get("canary", {})
        sections.append(
            '<section id="runtime-before"><h2>3 · Runtime test — before remediation</h2>'
            f"<p>Disposable k3d cluster <code>{e(', '.join(pf.get('cluster_identity', {}).get('nodes', [])))}</code>. "
            f"NetworkPolicy enforcement canary: baseline connect {badge(str(can.get('baseline_connected')))}, "
            f"blocked after deny {badge(str(can.get('blocked_after_deny')))} ({e(can.get('blocked_status'))}), "
            f"restored {badge(str(can.get('restored_after_delete')))} ⇒ enforcement confirmed "
            f"{badge('PASS' if pf.get('enforcement_confirmed') else 'FAIL')}.</p>"
            "<p>Probes run from inside the real source workload pods.</p>"
            + _runtime_table(runtime[0])
            + "</section>"
        )
    else:
        sections.append(
            '<section id="runtime-before"><h2>3 · Runtime test</h2><p class="muted">Runtime stages were '
            "not executed for this report. No runtime results are shown.</p></section>"
        )
    adv_status = (adv or {}).get("status", "NOT EXECUTED")
    sections.append(
        '<section id="adversarial"><h2>4 · Adversarial test</h2>'
        f"<p>{badge(adv_status)} {e((adv or {}).get('detail', 'No adversarial results exist.'))}</p></section>"
    )
    if plan:
        weights = ", ".join(f"{k} x {v}" for k, v in plan["cost_weights"].items())
        diff_text = (plan.get("rendered") or {}).get("diff") or ""
        sections.append(
            '<section id="options"><h2>5 · Remediation options</h2>'
            f"<p>{e(plan['selection_rationale'])}</p><p class='small muted'>Search: {e(json.dumps(plan['stats']))}. "
            f"Cost weights: {e(weights)}. Hard constraints are filters, never weighted.</p>"
            + _candidates(plan)
            + (
                f"<details open><summary>Selected change (diff)</summary><pre>{e(diff_text)}</pre></details>"
                if diff_text
                else ""
            )
            + "</section>"
        )
    after_parts = [
        '<section id="after"><h2>6 · After — verified access boundaries</h2>',
        legend,
        graph_svg(topo, after_edges, "After"),
    ]
    mv = (ver or {}).get("model_verification")
    if mv:
        rows = "".join(
            f"<tr><td><code>{e(c['constraint_id'])}</code></td><td>{badge(c['expected'], 'muted')}</td>"
            f"<td>{badge(c['outcome'])}</td></tr>"
            for c in mv["checks"]
        )
        after_parts.append(
            "<h3>Independent model verification</h3>"
            f"<p>{badge(mv['outcome'])} {e(mv['verifier'])}; cross-checked against engine: "
            f"{e(mv['cross_checked_against_engine'])}; disagreements: {len(mv['engine_disagreements'])}; "
            f"new connectivity vs. baseline: {len(mv['new_connectivity'])}.</p>"
            f"<table><thead><tr><th>Constraint</th><th>Expected</th><th>Outcome</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    if len(runtime) > 1:
        after_parts.append(
            f"<h3>Runtime verification — {e(runtime[-1]['phase'])}</h3>"
            + _runtime_table(runtime[-1])
        )
        for rt in runtime[1:-1]:
            after_parts.append(
                f"<details><summary>Earlier attempt: {e(rt['phase'])} — {e(rt['outcome'])}</summary>"
                + _runtime_table(rt)
                + "</details>"
            )
    after_parts.append("</section>")
    sections.append("".join(after_parts))
    if ver:
        stages = "".join(
            f"<tr><td class='small'>{e(s['timestamp'])}</td><td>{e(s['stage'])}</td><td>{badge(s['status'])}</td>"
            f"<td class='small'>{e(s['detail'])}</td></tr>"
            for s in ver["stages"]
        )
        drift = "".join(
            f"<li>{badge(f['severity'])} {e(f['title'])}</li>"
            for f in ver.get("drift_findings", [])
        )
        sections.append(
            '<section id="timeline"><h2>7 · Pipeline timeline</h2>'
            + (f"<h3>Configuration drift</h3><ul>{drift}</ul>" if drift else "")
            + f"<table><thead><tr><th>Time</th><th>Stage</th><th>Status</th><th>Detail</th></tr></thead><tbody>{stages}</tbody></table></section>"
        )
    lims = [
        *(plan or {}).get("limitations", []),
        "Runtime probes demonstrate L4 reachability from the tested pods only; application-level "
        "authorization is not evaluated.",
        "The demo databases are synthetic line-protocol emulators, not real database engines.",
    ]
    sections.append(
        '<section id="limits"><h2>8 · Limitations</h2><ul>'
        + "".join(f"<li>{e(x)}</li>" for x in lims)
        + "</ul></section>"
    )

    template = resources.files("clavure.reporting").joinpath("templates/report.html").read_text()
    page = (
        template.replace("{{title}}", "Clavure Security Report")
        .replace("{{scenario}}", e(topo.get("scenario")))
        .replace("{{generated}}", e(topo.get("generated_at")))
        .replace("{{fingerprint}}", e(topo.get("requirements_fingerprint")))
        .replace("{{content}}", "\n".join(sections))
    )
    target = out or (d / "clavure-report.html")
    target.write_text(page)
    return target
