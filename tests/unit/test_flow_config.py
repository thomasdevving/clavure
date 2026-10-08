"""Static checks of the GitLab Duo flow, agent config and CI configuration.

These check our files against rules taken from GitLab's documentation and the
Duo Workflow Service source (verified 2026-10-08):

* docs: doc/user/duo_agent_platform/flows/custom_flows_schema.md (restricted
  fields), ai-assist docs/flow_registry/v1.md (structure, routers, tool
  options), doc/.../flows/execution/agent-config-yaml.md (supported keys)
* tool names: ai-assist duo_workflow_service/tools/*.py ``name`` attributes

They cannot prove that GitLab accepts the flow; that requires a GitLab
instance with Duo Agent Platform enabled.
"""

from __future__ import annotations

import re

import yaml

from tests.conftest import ROOT

FLOW = yaml.safe_load((ROOT / "flows" / "clavure.yaml").read_text())

# Tool names verified in the ai-assist source (duo_workflow_service/tools).
VERIFIED_TOOLS = {
    "read_file",
    "read_files",
    "list_dir",
    "find_files",
    "edit_file",
    "create_file_with_contents",
    "mkdir",
    "get_merge_request",
    "list_merge_request_diffs",
    "create_merge_request",
    "update_merge_request",
    "create_merge_request_note",
    "list_all_merge_request_notes",
    "create_issue_note",
    "run_command",
    "run_git_command",
    "create_commit",
    "create_branch",
    "get_job_logs",
    "get_pipeline_failing_jobs",
    "get_repository_file",
}
WRITE_TOOLS = {"edit_file", "create_file_with_contents", "mkdir", "create_commit"}
COMPONENT_TYPES = {
    "AgentComponent",
    "DeterministicStepComponent",
    "OneOffComponent",
    "HumanInputComponent",
    "EndComponent",
    "AbortComponent",
}
AGENT_CONFIG_KEYS = {"image", "setup_script", "network_policy", "cache"}


def tools_of(component: dict) -> dict[str, dict]:
    out = {}
    for item in component.get("toolset", []):
        if isinstance(item, str):
            out[item] = {}
        else:
            ((name, opts),) = item.items()
            out[name] = opts or {}
    return out


def test_top_level_structure_and_restrictions():
    assert FLOW["version"] == "v1"
    assert FLOW["environment"] == "ambient"  # only value allowed for custom flows
    assert {"components", "routers", "flow", "prompts"} <= set(FLOW)
    assert not {"name", "description", "product_group"} & set(FLOW)


def test_components_and_prompts():
    names = [c["name"] for c in FLOW["components"]]
    assert len(names) == len(set(names))
    prompt_ids = {p["prompt_id"] for p in FLOW["prompts"]}
    for c in FLOW["components"]:
        assert not re.search(r"[:.]", c["name"])
        assert c["type"] in COMPONENT_TYPES
        assert "response_schema_id" not in c and "response_schema_version" not in c
        if c["type"] == "AgentComponent":
            assert c["prompt_id"] in prompt_ids
            assert c.get("prompt_version") is None  # local prompt
    for p in FLOW["prompts"]:
        assert "model" not in p
        assert "stop" not in (p.get("params") or {})
        assert {"prompt_id", "name", "unit_primitives", "prompt_template"} <= set(p)


def test_prompt_placeholders_are_provided_as_inputs():
    prompts = {p["prompt_id"]: p for p in FLOW["prompts"]}
    for c in FLOW["components"]:
        provided = {
            i["as"] if isinstance(i, dict) else i.split(":", 1)[-1] for i in c.get("inputs", [])
        }
        tmpl = prompts[c["prompt_id"]]["prompt_template"]
        used = set(re.findall(r"{{\s*(\w+)\s*}}", tmpl["system"] + tmpl["user"]))
        assert used <= provided, (c["name"], used - provided)


def test_routing_is_complete_and_reachable():
    names = {c["name"] for c in FLOW["components"]}
    edges: dict[str, set[str]] = {}
    for r in FLOW["routers"]:
        assert r["from"] in names
        targets = set(r["condition"]["routes"].values()) if "condition" in r else {r["to"]}
        assert targets <= names | {"end"}
        edges.setdefault(r["from"], set()).update(targets)
    entry = FLOW["flow"]["entry_point"]
    seen, stack = set(), [entry]
    while stack:
        n = stack.pop()
        if n in seen or n == "end":
            continue
        seen.add(n)
        stack.extend(edges.get(n, ()))
    assert seen == names
    assert all(n in edges for n in names)  # every component routes somewhere


def test_tools_are_verified_and_least_privilege():
    for c in FLOW["components"]:
        tools = tools_of(c)
        assert set(tools) <= VERIFIED_TOOLS, set(tools) - VERIFIED_TOOLS
        assert not set(tools) & WRITE_TOOLS, f"{c['name']} must not write files directly"
        if "run_command" in tools:
            assert tools["run_command"].get("program") in ("clavure", "git"), c["name"]
        assert "run_git_command" not in tools  # deprecated shim; git goes via pinned run_command
    by_name = {c["name"]: tools_of(c) for c in FLOW["components"]}
    assert by_name["clavure_analyst"]["run_command"]["program"] == "clavure"
    assert by_name["clavure_implementer"]["run_command"]["program"] == "clavure"
    assert by_name["clavure_publisher"]["run_command"]["program"] == "git"
    assert "create_merge_request" not in by_name["clavure_analyst"]


def test_agent_config_uses_documented_keys_and_no_cluster_credentials():
    cfg = yaml.safe_load((ROOT / ".gitlab" / "duo" / "agent-config.yml").read_text())
    assert set(cfg) <= AGENT_CONFIG_KEYS
    text = (ROOT / ".gitlab" / "duo" / "agent-config.yml").read_text().lower()
    assert "kubeconfig" not in text.replace("kubernetes credentials", "")


def test_codeowners_cover_trusted_files():
    owners = (ROOT / ".gitlab" / "CODEOWNERS").read_text()
    cfg = yaml.safe_load((ROOT / ".clavure.yaml").read_text())
    for path in cfg["trusted"]:
        assert f"/{path}" in owners or f"/{path.split('/')[0]}/" in owners, path
