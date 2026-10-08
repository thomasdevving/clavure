"""Render a selected plan into concrete manifest changes.

Modified and deleted policies are patched in the file and document they came
from (leading comments are preserved and an audit comment is added). New
policies go to a dedicated file. Objects that exist only in the live cluster
cannot be changed through git and are returned as out-of-band actions that a
human must perform.
"""

from __future__ import annotations

import difflib
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from clavure.optimizer.solver import CandidatePlan

_SEP = re.compile(r"^---[ \t]*$", re.MULTILINE)
GENERATED_FILE = "90-clavure-remediation.yaml"


@dataclass
class RenderResult:
    files_changed: list[str] = field(default_factory=list)
    out_of_band: list[str] = field(default_factory=list)
    diff: str = ""
    root: str = ""


def _split(text: str) -> list[str]:
    return _SEP.split(text)


def _identity(doc: dict) -> tuple[str, str, str]:
    meta = doc.get("metadata") or {}
    return (doc.get("kind", ""), meta.get("namespace") or "default", meta.get("name", ""))


class _K8sDumper(yaml.SafeDumper):
    """Indent block sequences the way Kubernetes manifests usually are."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def _represent_list(dumper: yaml.SafeDumper, data: list):
    # Short lists of scalars (policyTypes, label values) stay on one line, as
    # hand-written manifests usually have them; everything else is block style.
    flow = 0 < len(data) <= 4 and all(isinstance(x, str | int) for x in data)
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=flow)


_K8sDumper.add_representer(list, _represent_list)


def _dump(doc: dict) -> str:
    return yaml.dump(doc, Dumper=_K8sDumper, sort_keys=False, default_flow_style=False)


def _display(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def _leading_comments(chunk: str) -> str:
    lines = []
    for line in chunk.lstrip("\n").splitlines():
        if line.startswith("#") or not line.strip():
            lines.append(line)
        else:
            break
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def _patch_file(path: Path, edits: dict[tuple[str, str, str], tuple[str, dict | None]]) -> bool:
    text = path.read_text()
    chunks = _split(text)
    changed = False
    out_chunks = []
    for chunk in chunks:
        try:
            doc = yaml.safe_load(chunk)
        except yaml.YAMLError:
            doc = None
        ident = _identity(doc) if isinstance(doc, dict) else None
        if ident in edits:
            note, new_doc = edits.pop(ident)
            changed = True
            if new_doc is None:
                continue  # deleted
            header = _leading_comments(chunk)
            body = f"# Remediated by Clavure: {note}\n" + _dump(new_doc)
            out_chunks.append(
                ("\n" if out_chunks else "") + (header + "\n" if header else "") + body
            )
        else:
            out_chunks.append(chunk)
    if edits:
        missing = ", ".join("/".join(k) for k in edits)
        raise ValueError(f"{path}: could not locate documents for {missing}")
    if changed:
        new_text = "---".join(c if c.endswith("\n") or not c else c + "\n" for c in out_chunks)
        path.write_text(new_text.rstrip("\n") + "\n")
    return changed


def render_plan(
    plan: CandidatePlan,
    manifest_roots: list[str | Path],
    *,
    output_dir: str | Path | None = None,
    generated_dir: str | Path | None = None,
) -> RenderResult:
    """Apply ``plan`` to the manifests.

    With ``output_dir`` the manifest roots are copied there first and the copy
    is patched (the originals are untouched). Without it the files are
    patched in place.
    """
    roots = [Path(r) for r in manifest_roots]
    mapping: dict[Path, Path] = {}
    if output_dir is not None:
        out = Path(output_dir)
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        for i, r in enumerate(roots):
            dest = out / f"{i:02d}-{r.name}"
            if r.is_dir():
                shutil.copytree(r, dest)
            else:
                dest.mkdir(parents=True)
                shutil.copy2(r, dest / r.name)
            mapping[r.resolve()] = dest
    result = RenderResult(root=str(output_dir or ""))

    def target_for(src_path: str) -> Path:
        p = Path(src_path).resolve()
        for orig, dest in mapping.items():
            if orig.is_dir() and p == orig:
                return dest
            if orig.is_dir() and orig in p.parents:
                return dest / p.relative_to(orig)
            if p == orig:
                return dest / p.name
        return Path(src_path)

    before: dict[Path, str] = {}
    edits: dict[Path, dict] = {}
    note = plan.summary()
    for ch in plan.changes:
        if ch.origin == "live-cluster":
            result.out_of_band.append(
                f"{ch.change} {ch.policy}: object exists only in the live cluster"
            )
            continue
        if ch.change == "added":
            continue
        src_path = ch.source.split("#")[0] if ch.source else None
        if not src_path:
            raise ValueError(f"no source file recorded for {ch.policy}")
        tgt = target_for(src_path)
        ns, name = ch.policy.split("/", 1)
        edits.setdefault(tgt, {})[("NetworkPolicy", ns, name)] = (note, ch.manifest)

    for tgt, file_edits in edits.items():
        before[tgt] = tgt.read_text()
        if _patch_file(tgt, dict(file_edits)):
            result.files_changed.append(str(tgt))

    added = [ch for ch in plan.changes if ch.change == "added"]
    if added:
        gdir = Path(generated_dir) if generated_dir else roots[-1]
        if gdir.is_file():
            gdir = gdir.parent
        gdir = target_for(str(gdir)) if mapping else gdir
        gfile = gdir / GENERATED_FILE
        before[gfile] = gfile.read_text() if gfile.exists() else ""
        docs = [_dump(ch.manifest) for ch in added]
        header = f"# Generated by Clavure remediation: {note}\n"
        existing = before[gfile].rstrip("\n")
        gfile.write_text((existing + "\n---\n" if existing else "") + header + "---\n".join(docs))
        result.files_changed.append(str(gfile))

    diff_parts = []
    for path, old in before.items():
        new = path.read_text() if path.exists() else ""
        diff_parts.extend(
            difflib.unified_diff(
                old.splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile=f"a/{_display(path)}",
                tofile=f"b/{_display(path)}",
            )
        )
    result.diff = "".join(diff_parts)
    return result
