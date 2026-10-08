"""Dedicated, disposable k3d cluster controller (PRIVILEGED, trusted).

Safety properties:

* Clavure only ever talks to a cluster it created itself, through a
  kubeconfig file it owns (``.clavure/kubeconfig-<name>.yaml``). It never
  reads or modifies ``~/.kube/config`` or the user's current context; k3d is
  invoked with ``--kubeconfig-update-default=false`` and
  ``--kubeconfig-switch-context=false``.
* Every kubectl invocation passes ``--kubeconfig`` explicitly.
* :meth:`ClusterController.verify_identity` checks that the API server's
  nodes are the k3d nodes of this cluster before any mutation.
* The credentials of this controller are never passed to adversarial agents
  or to the restricted probe pods.

Environment knobs (all optional):

  CLAVURE_K3S_IMAGE          k3s image (default rancher/k3s:v1.34.1-k3s1)
  CLAVURE_K3S_CA_BUNDLE      CA bundle to mount as the node trust store
                             (needed behind TLS-intercepting egress proxies)
  CLAVURE_K3S_RESTRICT_OOM   "1" to install the restrict_oom_score_adj
                             containerd template (nested sandboxes)
  K3D_IMAGE_TOOLS            k3d helper image override (passed through)
  CLAVURE_K3D_API_HOST       host name under which the k3d API server is
                             reachable from where kubectl runs (e.g. "docker"
                             for GitLab docker-in-docker services); adds a TLS
                             SAN and rewrites the kubeconfig server address
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

# Pinned by digest (Docker Hub, 2026-10-08). k3d accepts tag@digest.
DEFAULT_K3S_IMAGE = "rancher/k3s:v1.34.1-k3s1@sha256:5e0707cfd1239b358ef73f3254bc3eadc027dd30cd5ec6ca41e29e47652a1b8c"
STATE_DIR = Path(".clavure")


class ClusterError(RuntimeError):
    pass


def _run(cmd: list[str], *, timeout: int = 300, input: bytes | None = None, check: bool = True):
    proc = subprocess.run(cmd, capture_output=True, timeout=timeout, input=input)
    if check and proc.returncode != 0:
        raise ClusterError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.decode(errors='replace')[-2000:]}"
        )
    return proc


@dataclass
class ClusterController:
    name: str = "clavure-test"
    k3s_image: str = DEFAULT_K3S_IMAGE
    ca_bundle: Path | None = None
    restrict_oom: bool = False
    api_host: str | None = None
    state_dir: Path = field(default_factory=lambda: STATE_DIR)

    @classmethod
    def from_env(cls, name: str = "clavure-test") -> ClusterController:
        ca = os.environ.get("CLAVURE_K3S_CA_BUNDLE")
        return cls(
            name=name,
            k3s_image=os.environ.get("CLAVURE_K3S_IMAGE", DEFAULT_K3S_IMAGE),
            ca_bundle=Path(ca) if ca else None,
            restrict_oom=os.environ.get("CLAVURE_K3S_RESTRICT_OOM") == "1",
            api_host=os.environ.get("CLAVURE_K3D_API_HOST") or None,
        )

    # ------------------------------------------------------------------
    @property
    def kubeconfig(self) -> Path:
        return (self.state_dir / f"kubeconfig-{self.name}.yaml").resolve()

    @property
    def server_container(self) -> str:
        return f"k3d-{self.name}-server-0"

    @staticmethod
    def tools_available() -> dict[str, bool]:
        return {t: shutil.which(t) is not None for t in ("docker", "k3d", "kubectl")}

    def docker_available(self) -> bool:
        if not shutil.which("docker"):
            return False
        return _run(["docker", "info"], timeout=30, check=False).returncode == 0

    def exists(self) -> bool:
        proc = _run(["k3d", "cluster", "list", "-o", "json"], timeout=60, check=False)
        if proc.returncode != 0:
            return False
        return any(c.get("name") == self.name for c in json.loads(proc.stdout or b"[]"))

    def create(self, wait_seconds: int = 240) -> None:
        if self.exists():
            self._write_kubeconfig()
            self.verify_identity()
            return
        self.state_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            "k3d",
            "cluster",
            "create",
            self.name,
            "--image",
            self.k3s_image,
            "--servers",
            "1",
            "--agents",
            "0",
            "--no-lb",
            "--kubeconfig-update-default=false",
            "--kubeconfig-switch-context=false",
            "--k3s-arg",
            "--disable=traefik@server:*",
            "--k3s-arg",
            "--disable=metrics-server@server:*",
            "--runtime-label",
            "clavure.io/disposable=true@server:*",
            "--wait",
            "--timeout",
            f"{wait_seconds}s",
        ]
        if self.api_host:
            cmd += [
                "--api-port",
                "0.0.0.0:6550",
                "--k3s-arg",
                f"--tls-san={self.api_host}@server:*",
            ]
        if self.ca_bundle:
            cmd += ["-v", f"{self.ca_bundle.resolve()}:/etc/ssl/certs/ca-certificates.crt@server:*"]
        if self.restrict_oom:
            tmpl = self.state_dir / "config-v3.toml.tmpl"
            tmpl.write_text(
                resources.files("clavure.runtime").joinpath("k3s/config-v3.toml.tmpl").read_text()
            )
            cmd += [
                "-v",
                f"{tmpl.resolve()}:/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl@server:*",
            ]
        _run(cmd, timeout=wait_seconds + 120)
        self._write_kubeconfig()
        self.verify_identity()

    def _write_kubeconfig(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        proc = _run(["k3d", "kubeconfig", "get", self.name], timeout=60)
        data = proc.stdout
        if self.api_host:
            data = re.sub(
                rb"server: https://[^:\s]+:", f"server: https://{self.api_host}:".encode(), data
            )
        self.kubeconfig.write_bytes(data)
        self.kubeconfig.chmod(0o600)

    def delete(self) -> None:
        if self.exists():
            _run(["k3d", "cluster", "delete", self.name], timeout=180)
        if self.kubeconfig.exists():
            self.kubeconfig.unlink()

    def kubectl_base(self) -> list[str]:
        return ["kubectl", "--kubeconfig", str(self.kubeconfig), "--request-timeout=30s"]

    def verify_identity(self) -> dict:
        """Refuse to operate unless the API server belongs to this k3d cluster."""
        if not self.kubeconfig.exists():
            raise ClusterError(f"no Clavure kubeconfig for cluster {self.name}")
        proc = _run([*self.kubectl_base(), "get", "nodes", "-o", "json"], timeout=60)
        nodes = json.loads(proc.stdout)["items"]
        names = [n["metadata"]["name"] for n in nodes]
        if not names or not all(n.startswith(f"k3d-{self.name}-") for n in names):
            raise ClusterError(
                f"kubeconfig does not point at k3d cluster {self.name}: nodes={names}"
            )
        args = {}
        for n in nodes:
            args = json.loads(
                n["metadata"].get("annotations", {}).get("k3s.io/node-args", "[]") or "[]"
            )
        return {"nodes": names, "k3s_node_args": args}

    def import_image(self, image: str) -> None:
        """Load a locally built image into the node's containerd (no registry)."""
        save = subprocess.Popen(["docker", "save", image], stdout=subprocess.PIPE)
        try:
            proc = subprocess.run(
                [
                    "docker",
                    "exec",
                    "-i",
                    self.server_container,
                    "ctr",
                    "-n",
                    "k8s.io",
                    "images",
                    "import",
                    "-",
                ],
                stdin=save.stdout,
                capture_output=True,
                timeout=300,
            )
        finally:
            if save.stdout:
                save.stdout.close()
            save.wait(timeout=60)
        if proc.returncode != 0 or save.returncode != 0:
            raise ClusterError(
                f"image import failed: {proc.stderr.decode(errors='replace')[-1000:]}"
            )

    def status(self) -> dict:
        out: dict = {
            "name": self.name,
            "tools": self.tools_available(),
            "kubeconfig": str(self.kubeconfig),
        }
        out["docker"] = self.docker_available()
        if out["docker"] and out["tools"]["k3d"]:
            out["exists"] = self.exists()
            if out["exists"] and self.kubeconfig.exists():
                try:
                    out["identity"] = self.verify_identity()
                except ClusterError as exc:
                    out["identity_error"] = str(exc)
        return out
