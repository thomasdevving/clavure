"""Clavure: security verification and least-disruptive remediation.

The package is split along trust boundaries:

* ``clavure.core``          — manifest parsing, NetworkPolicy semantics, security graph
* ``clavure.optimizer``     — candidate remediation search (deterministic)
* ``clavure.verification``  — independent model verifier and runtime verifier (trusted)
* ``clavure.adversarial``   — bounded adversarial testing through restricted identities
* ``clavure.runtime``       — disposable k3d cluster controller (privileged, never given to agents)
* ``clavure.reporting``     — JSON artifacts and the standalone HTML report
"""

__version__ = "0.1.0"
