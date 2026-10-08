# Adversarial verification — status

**Not implemented in this build.**

Milestone 4 of the project brief (an adversarial agent extension) is not part
of this repository. No adversarial results are produced or reported anywhere:

* `adversarial-results.json` is written with `"status": "NOT_IMPLEMENTED"` and
  an empty result list;
* the HTML report's "Adversarial test" section shows the same status;
* the pipeline records the extension as not implemented in
  `verification-report.json#adversarial_extension`.

What *is* implemented and covers part of the intent: the trusted runtime
verifier probes every declared forbidden connection on every exposed TCP port,
from inside the real source workload pods, both by Service name and directly by
pod IP, in a disposable cluster. It feeds model/runtime mismatches back into the
optimizer (see [verification.md](verification.md)).

The application-level RBAC demonstration (optional, section 11 of the brief) is
also not implemented.
