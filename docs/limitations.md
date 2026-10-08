# Limitations

## Scope

* Kubernetes `networking.k8s.io/v1` NetworkPolicy, TCP only. UDP/SCTP rules
  are parsed but never match TCP traffic. AdminNetworkPolicy, Cilium, Calico
  and Istio objects are detected and make the affected verdicts UNSUPPORTED;
  they are not modelled.
* `ipBlock` peers make pod-to-pod verdicts UNKNOWN (implementation-defined in
  Kubernetes).
* Workloads are modelled from pod templates. Pods created outside the analysed
  manifests are not seen unless the live state is ingested. Only
  NetworkPolicies are re-ingested today.
* Reachability is L3/L4 only: no application authorization, no
  exploitability, no multi-hop pivot modelling.
* Required connections are declared per Service port; Services without
  selectors and ExternalName Services are not modelled.

## Optimizer

* Optimal only within the generated action space, the combination bound (3)
  and the explicit cost model. Business disruption is an estimate based on
  declared criticality, not observed traffic.
* Generated selectors use labels of workloads present in the manifests. Future
  pods with the same labels will match, and `NotIn` exclusions especially so
  (penalised in the cost model).
* Plans that change live-only objects (drift) need a manual out-of-band
  change. They are never applied automatically, and verification includes
  the live objects as they are.

## Runtime verification

* One replica per workload; probes run from the first Ready pod.
* Blocked-connection evidence on K3s is ECONNREFUSED. It is accepted only with
  a healthy target listener and a passing enforcement canary.
* The demo databases are synthetic line-protocol emulators.
* The `runtime:k3d` CI job (docker-in-docker) has not been run.

## GitLab

* Neither the Duo flow nor any GitLab pipeline has been executed (no GitLab
  access in the build environment).
* An MR can edit `.gitlab-ci.yml`. Enforce the guard and trusted verification
  jobs with a pipeline execution policy or an external CI configuration.
* Flow routing depends on the agent returning the exact token printed by
  Clavure. A wrong token falls through to the reporter (fail-safe), not to
  publishing.

## Not implemented

* Adversarial agent extension (milestone 4) and the optional application-RBAC
  demonstration.
* Cloud IAM and application RBAC adapters.
