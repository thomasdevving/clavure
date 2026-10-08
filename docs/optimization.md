# Remediation optimization

## Problem

Given the current policy set *P*, declared required connections *R* and
forbidden connections *F*, find a change Δ that:

* **satisfies every hard constraint** (H1–H6 below) for *P ⊕ Δ*, and
* has minimal cost among the candidates that do.

## Action space

Actions are generated **from evidence**, never from knowledge of the demo. For
every connection that a forbidden constraint covers and the model rates
`ALLOWED`, the reachability engine reports the permitting rules on both sides
(egress of the source, ingress of the destination). For each such rule:

| Action | Meaning |
|---|---|
| `remove-rule` | drop the rule |
| `remove-peer` | drop one peer (only if the rule has more than one; an emptied peer list drops the rule instead of becoming "allow all") |
| `narrow-peer` | AND the peer with the distinguishing labels of the *required* counterparts it serves (never broader than before) |
| `restrict-ports` | restrict the rule to ports the required connections through it use |
| `narrow-targets` | replace the policy's `podSelector` so it selects only the workloads whose required traffic depends on it |
| `exclude-target` | add a `NotIn` requirement excluding the workload (penalised: future pods match) |
| `delete-policy` | delete the policy |
| `isolate` | for a side that is not isolated: a new policy isolating it with explicit allows for its required traffic |
| `allow-required` | for a *broken* required connection: the narrowest allow rules |
| `quarantine-workload` *(coarse)* | cut the source off entirely |
| `block-all-ingress` *(coarse)* | block every inbound connection to the destination |

The coarse actions document the obvious-but-wrong fixes. They are evaluated
exactly like the others, so their rejection is computed rather than asserted.

Which required traffic flows through which policy, rule and peer comes from
the permitting-rule evidence of the required connections (`candidates.required_usage`).

## Search

All conflict-free combinations of 1..k actions (k = `maxActionsPerPlan`,
default 3) are enumerated in a fixed order. Actions conflict when they touch
the same policy element (prefix relation on touched paths). Each combination
is applied to a draft that keeps original rule and peer indexes, then the
**full** reachability model is recomputed. An evaluation budget (default
20 000) is enforced; exhausting it is reported and voids the optimality claim.

## Hard constraints (filters, never weighted)

| | |
|---|---|
| H1 | every forbidden constraint SATISFIED (blocked on every port) |
| H2 | every required constraint SATISFIED (every Service backend reachable) |
| H3 | every generated or modified NetworkPolicy passes strict validation |
| H4 | no constraint is UNDECIDED (no UNKNOWN / UNSUPPORTED accepted silently) |
| H5 | no new connectivity: no connection that was not ALLOWED becomes possibly allowed, unless it is explicitly required |
| H6 | consistent with runtime evidence: a BLOCKED prediction that runtime contradicted, and that live re-ingestion could not explain, is not trusted |

## Cost model (ranking only)

`total = Σ weight × objective`, with weights reported in every
`remediation-plan.json`:

| Objective | Weight | Meaning |
|---|---|---|
| `policy_objects_changed` | 10 | created + modified + deleted policies |
| `rule_edits` | 2 | atomic edits |
| `workloads_reconfigured` | 2 | workloads selected by any changed policy (rollout blast radius) |
| `workloads_connectivity_changed` | 3 | workloads whose allowed connections change |
| `connectivity_removed` | 8 | non-forbidden connections removed (collateral) |
| `business_disruption` | 5 | collateral weighted by declared criticality (×10 for required) |
| `complexity` | 1 | new objects, `NotIn` exclusions, selector terms, out-of-band changes |
| `source_side_only_blocks` | 4 | forbidden connections blocked only at the source's egress; prefers protecting the asset itself |

Ties are broken by action count and then lexicographically, so results are
deterministic. Each valid plan is marked `minimal` when no proper subset of
its actions is valid.

**Optimality claim.** The selected plan is optimal *within the generated
action space, the bound k and this cost model*. Other rewrites are not
considered.

## Demo results (from `docs/evidence/run-clean/remediation-plan.json`)

9 actions generated, 44 combinations evaluated, 5 valid plans.

| Plan | Result | Cost | Change |
|---|---|---|---|
| P-001 | **selected** | 22 | narrow `allow-analytics-to-data-tier` podSelector to `app=orders-db` |
| P-002 | valid | 25 | exclude finance-db from that policy (`NotIn`) |
| P-003 | valid | 25 | narrow reporting's egress peer to orders-db |
| — | rejected (H2) | — | block all finance-db ingress: breaks `REQ-PAYMENT-FINANCEDB` |
| — | rejected (H2) | — | quarantine reporting: breaks `REQ-REPORTING-ORDERS` |
| — | rejected (H2) | — | delete / remove either new policy or rule: breaks `REQ-REPORTING-ORDERS` |

With the drift fixture present (`run-drift/`), live re-ingestion adds
`legacy-finance-export`. P-001 then fails H1, and the optimizer selects the
egress-side narrowing (cost 25).
