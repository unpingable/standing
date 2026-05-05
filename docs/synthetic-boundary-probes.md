# Standing — Synthetic Boundary Probes

> Standing is not yet active. These probes do not describe current Standing
> behavior. They do not authorize implementation. They do not define policy.
>
> They record future admissibility boundaries so Standing does not inherit
> authority from Agent Governor, Nightshift, or observatory-family practice
> by accident.

## What this document is

A fence line, not a plant.

Standing has no natural firing site yet — Nightshift uses only
`nightshift.record_receipt` on the Governor wire; `check_policy` and
`authorize_transition` have no producers. Until that changes, building
"real workflows" risks design-basis erasure: inventing a controller before
the wound is fully visible.

What is allowed now is *pre-policy probing*: not "what should Standing do?"
but "what kinds of questions will Standing eventually need to answer
without becoming Governor?"

These five probes name those questions. Each anchors to a lesson already
articulated elsewhere in the constellation. None of them define a Standing
policy. None of them describe current slice-1 behavior. They are
boundary-shape tests for the eventual admissibility surface.

## Probe 1 — Capability grant does not imply authority

An actor can technically perform an operation but lacks standing to do it.
A Claude session has the file-system capability to edit
`agent_gov/docs/SPEC.md`; it does not have standing to amend the policy
specification. Expected admissibility outcome: *technical capability
present; standing absent; action denied or advisory-only*.

This is the core Standing distinction. `can` is not `may`. Every other
probe is a special case of it.

## Probe 2 — Advisory evidence does not become Standing

External practice (an observatory-family lesson, a chatty synthesis,
prior art from another system) is imported as evidence. A future Standing
session attempts to promote it directly into a policy rule. Expected
admissibility outcome: *external practice may enter as advisory evidence
or prior art; it cannot enter as governing vocabulary*.

Anchor: observatory-family lesson `mem_8b6b6823d90944a192d2bd695e2575ad`
(2026-04-28, pattern language refinement — authority vs evidence).
"Do not import external practice as authority. Do not ignore external
practice as evidence."

## Probe 3 — Scope mismatch

An actor with standing in one project's domain proposes an action in
another's. A Nightshift workload principal with grants for the
`wl:nightshift:*` scope attempts to effect a policy change in
`agent_gov`. Expected admissibility outcome: *denied due to scope
mismatch — adjacency is not permission*.

**Important:** current slice-1 Standing policy may not distinguish this
scope shape yet. The probe tests the eventual admissibility surface only.
Most systems die because someone treats adjacency as permission; this
probe records that the boundary will be enforced once Standing has a
real policy substrate.

## Probe 4 — Revoked or stale grant cannot authorize

A previously valid Standing grant exists in receipt history but is
expired or revoked. An actor invokes the grant to authorize a new
action. Expected admissibility outcome: *the grant may explain history;
it cannot authorize action*.

This ports cleanly into the verifier-style invariant: absence, missing
evidence, or stale evidence cannot become satisfiable imagination.
History is auditable; it is not authority.

## Probe 5 — Mode-phase separation

An ops-mode session under runtime pressure attempts to amend a Standing
schema or invariant — e.g. relaxing a fail-closed rule because a deploy
is blocked. Expected admissibility outcome: *denied; architecture-mode
required for constitutional schema change*.

Anchor: observatory-family lesson `mem_7cf6b28a711148f4a62ca5715f99b67a`
(2026-04-17, mode-phase separation). Schema/invariant work belongs to
architecture-mode (constitutional amendment to authority model).
Runtime policy tuning belongs to ops-mode. Don't collapse them. This
probe blocks "runtime pressure amended the constitution."

## Keeper line

> Standing synthetic work is allowed only while it refuses to pretend
> Standing has a firing site.

When Nightshift produces a real action or transition surface that needs
policy gating against a workload principal, the probes here graduate
from boundary-shape tests into actual policy authoring inputs — and this
document gets superseded by something that names a real plant. Until
then, these are the questions to refuse, not the answers to build.
