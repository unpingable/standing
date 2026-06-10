# Lifecycle freeze — incident-mode suspension

> **Status:** `candidate / non-binding`. Names the missing ops-real lifecycle verb between `Active` and `Revoked`. Becomes binding when an incident drill or a consumer-side ops handbook first reaches for the verb.
>
> **Composes with:** `docs/remote-standing-boundary.md`, slice-1 grant state machine, README "Invariants" block.

## The gap

The slice-1 grant state machine has terminal and time-bound transitions:

```text
Requested → Issued | Denied
Issued    → Active | Expired | Revoked | Abandoned
Active    → Used (event) | Expired | Revoked | Abandoned | LeaseExpired
```

What is missing is a **non-terminal, ops-driven suspension** — a verb that means:

> This grant class remains real, but cannot authorise while incident mode is active.

Today the operator's only options for "halt deploys while smoke is coming out of the machine" are:

1. **Revoke individual grants.** Wrong tool: revocation is terminal, requires re-issuing each grant after the incident closes, and abuses a security-shaped verb for an ops-shaped condition.
2. **Mutate policy.** Heavy: policy-hash flips on every freeze/thaw, the receipt chain inflates with policy churn, and the operator has to author and unauthor counter-policy entries.
3. **Nothing.** Hope the consumer side wraps its own kill-switch around Standing.

None of those match the actual ops reality, which is not *"Bob's grant is bad"* but *"nobody deploys until the smoke stops."*

## The verb (candidate)

```text
standing policy freeze \
  --class <claim_kind | action | actor pattern> \
  --reason <free-text incident handle> \
  [--audience <name:instance>] \
  [--until <RFC 3339 timestamp>]

standing policy thaw --class <...> [--audience <...>]

standing policy list-freezes
```

`freeze` is **policy-level, not per-grant.** A freeze entry is a row in a policy-side table; matching grants continue to exist with their current state, but resolvers refuse them with a named refusal mode while the freeze covers them.

## The lifecycle ladder, restated

```text
mint → active → frozen → active
              ↘ revoked / expired
```

`frozen` is a non-terminal state of the *policy decision*, not of the grant record. The grant itself remains `Active`; the policy returns `Denied` with `standing_basis: "class_frozen"` and the freeze entry's reason field in the decision attribution. When the freeze lifts, the same grant is `Active` again — no re-issue, no new receipt chain, no security-verb abuse.

This avoids the failure mode where revocation gets used as a temporary kill-switch and then the security team has to chase "is this revoked because compromised, or revoked because the deploy window was closed?" — a question whose answer is *yes, both, and you can't tell from the receipt.*

## New refusal mode

Adds one entry to the refusal-mode set in `remote-standing-boundary.md`:

```text
class_frozen        a policy-level freeze covers this request;
                    grant exists and would otherwise allow, but
                    the freeze entry refuses. Reason and freeze
                    handle surface in standing_basis.
```

The freeze becomes visible in receipts:

```json
{
  "standing_verdict": "denied",
  "standing_basis": "class_frozen:incident-2026-06-10-deploy-rollback",
  "freeze_class": "claim_kind:deploy",
  "freeze_reason": "incident mode — deploy paused pending storage01 recovery",
  "freeze_until": "2026-06-10T18:00:00Z",
  ...
}
```

## Properties this spec must obey

```text
Non-terminal at the grant layer.
  Freezes act on the policy decision, not the grant record. A
  frozen-then-thawed grant has the same id, the same receipt
  chain, the same lifecycle position. The freeze does not amend
  the grant; it screens it.

Receipt-bearing.
  Both freeze and thaw emit policy-event receipts. The receipt
  chain for any denied-during-freeze request walks back through
  the policy-freeze receipt, not through a grant-revocation
  receipt that does not exist.

Scoped by class, not by holder.
  Freeze targets a claim_kind, an action, an actor pattern, an
  audience, or a tuple of those. Freezing "all deploys" is the
  common case. Freezing "this particular grant" is the wrong
  shape — that is what revocation is for.

Reversible by default.
  No --until means the freeze is open-ended until explicit thaw.
  --until adds an automatic thaw event scheduled at the timestamp;
  the auto-thaw still emits a receipt.

Visible in receipts immediately.
  A request denied during a freeze MUST surface the freeze handle
  in standing_basis. An operator reading why must reach the
  freeze receipt, not a generic deny.
```

## What the forcing event looks like

The candidate becomes binding when one of the following happens:

1. An operator runs an incident drill against Standing and tries to halt a grant class without permanent revocation. The drill produces a maintenance issue that this spec answers.
2. A consumer (NQ binding flip, Wicket adapter, AG) requests a `freeze` verb to wire into its own incident-mode handling.
3. An ops handbook for any Standing-consuming system references "freeze the deploy class while we investigate" as a step and the step lands on this spec.

Until then: candidate-not-binding. No code today. No policy table schema today. No CLI subcommand today.

## What this does not specify

- Authorization for `freeze` and `thaw` themselves. Probably: requires a grant authorising policy mutation, or operator fiat under the genesis chain (see [[genesis-receipt]]). Pinned when the spec is built.
- Interaction with the post-MVP `AssertionGrant` lease shape. A frozen lease should probably continue to count clock-time toward expiry rather than being "paused" — that is, freeze is not a stop-clock, it is a deny-overlay. Worth pinning when Phase 4 builds.
- Cross-instance freeze propagation (no federation, so: not in scope).
- Conflict with consumer-side `standing_visible_not_binding` mode. The freeze should be visible in the decision regardless; whether the consumer acts on it is the consumer's call, same shape as the rest of visible-not-binding.

## Why now (paper, not code)

Freeze is the missing ops verb that the slice-1 lifecycle did not invent because slice-1 closed shipping entitlement-to-act for a single co-located deployment. Cross-machine deployment turns ops drills into a real shape — incident mode is the use case that distinguishes "this individual grant is bad" from "this class of operation is paused." Naming the verb now lets the next consumer that asks for it find the shape pre-cooked rather than inventing a per-consumer kill-switch and re-discovering the revocation-abuse pattern.

## Provenance

Filed 2026-06-10 from a review pass on Standing's lifecycle. The verb was named in a follow-up: *"Freeze means: this grant class remains real, but cannot authorize while incident mode is active. Policy-level makes sense. ... It avoids abusing revocation for temporary suspension."* The ladder `mint → active → frozen → active` with `↘ revoked / expired` is the explicit lifecycle shape that motivates the policy-layer placement. No code today; candidate spec only.
