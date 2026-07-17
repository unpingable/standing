# Lifecycle freeze — incident-mode suspension

> **Status:** Implemented in Phase 4b–6. `standing policy freeze | thaw |
> list-freezes` manage a receipt-bearing deny-overlay in `policy_freezes`.
> Matching assertion spends and authorizing act-grant transitions are refused;
> assertion decisions surface `class_frozen:<handle>`. `--until` is lazy expiry:
> after the timestamp the row stops matching, with no scheduler or synthetic
> thaw receipt. Frozen grants keep counting clock time. Freeze and thaw require
> a verified identity matching the installed genesis operator.
>
> **Composes with:** `docs/remote-standing-boundary.md`, slice-1 grant state machine, README "Invariants" block.

## The gap (historical, now closed)

The slice-1 grant state machine has terminal and time-bound transitions:

```text
Requested → Issued | Denied
Issued    → Active | Expired | Revoked | Abandoned
Active    → Used (event) | Expired | Revoked | Abandoned | LeaseExpired
```

What was missing was a **non-terminal, ops-driven suspension** — a verb that
means:

> This grant class remains real, but cannot authorise while incident mode is active.

Before the freeze overlay, the operator's only options for "halt deploys while
smoke is coming out of the machine" were:

1. **Revoke individual grants.** Wrong tool: revocation is terminal, requires re-issuing each grant after the incident closes, and abuses a security-shaped verb for an ops-shaped condition.
2. **Mutate policy.** Heavy: policy-hash flips on every freeze/thaw, the receipt chain inflates with policy churn, and the operator has to author and unauthor counter-policy entries.
3. **Nothing.** Hope the consumer side wraps its own kill-switch around Standing.

None of those match the actual ops reality, which is not *"Bob's grant is bad"* but *"nobody deploys until the smoke stops."*

## Current CLI

```bash
standing policy freeze \
  --handle <incident-handle> \
  --class-type <claim_kind | action | actor | audience> \
  --class-value <exact-value> \
  --reason <free-text-reason> \
  [--audience <name:instance>] \
  [--until <RFC-3339-timestamp>] \
  --identity <genesis-operator-identity> --secret <key>

standing policy thaw --handle <incident-handle> \
  --identity <genesis-operator-identity> --secret <key>

standing policy list-freezes [--all]
```

`freeze` is **policy-level, not per-grant.** A freeze entry is a row in a policy-side table; matching grants continue to exist with their current state, but resolvers refuse them with a named refusal mode while the freeze covers them.

`claim_kind` and `audience` target assertion leases. `action` targets act
grants. `actor` can screen either path. Optional `--audience` narrows an
assertion `claim_kind` or `actor` freeze to one audience; audience-scoped rows
do not apply to act grants, which carry no audience.

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

The resolver decision gives a consumer enough information to make the refusal
visible in its own receipt:

```json
{
  "standing_verdict": "denied",
  "standing_basis": "class_frozen:incident-2026-06-10-deploy-rollback",
  "reason": "assertion refused: class frozen ...",
  ...
}
```

The separately stored `PolicyFrozen` receipt carries `class_type`,
`class_value`, audience scope, reason, and optional `frozen_until`.

## Properties this spec must obey

```text
Non-terminal at the grant layer.
  Freezes act on the policy decision, not the grant record. A
  frozen-then-thawed grant has the same id, the same receipt
  chain, the same lifecycle position. The freeze does not amend
  the grant; it screens it.

Receipt-bearing.
  Both explicit freeze and explicit thaw emit policy-event
  receipts. A denied request names the freeze handle, which makes
  that policy receipt citable; the refusal does not fabricate a
  grant transition or append to the untouched grant's chain.

Scoped by class, not by holder.
  Freeze targets a claim_kind, an action, an actor pattern, an
  audience, or a tuple of those. Freezing "all deploys" is the
  common case. Freezing "this particular grant" is the wrong
  shape — that is what revocation is for.

Reversible by default.
  No --until means the freeze is open-ended until explicit thaw.
  --until is lazy expiry: after the timestamp the entry no longer
  matches. There is no scheduler and no automatic thaw receipt.

Visible in receipts immediately.
  A resolver decision denied during a freeze surfaces the handle
  in standing_basis. Consumers record that decision; operators
  can cite the independently stored PolicyFrozen receipt.
```

## Historical forcing event (satisfied)

The candidate becomes binding when one of the following happens:

1. An operator runs an incident drill against Standing and tries to halt a grant class without permanent revocation. The drill produces a maintenance issue that this spec answers.
2. A consumer (NQ binding flip, Wicket adapter, AG) requests a `freeze` verb to wire into its own incident-mode handling.
3. An ops handbook for any Standing-consuming system references "freeze the deploy class while we investigate" as a step and the step lands on this spec.

The Phase 4b–6 hardening pass promoted the candidate and implemented the table,
CLI, receipts, and enforcement on both grant families.

## Current boundaries

- Freeze/thaw authority is the verified genesis operator. No arbitrary verified
  workload may mutate the overlay.
- Assertion and act-grant enforcement is implemented. A freeze is not a
  stop-clock and never rewrites grant state.
- Cross-instance freeze propagation (no federation, so: not in scope).
- In `visible_not_binding` mode the decision remains advisory; a consumer must
  record the freeze posture but chooses whether it binds. Binding mode refuses.

## Historical rationale

Freeze is the missing ops verb that the slice-1 lifecycle did not invent because slice-1 closed shipping entitlement-to-act for a single co-located deployment. Cross-machine deployment turns ops drills into a real shape — incident mode is the use case that distinguishes "this individual grant is bad" from "this class of operation is paused." Naming the verb now lets the next consumer that asks for it find the shape pre-cooked rather than inventing a per-consumer kill-switch and re-discovering the revocation-abuse pattern.

## Provenance

Filed 2026-06-10 from a review pass on Standing's lifecycle. The verb was named
in a follow-up: *"Freeze means: this grant class remains real, but cannot
authorize while incident mode is active. Policy-level makes sense. ... It
avoids abusing revocation for temporary suspension."* The candidate text is
retained as design stratigraphy; implementation landed in Phase 4b–6.
