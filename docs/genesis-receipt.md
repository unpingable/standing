# Genesis receipt #0

> **Status:** `candidate / non-binding`. Names the chain-termination gap. Becomes binding when a `standing query why` walk first terminates in silence and the operator wants the silence to be a named receipt instead.
>
> **Composes with:** README "Invariants" block (state-not-cargo), `docs/remote-standing-boundary.md`, `project_standing_design_decisions` (fail-closed on receipts).

## The gap

`standing query why --id <grant-id>` walks the receipt chain backward from current state, citing the policy decision that authorised activation, terminating at the grant request receipt. The walk currently terminates **in silence further back** — there is no receipt that names the operator who established the initial policy, on what date, under what authority.

A chain that terminates at silence is fiat laundered through omission. A chain that terminates at a named genesis receipt is fiat made citable.

> Standing's invariant is *fail-closed on receipts*. The genesis of the receipt chain itself should obey the invariant.

## The spec (candidate)

A new receipt kind, emitted exactly once per Standing instance at the point of first policy install:

```json
{
  "kind": "GenesisInstall",
  "version": "standing.genesis.v1",
  "operator": "<canonical principal — human:handle or workload:name:location>",
  "basis": "operator_fiat",
  "prior_grant": null,
  "policy_hash": "<sha-256 of canonical policy bytes>",
  "policy_source": "<path / URL / inline marker>",
  "established_at": "<RFC 3339 UTC timestamp>",
  "claim": "Operator establishes initial Standing policy by explicit fiat. No prior grant authorises this; the operator is the genesis authority of this Standing instance.",
  "instance_id": "<UUID of this Standing instance>"
}
```

Content-addressed by SHA-256 over canonical JSON like every other receipt. Immutable. Stored in the same receipts table with `kind = "GenesisInstall"`.

## Properties this spec must obey

```text
Exactly one per instance.
  A second GenesisInstall receipt is a contradiction. The schema
  invariant is enforced at write time: refuse to write a second
  one against the same instance_id.

Terminal in walk direction.
  query why and query chain MUST terminate at the genesis receipt,
  not at a silent absence. The walk function returns it as the
  named root, not as null.

Operator is canonical principal.
  Same canonicalization rules as the rest of Standing
  (human:handle, workload:name:location, etc.). No bare names.

Fiat is named, not avoided.
  basis: "operator_fiat" is the load-bearing string. The point of
  the receipt is not to pretend fiat is policy — it is to make the
  fiat visible. Standing does not magic up institutional authority
  it does not have.

policy_hash pins the policy.
  Subsequent policy updates are themselves receipt-bearing events
  authorised under prior grants OR (for the operator) under
  citation of the GenesisInstall receipt. The instance never
  forgets where it started.
```

## What the forcing event looks like

The candidate becomes binding when one of the following happens:

1. An operator runs `standing query why` against any grant and walks off the end into nothing. The first such walk produces a maintenance issue that this spec answers.
2. Standing acquires a second consumer (NQ goes binding, or AG arrives) and that consumer asks "what authorised the *policy*?" — at which point the answer "nothing, it's just there" is structurally embarrassing.
3. An audit-facing artifact (a downstream system citing Standing's receipt chain) needs the chain to terminate at something nameable. Probably first surfaces from the gauntlet's S5 `why` command, which is planned to join through `standing query why` (see [[project-standing-query-why-join-point]]).

Until one of those fires: candidate-not-binding. Standing does not implement a `standing genesis` CLI verb yet, does not write `GenesisInstall` receipts on first run, does not retrofit existing instances.

## Operator fiat is real

The keeper this spec preserves:

> Operator fiat is the genesis authority of any Standing instance. The point of the receipt is not to pretend that fiat is policy — it is to make the fiat visible, citable, and one walk-step away from any consequence it underwrites.

A receipt that names fiat as fiat is more honest than a chain that terminates in silence. The genesis receipt does not avoid fiat; it admits it, and binds the operator to one citable moment instead of letting authority diffuse into ambient box-fiat.

This is the same shape as the FiatAdmissibility doctrine in adjacent projects: fiat is not forbidden; fiat is required to be visible. Standing's genesis receipt is the local manifestation.

## What this does not specify

- The CLI verb name (`standing genesis install --policy <path>` is plausible, not pinned).
- Whether re-installs are allowed on the same instance under cited prior authority (probably no; replace the instance instead).
- Whether the genesis receipt is signed by anything beyond the operator's identity substrate. Probably not — the substrate's strength applies, per the substrate-honesty limit (see README "Limitations").
- Migration path for existing Standing instances that pre-date this spec. Likely: optional retrofit receipt with `migrated_at` field, explicitly noting that the *pre-spec* genesis cannot be reconstructed and the migration receipt names only the migration event, not the original install.
- Whether the operator's identity must itself be ratified by some external authority. No — that is infinite-regress bait. The operator is the genesis; the genesis is fiat; the fiat is named; the chain stops.

## Provenance

Filed 2026-06-10 from a review pass on Standing's README (Claude Fable, operator-relayed) which named the chain-termination gap explicitly: *"Without a genesis receipt, the system has a noble lineage that mysteriously begins at 'trust me bro.'"* No implementation work today; candidate spec only. Operator authority for this filing was itself a visible fiat ("fuck a forcing case, do it"), which is the exact authorial shape this spec is meant to make citable rather than silent.
