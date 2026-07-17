# Genesis receipt #0

> **Status:** Implemented. `standing genesis install/show` and
> `ReceiptKind::GenesisInstall` exist; the store permits exactly one genesis
> receipt. Act-grant chains created after installation and all assertion-lease
> chains are cryptographically rooted by making their first receipt's
> `parent_digest` the genesis digest. Assertion issuance fails closed without
> that settlement witness. `query why` and `query chain` report the root.
> Pre-genesis historical act grants are not retroactively re-parented.
> Assertion issuance and freeze/thaw additionally require a verified operator
> matching the genesis actor; an assertion lease is issued to a distinct
> speaker, never self-granted by that speaker.
>
> **Composes with:** README "Invariants" block (state-not-cargo), `docs/remote-standing-boundary.md`, `project_standing_design_decisions` (fail-closed on receipts).

## The gap (historical, now closed)

Before genesis support, `standing query why --id <grant-id>` walked backward to
the grant request and then terminated in silence. There was no receipt naming
the operator who established initial authority. That was the gap this filing
identified; current post-genesis chains terminate at the citable root.

A chain that terminates at silence is fiat laundered through omission. A chain that terminates at a named genesis receipt is fiat made citable.

> Standing's invariant is *fail-closed on receipts*. The genesis of the receipt chain itself should obey the invariant.

## Historical candidate shape

The proposal used the following conceptual shape. The implementation stores
these fields through the normal `Receipt` envelope plus its evidence object;
this block is explanatory, not a byte-for-byte wire example:

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

policy_hash pins the policy source present at genesis.
  Subsequent policy updates are themselves receipt-bearing events
  authorised under prior grants OR (for the operator) under
  citation of the GenesisInstall receipt. The instance never
  forgets where it started.
```

The first four properties are implemented. The final paragraph's general
policy-update lifecycle remains doctrine; Standing currently has genesis and
freeze/thaw policy events, not an arbitrary policy-install/update subsystem.

## Historical forcing event (satisfied)

The candidate becomes binding when one of the following happens:

1. An operator runs `standing query why` against any grant and walks off the end into nothing. The first such walk produces a maintenance issue that this spec answers.
2. Standing acquires a second consumer (NQ goes binding, or AG arrives) and that consumer asks "what authorised the *policy*?" — at which point the answer "nothing, it's just there" is structurally embarrassing.
3. An audit-facing artifact (a downstream system citing Standing's receipt chain) needs the chain to terminate at something nameable. Probably first surfaces from the gauntlet's S5 `why` command, which is planned to join through `standing query why` (see [[project-standing-query-why-join-point]]).

The operator explicitly promoted this candidate and genesis support landed on
2026-06-10. Phase 4b–6 then added cryptographic parent linkage. Installation is
explicit rather than an implicit first-run side effect, and existing chains are
not retrofitted.

## Operator fiat is real

The keeper this spec preserves:

> Operator fiat is the genesis authority of any Standing instance. The point of the receipt is not to pretend that fiat is policy — it is to make the fiat visible, citable, and one walk-step away from any consequence it underwrites.

A receipt that names fiat as fiat is more honest than a chain that terminates in silence. The genesis receipt does not avoid fiat; it admits it, and binds the operator to one citable moment instead of letting authority diffuse into ambient box-fiat.

This is the same shape as the FiatAdmissibility doctrine in adjacent projects: fiat is not forbidden; fiat is required to be visible. Standing's genesis receipt is the local manifestation.

## Current limits

- The CLI is `standing genesis install --identity <file> --secret <key>` with
  optional `--policy-source <marker>`; `standing genesis show` reads it back.
- Re-install is refused. If the genesis operator key is compromised, replace
  the instance rather than rewriting its root.
- The receipt inherits the verified operator's HMAC identity substrate; it does
  not claim a stronger signature or institutional authority.
- Existing pre-genesis grant chains are not retrofitted. A later genesis names
  the installation event honestly; it cannot reconstruct earlier authority.
- Whether the operator's identity must itself be ratified by some external authority. No — that is infinite-regress bait. The operator is the genesis; the genesis is fiat; the fiat is named; the chain stops.

## Provenance

Filed 2026-06-10 from a review pass on Standing's README (Claude Fable,
operator-relayed) which named the chain-termination gap explicitly: *"Without a
genesis receipt, the system has a noble lineage that mysteriously begins at
'trust me bro.'"* The original candidate wording is retained above as design
stratigraphy. Genesis MVP landed the same day; Phase 4b–6 later rooted new grant
and assertion chains at that receipt.
