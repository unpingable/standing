# Compromise recovery

> **Status:** `candidate / doctrine`. The emergency counterpart to the routine
> rotation in [[component-key-keytab]]. Names what to do when a secret leaks —
> distinct from a scheduled rotation because the old key must be **repudiated**,
> not gracefully overlapped.
>
> **Composes with:** [[component-key-keytab]], [[genesis-receipt]],
> [[lifecycle-freeze]].

## Routine rotation vs compromise

Routine rotation keeps the old key **live** during an overlap window so in-flight
credentials still verify. Compromise is the opposite: the old key is in an
attacker's hands, so anything it can still sign is a live forgery. The old key
must stop verifying **as fast as the blast radius allows**, even at the cost of
rejecting in-flight legitimate credentials.

## The blast radius of a leaked secret

A leaked `(kid, secret)` lets an attacker mint:

- **Identity claims** as any workload in that key's trust scope (any
  `name`/`location`) — because the HMAC is symmetric, verify-power == sign-power.
- **Assertion proofs** (`sign_proof`) for any lease whose verification uses that
  key — forging the per-request MAC.

It does **not** let the attacker:

- Forge a **receipt chain** retroactively — receipts are content-addressed and
  append-only (`verify_integrity` / `chain.verify`), so a forged history breaks
  the digest walk. But the attacker *can* create new, validly-signed events
  going forward until the key is repudiated.
- Widen an **existing lease's scope** — the issuance receipt binds the full terms
  (`mutated_terms_rejected`); a forged spend still has to fall inside a real
  lease's `claim_kind × subject_scope × audience × window × budget`.

## Recovery ladder

1. **Repudiate the key.** Drop the compromised `kid` from every verifier's
   `KeySet` immediately — do **not** demote it to `legacy` (that would keep the
   attacker's forgeries verifying). After this, claims under that `kid` are
   `UnknownKeyId`. This is the single most important step and the fastest.
2. **Freeze the blast-radius classes.** If repudiation cannot be pushed to all
   verifiers at once, use [[lifecycle-freeze]] to deny the affected
   `claim_kind` / `actor` / `audience` classes while you close the gap. Freeze is
   a deny-overlay that still counts clock-time — it buys time without pretending
   the leases don't exist.
3. **Revoke leases minted or spent under the key during the exposure window.**
   Assertion leases issued or spent while the key was compromised are suspect;
   revoke them (`assert revoke`) so a re-witness is forced. Prefer revocation
   over waiting for expiry when the window is wide.
4. **Re-key legitimate signers.** Issue `secret_new` under `kid_new` per
   [[component-key-keytab]] and cut signers over. This is a normal rotation with
   the overlap window set to **zero** (no legacy — the old key is repudiated, not
   retired).
5. **If the genesis operator key is compromised, replace the instance.** The
   genesis receipt is the instance's root of fiat ([[genesis-receipt]]); a
   compromised operator key means the root is untrustworthy. There is no
   in-place recovery — stand up a new instance with a fresh genesis and migrate
   leases forward. (The genesis doc's "replace the instance rather than
   re-install" rule is the same conclusion reached from the compromise angle.)

## What Standing gives you for the post-mortem

- **Receipt chains** name every lease issuance and every spend, with
  `issued_at` / `evaluated_at` — so the exposure window can be intersected with
  the receipt timeline to enumerate exactly which spends are suspect.
- **`jti` ledger** (`seen_assertion_jti`) records which nonces were presented,
  bounding replay-vs-fresh questions during the window.
- **`settlement_witness`** on each issuance ties leases back to the genesis, so
  "which leases descend from the compromised authority" is answerable.

## What this does NOT specify

- Detection. Standing does not detect a leak; it bounds the damage and supports
  the forensics once a leak is known.
- Notification / paging. An ops concern, not a standing concern.
- Automatic revocation. Revocation is operator-driven and receipt-bearing;
  Standing does not auto-revoke on a heuristic.

## Provenance

Filed Phase 5 alongside `KeyResolver` / `KeySet` and the MAC-verified assertion
path. The ladder is the compromise-angle reading of the same key lifecycle
[[component-key-keytab]] describes for the routine case.
