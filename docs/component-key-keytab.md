# Component keys & keytab doctrine

> **Status:** `candidate / doctrine`. Describes how `kid → secret` resolution and
> key rotation work now that `KeyResolver` / `KeySet` are implemented
> (`standing-identity`, Phase 5). Binding once a second component holds its own
> key or the first rotation is run for real.
>
> **Composes with:** [[genesis-receipt]] (the operator key is the genesis
> authority), [[compromise-recovery]] (the emergency path), `docs/remote-standing-boundary.md`.

## The gap this closes

Identity claims have always carried and signed a `kid` (key id), but nothing
mapped a `kid` to the secret that verifies it: `verify_identity` took a single
bare secret. That is the pre-rotation world — one key, forever, and rotating it
means a flag-day where every component re-registers at once.

`standing-identity` now ships:

- `KeyResolver` — the trait `kid → Option<&[u8]>`. An unknown kid is
  `AssessmentResult::UnknownKeyId`, a **distinct** refusal from
  `InvalidSignature`: "we don't hold that key" is not "the signature is wrong."
- `SingleKey` — one kid, one secret (the pre-rotation world made explicit).
- `KeySet { primary, legacy }` — the rotation-aware resolver.

## Keytab layout (recommended)

A *keytab* is the set of `(kid, secret)` pairs a verifier holds. Standing does
not prescribe storage (env, file, secrets manager) — only shape:

```text
primary  = (kid_new, secret_new)   # new signatures use this
legacy   = (kid_old, secret_old)   # optional; verify-only, during overlap
```

- **Signers** (components minting their own identities / assertion proofs) hold
  exactly their current `(kid, secret)` and stamp `kid` on every claim.
- **Verifiers** (Standing, and consumers verifying inbound claims) hold a
  `KeySet` and resolve the claim's `kid` against it.
- A `kid` is an opaque label. Convention: `<component>.<generation>`, e.g.
  `nq.v3`. Standing does not parse it; it is matched exactly.

## Rotation procedure (overlap, not flag-day)

1. **Generate** `secret_new` under a fresh `kid_new`. Distribute it to the
   signer(s).
2. **Widen** every verifier's `KeySet` to `primary = (kid_new, secret_new)`,
   `legacy = (kid_old, secret_old)`. Both keys now verify; new claims are
   already signed under `kid_new`.
3. **Cut over** signers to `kid_new`. Because verifiers already accept it, there
   is no synchronized moment.
4. **Retire** `legacy` once no claim signed under `kid_old` can still be within
   its TTL (identity claims: `DEFAULT_TTL_SECS`; assertion leases: the longest
   live `expires_at`). After that, drop `legacy`; `kid_old` becomes
   `UnknownKeyId`.

The overlap window's minimum length is *the longest credential lifetime signed
under the old key* — you cannot retire a key while something it signed is still
supposed to be valid. This is the same "a witness ages, you cannot carry
freshness forward without paying elapsed time" discipline the Lean freshness
kernel names.

## What this does NOT specify

- **Key distribution / storage.** How `secret_new` reaches a signer is out of
  scope — that is a secrets-management concern, not a standing concern. The
  MAC-verified assertion path (`Store::spend_assertion_verified`) takes the key
  from the caller for the same reason: Standing verifies, it does not distribute.
- **Per-audience keys for assertion proofs.** The proof MAC capability exists
  (`sign_proof` / `spend_assertion_verified`); which key an audience uses to
  verify a given actor's proof is a distribution question deferred until a real
  consumer needs it.
- **Asymmetric keys / PKI.** HMAC (symmetric) is the substrate. Upgrading to
  signatures is a named non-goal until a cross-trust-domain consumer forces it
  (`CLAUDE.md`: "Don't upgrade HMAC identity to full PKI without real need").

## Provenance

Filed Phase 5 alongside the `KeyResolver` / `KeySet` implementation. The `kid`
field and `UnknownKeyId` verdict predate this doc (they were the pre-poured seam,
commit 84ae6f1); this doc names the operating procedure the seam was cut for.
