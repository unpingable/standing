# Consumer integration contract (Phase 6 binding surface)

> **Status:** `lab-backed compatibility evidence, not live testimony`. This
> describes the surface a consumer (NQ binding flip, Wicket adapter, Nightshift)
> points at, and is exercised by synthetic fixtures + the demo script under
> `examples/`. It is **not** a claim that any real consumer is wired — the
> consumer flips independently. Cages labeled; zoo built.
>
> **Composes with:** `docs/remote-standing-boundary.md`,
> [[component-key-keytab]], [[lifecycle-freeze]].

## The two integration paths

A consumer that wants Standing to gate a binding/mutating effect has two entry
points, depending on whether it holds a lease id:

1. **Preflight orchestrator** (`standing assert resolve`, or
   `Store::resolve_assert_{preview,spend}`) — the consumer knows the lease id and
   asks the four-variant question: is assert-standing required, and is it
   available? Returns an `AssertCheckResult`.
2. **`StoreResolver`** (`StandingResolver::assess`) — the consumer holds no lease
   id; it presents a `StandingRequest` by coordinates and Standing finds the
   covering lease. Returns a `StandingDecision`. This is the resolver-abstraction
   path (the same trait as `DenyAll` / `LocalOnly` / `StaticConfig`).

Both spend the same lease machinery; both honor freeze, window, budget, replay.

## Shapes the consumer produces / consumes

### `StandingRequest` (consumer → Standing, resolver path)

```text
actor          canonical principal id (e.g. "wl:speaker:host1")
claim_kind     the class of claim (e.g. "sqlite_wal_state")
subject_scope  the CONCRETE subject being asserted about (matched against a
               lease's coverage pattern)
audience       instance-qualified (e.g. "nq:main")
now            the consumer's clock reading
jti            REQUIRED in binding mode — a per-request single-use nonce
body_digest    SHA-256 of the request body this assertion attests to
```

### `RequestProof` (consumer → Standing, preflight/prove path)

The per-request half of the Kerberos split. Its canonical signed body is FIXED
(so a future MAC signs a stable shape):

```text
proof_version  "standing.request_proof.v1"
grant_id       the lease id
actor          speaker principal id
claim_kind     · subject_id · audience
body_digest    optional
jti            single-use per audience
issued_at      freshness anchor (MAC-verified path checks skew + age)
```

Signing: `Store::sign_proof(&proof, secret)` → the `mac` the MAC-verified path
(`Store::spend_assertion_verified`) checks. The MAC-less path
(`spend_assertion`) trusts the transport.

### `StandingDecision` (Standing → consumer, resolver path)

Every field is load-bearing for the consumer's own receipt discipline — record
all of them:

```text
verdict            allowed | denied | unknown
standing_enforced  false in visible_not_binding, true in binding  ← the bolt
standing_basis     allowed_by_store_grant | <refusal vocabulary>
verification_mode  "store_grant"
resolver           "StoreResolver"
scope · audience · evaluated_at · expires_at · reason
```

### `AssertCheckResult` (Standing → consumer, preflight path)

Adds the honesty fields that keep a preview from laundering into authority:

```text
decision            not_required | required_not_implemented
                    | required_and_available | required_but_denied
authorizes_effect   TRUE only on the spend path with a recorded receipt ← check this
decision_mode       "preview" | "spend" | "resolved"
emitted_receipt_digest   set iff a spend happened
reuse_bound · certified_sound   "unbounded_kind_scope" / false for budgetless leases
freshness           "within_validity"  (NOT full Fresh until MAC/skew land)
```

## The refusal vocabulary a consumer must handle

A consumer in binding mode treats every non-`allowed` / non-`authorizes_effect`
outcome as refusal. The `standing_basis` names why:

```text
standing_absent · no_covering_lease   no lease covers this actor/audience
claim_kind_out_of_scope · subject_out_of_scope · audience_mismatch
standing_expired · grant_not_yet_valid           window
use_budget_exhausted                              L1 budget spent
replay_detected                                   jti reused
class_frozen:<handle>                             incident-mode freeze
assertion_mac_invalid · clock_skew_exceeded · request_timestamp_out_of_window
```

Unknown future variants MUST be treated as conservative refusal.

## What Standing does NOT promise the consumer

- **Truth.** Standing says the actor had *standing to assert*, not that the claim
  is true. NQ still decides what the evidence testifies to.
- **A per-request unforgeable envelope in the MAC-less path.** `spend_assertion`
  is scope+replay+window under trusted transport; the unforgeable envelope is
  `spend_assertion_verified` + audience keys (distribution deferred,
  [[component-key-keytab]]).
- **Count-bounded reuse for unbounded leases.** An `--unbounded` lease is stamped
  `certified_sound: false`; a consumer that needs the bounded guarantee should
  require `reuse_bound != "unbounded_kind_scope"`.

## Provenance

Filed Phase 6 with `StoreResolver`. Exercised by `examples/nq-gov-wicket-demo.sh`
and the `store_resolver` / `resolve` / `assertion_tests` suites — synthetic
substrate, labeled as compatibility evidence, not testimony about a live NQ,
Wicket, or Nightshift deployment.
