# Example: NQ integration in `standing_visible_not_binding` mode

> **Status:** Static advisory integration walkthrough, not a contract or a
> claim about live NQ. It names a candidate shape for NQ to consume
> `StaticConfigResolver` when accepting remote preflight submissions. Standing
> now also ships the assertion-lease-backed `StoreResolver` and binding spend
> path; those are intentionally not smuggled into this visible-not-binding
> example. The actual consumer integration belongs in NQ.
>
> Reads alongside `docs/remote-standing-boundary.md`. Numbers in this file
> preserve an NQ snapshot from 2026-05-27 (pull-only topology, two claim
> tracks, no remote ingestion path). Treat that as historical input and verify
> NQ's current shape before implementing the proposed route.

## The pressure

NQ is pull-only today: each publisher exposes `GET /state`, the central
aggregator polls on schedule, the server is read-only. As NQ instances
multiply (`nq-linode`, `nq-sushi-k`, `nq-main`) they accumulate evidence
that other instances would benefit from — `sqlite_wal_state` on a remote
labelwatch DB, `disk_state` on a peer host, `dns_state` from a different
vantage. The natural shape is a *POST* surface that lets one NQ submit
preflight results to another.

The moment that POST exists, the boundary question lands:

> May `component:nq:linode` introduce `sqlite_wal_state` testimony about
> `labelwatch/foo` into `nq:main`, right now?

Identity (mTLS, HMAC, OIDC — pick one) answers *who spoke*. Standing
answers *whether that speaker had the right to speak in that role*.

## The seam in NQ (proposed)

Add a route in `crates/nq/src/http/routes.rs` (currently only `GET`):

```rust
// POST /api/preflight/ingest
async fn api_ingest_remote_preflight(
    State(db): State<Db>,
    State(standing): State<Arc<dyn StandingResolver + Send + Sync>>,
    headers: HeaderMap,
    Json(payload): Json<PreflightResult>,
) -> Result<(StatusCode, Json<IngestResponse>), IngestError> {
    // 1. Identity — out of Standing's scope. Whatever NQ uses for peer
    //    identification (mTLS subject, signed header, etc.) produces a
    //    canonical principal id.
    let actor = extract_actor(&headers)?;  // e.g. "component:nq:linode"

    // 2. Build the standing request.
    let req = StandingRequest::new(
        Principal::new(actor.clone(), actor),
        payload.claim_kind.clone(),     // e.g. "sqlite_wal_state"
        payload.target.clone(),         // e.g. "labelwatch/foo"
        local_audience(),               // e.g. "nq:main"
        Utc::now(),
    ).map_err(IngestError::StandingRequest)?;

    // Visible-not-binding does not spend, so this walkthrough does not add a
    // jti/body digest. A StoreResolver binding request MUST add both.

    // 3. Ask Standing.
    let decision = standing.assess(&req)
        .map_err(IngestError::StandingResolve)?;

    // 4. Record the decision in NQ's own receipt. ALL attribution
    //    fields must survive into the receipt — no omitting
    //    standing_enforced, no dropping standing_basis.
    let receipt = nq_receipt::builder()
        .kind(ReceiptKind::PreflightIngested)
        .subject(&payload.target)
        .actor(&actor)
        .evidence(json!({
            "payload_digest": payload.digest(),
            "standing": {
                "standing_mode": "visible_not_binding",
                "verification_mode": decision.verification_mode,
                "identity_substrate": decision.identity_substrate,
                "standing_enforced": decision.standing_enforced,
                "standing_verdict": decision.verdict,
                "standing_basis": decision.standing_basis,
                "resolver": decision.resolver,
                "actor": decision.actor,
                "claim_kind": decision.claim_kind,
                "subject_scope": decision.subject_scope,
                "jti": decision.jti,
                "body_digest": decision.body_digest,
                "emitted_receipt_digest": decision.emitted_receipt_digest,
                "reuse_bound": decision.reuse_bound,
                "certified_sound": decision.certified_sound,
                "scope": decision.scope,
                "audience": decision.audience,
                "evaluated_at": decision.evaluated_at,
                "expires_at": decision.expires_at,
            },
        }))
        .build()?;

    // 5. In visible_not_binding mode: persist the preflight result
    //    regardless of verdict. Standing surfaces posture; it does not
    //    enforce. A `Denied` decision is RECORDED, not refused.
    //
    //    THIS DOES NOT MEAN PUBLIC UNAUTHENTICATED INGESTION IS OK.
    //    Visible-not-binding applies to *claim authority*, not to
    //    *storage abuse*. The admission boundary in step 1 (identity)
    //    is independent of Standing.
    db.write_preflight(&payload, &receipt).await?;

    Ok((StatusCode::OK, Json(IngestResponse {
        receipt_digest: receipt.digest,
        standing_verdict: decision.verdict,
        standing_enforced: decision.standing_enforced,
    })))
}
```

## Wiring the resolver

NQ embeds `StaticConfigResolver` in the application state:

```rust
let config = StaticConfig::load(Path::new("/etc/nq/standing.toml"))?;
let resolver: Arc<dyn StandingResolver + Send + Sync> =
    Arc::new(StaticConfigResolver::new(
        config,
        ResolverMode::VisibleNotBinding,  // explicit; no default flip
    ));
```

The config file follows the shape in `examples/static-config.toml`:

```toml
[[entry]]
actor = "component:nq:linode"
claim_kind = "sqlite_wal_state"
subject_scope = "labelwatch/*"
audience = "nq:main"
```

Matching semantics are fixed (see `docs/remote-standing-boundary.md`
§ "Scope matching semantics"):

- `actor`: exact match on canonical principal id
- `claim_kind`: exact
- `subject_scope`: exact OR trailing-`*` prefix on `/`-delimited path
- `audience`: exact, instance-qualified

## What this gives NQ operators

1. **A receipt-visible standing posture for every remote ingestion.**
   Operators can `nq query receipts --kind preflight_ingested` and see
   which peer asserted what, whether Standing admitted them, and which
   resolver decided. `standing_basis` distinguishes `unknown_peer` from
   `claim_kind_out_of_scope` from `audience_mismatch` so the failure
   mode is legible.

2. **Red-team smoke test.** Submit from `component:nq:rogue`:

   ```
   POST /api/preflight/ingest
   actor=component:nq:rogue
   claim_kind=sqlite_wal_state
   subject_scope=labelwatch/foo
   audience=nq:main

   → 200 OK
   → receipt records standing_verdict=denied,
     standing_basis=unknown_peer, standing_enforced=false
   → preflight ingested but flagged
   ```

3. **Per-instance vocabulary discipline.** Audience is `nq:main`, not
   `nq`. A grant for `nq:main` does *not* admit testimony into
   `nq:other`. This is the Kerberos-shaped failure mode (ticket for one
   realm replayed to another) refused at the front door.

## What does NOT belong in this integration

- **Identity verification.** Standing's resolver assumes the caller has
  already produced a verified canonical `Principal`. mTLS, HMAC, OIDC —
  Standing doesn't care, but identity is upstream of the resolver call.
- **Binding-grade enforcement in this walkthrough.** Visible-not-binding mode
  records a denied decision but does not refuse ingestion. Standing's binding
  `StoreResolver`, time/use-bounded `AssertionGrant`, per-audience replay
  ledger, request-body requirement, MAC proof option, key rotation primitives,
  and compromise doctrine are implemented. NQ must still make an explicit
  consumer-side binding decision, verify identity, provide `jti` plus
  `body_digest`, and record/refuse the result; this file does not claim that
  integration has happened.
- **Lease issuance.** `StaticConfigResolver` needs no grant store. A real
  lease-backed integration has the genesis operator issue a bounded lease to a
  distinct speaker and uses `StoreResolver`; see
  `docs/consumer-integration.md` and `examples/nq-gov-wicket-demo.sh`.
- **Cross-component receipt provenance.** A chain from NQ's preflight
  receipt back to Standing's decision (and forward to Wicket's
  preflight admission, and onward to Nightshift's closure assessment)
  is open in the cartography doctrine. Don't invent its format here.

## How to drive the resolver from the CLI

For an operator validating a peer's expected standing without firing a
real ingestion:

```
standing resolver test \
  --resolver static_config \
  --config /etc/nq/standing.toml \
  --actor component:nq:linode \
  --claim-kind sqlite_wal_state \
  --subject-scope labelwatch/foo \
  --audience nq:main \
  --mode visible_not_binding
```

Output is the canonical-JSON `StandingDecision` — the same shape NQ's
ingestion receipt embeds.

```
standing resolver list-modes
```

Lists the three implementations exercised by `resolver test` and points to
`standing assert resolve` for the fourth, store-backed assertion-lease path.

## Keepers for the NQ side

```text
Identity proves who spoke. Standing decides whether that speaker had
the right to speak in that role.

Visible-not-binding applies to claim authority, not to storage abuse.

Audience is instance-qualified. `nq:main` is not `nq`.

The receipt's resolver/standing_basis/standing_enforced are
how operators tell static config from grant-enforced. They must
not be optional fields.
```

## Smoke-test cross-reference

The `crates/standing-cli/tests/integration.rs` integration suite drives
the resolver through all four NQ Track-A claim kinds (`sqlite_wal_state`,
`disk_state`, `dns_state`, `ingest_state`) using the same example config
NQ would ship. The mismatch tests verify each `standing_basis` value is
reachable from the CLI surface. NQ's integration smoke test should
mirror that shape, exercising the four claim kinds plus the
`unknown_peer`, `claim_kind_out_of_scope`, and `audience_mismatch`
refusal paths against its own integration of `StaticConfigResolver`.
