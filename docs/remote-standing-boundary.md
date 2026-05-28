# Remote Standing Boundary — local manifestation

> **Status:** `candidate / non-binding`. Names the surface Standing will eventually expose to cross-machine consumers. Does not authorize binding-grade enforcement in any consumer until each consumer's own local manifestation is filed and ratified.
>
> **Composes with:** `~/git/cartography/coordination/nq-REMOTE_STANDING_BOUNDARY.md` (filed 2026-05-27 by notquery-Claude). That document is the cross-constellation primitive. This document is Standing's local manifestation of it.

## Why this document exists

Slice 1 of Standing closed (`SLICE-1-CLOSEOUT.md`, 2026-05-20) shipping entitlement-to-act: workload-identity-verified, scoped, time-bounded grants for `(actor, action, target)` tuples, with receipts at every state transition. That surface is local: actor, store, and policy live in the same process.

NQ, Nightshift, and Wicket are not guaranteed to live in the same process — increasingly, not in the same machine. The moment a remote NQ submits a finding, or a remote Nightshift requests a closure, a new question lands at the boundary:

> May this remote actor introduce *this class of testimony or request* into this receiving system, in this scope, to this audience, within this window?

That is **entitlement-to-assert** (or entitlement-to-request) — structurally distinct from entitlement-to-act. An actor who has authenticated and reached the boundary is not, by virtue of that, allowed to introduce arbitrary testimony or trigger arbitrary lifecycle requests downstream. Standing is the layer that decides.

## The keeper

> A remote call is not just transport. It is a standing claim with a payload.

Identity proves who spoke. Standing decides whether that speaker had the right to speak in that role.

## The five layers a remote-surface design must distinguish

```text
identity      — who/what is calling?
authz         — what verbs may this caller invoke?
standing      — what kind of testimony/request may this caller introduce?
transport     — what protects the call in flight?
receipt/audit — what durable record survives the call?
```

Standing-the-tool owns exactly the third layer. It does not become identity provider, authz engine, transport layer, or audit aggregator.

Conflating these is the failure mode:

- *"mTLS says this is nq-linode, therefore accept whatever it says"* — identity mistaken for standing.
- *"The caller is logged in, therefore they may transition this finding"* — authz mistaken for standing.
- *"We added a bearer token"* — solves one layer, leaves four unaddressed.
- *"VPN means trusted"* — collapses all five into one.

## Constellation role split

```text
Standing-the-tool
  who/what may speak or request?

Wicket
  may this proposed operation proceed?

NQ
  what can this evidence testify to?

Nightshift
  what posture follows from the evidence?

AG (future)
  larger governed mutation regime
```

**No component grants itself the authority of an adjacent component.**

## Entitlement-to-act vs entitlement-to-assert

Slice 1 primitive:

```text
may actor A perform action X on target Y, until time T?
```

The new primitive named here:

```text
may actor A introduce claim_kind K about subject_scope S
into audience B, within window [t0, t1]?
```

Invariants (mirrored from the act primitive):

- Standing-to-assert does **not** mean the claim is true. It only means the actor is permitted to introduce that class of testimony to that audience. NQ still decides what the evidence can testify to. Nightshift still decides posture. Wicket still preflights action.
- Standing-to-request does **not** mean the action is admissible. It means the actor is permitted to ask. Wicket decides whether the ask becomes a do.
- Receipts at every state transition that *does* exist. Fail-closed on receipts.
- Content-addressed (RFC 8785 JCS + SHA-256). WLP-compatible.

### `subject_id` vs `subject_scope` — vocabulary that should stop blurring

Two related things hide under one name in the slice-1 / MVP code. The doc keeps them distinct from here on:

```text
subject_id     the concrete subject of one specific assertion or
               testimony packet. E.g. "labelwatch/foo",
               "host:storage01", "ns_observation_loop".

subject_scope  the grant's coverage pattern; the class of subjects
               the grant authorises a speaker to assert about.
               E.g. "labelwatch/*", "host:storage01" (exact),
               "ns/*".
```

A `StandingRequest` carries a `subject_id` (the concrete thing being asserted about right now). A grant — `AssertionGrant` (Phase 4) or a `StaticConfigEntry` (MVP) — carries a `subject_scope` (the pattern of subjects the grant covers). The matching function asks: *does this grant's subject_scope cover that request's subject_id?*

The current MVP code field is named `subject_scope` on both sides for slice-1 reasons; that does not need to change today. The doc stops conflating them, because the distinction is load-bearing for component-testimony and for the eventual Phase 4 lease-shaped grant.

Sibling-side names for the same distinction:

```text
NQ-NS bilateral spike
  (~/git/cartography/coordination/NQ-NS-CHANNEL-SPLIT.md)
  subject_id     same meaning as here
  coverage_scope grant-pattern-on-the-NQ-receiving-side (a
                 declared-coverage entry, not a Standing grant
                 itself, but composes against the same axis).
```

## Grant vs request proof — the Kerberos split

Standing borrows shape from Kerberos-like systems: a long-lived (well, lease-long) grant and a per-request proof. **Do not let "has grant" become "any packet with that grant ID is valid forever."**

```text
AssertionGrant (lease-shaped)
  actor may assert claim_kind K about subject_scope S
  to audience B between t0 and t1

RequestProof (per-request)
  this specific call is fresh, from that actor,
  for that audience, now, against that body
```

Minimum fields a request proof must carry when binding-grade enforcement is live:

```text
grant_id
jti                  (request nonce; replay-defended per audience)
audience             (canonical, instance-qualified)
issued_at
body_digest          (SHA-256 of canonical request body)
mac / signature      (over the above, using the audience's expected key)
```

MVP does not require the full request-proof envelope shipped on the wire — but the `StandingRequest` type in `standing-policy::resolver` carries the matching shape (`actor`, `claim_kind`, `subject_scope`, `audience`, `now`, optional `jti` and `body_digest`) so consumers building binding-grade flows later are not refactoring the trait.

## Canonical principal and audience names

Principal canonicalization is authorization logic, not formatting decoration. Do not allow these to become silently equivalent:

```text
nq
nq-linode
nq.neutral.zone
host:nq-linode
component:nq@linode
```

Canonical forms used by Standing:

```text
component:<name>:<instance>     e.g. component:nq:linode
                                     component:nightshift:sushi-k
human:<handle>                  e.g. human:jbeck
workload:<name>:<location>      e.g. workload:deploy-bot:host-abc
                                  (current WorkloadId form, slice-1 native)
```

Aliases are explicit mappings in resolver configuration, not vibes. Two distinct canonical strings are two distinct principals.

Audience is also instance-qualified:

```text
audience: "nq:linode"
audience: "nightshift:sushi-k"
audience: "wicket:local"
```

A grant meant for one NQ instance is **not** portable to another NQ instance. Cross-instance use is a Kerberos-shaped failure (ticket for one realm replayed to another).

## Imported sibling vocabulary (provisional)

Standing does not own the axis or action-class taxonomies. They are sibling vocabulary, used here to compose against NQ, NS, Wicket, and AG without redefining them. Convergence is cartography's job, not Standing's. The lists below are *recognised and provisional* — Standing carries / evaluates standing over requests that reference these surfaces, but Standing does not enumerate them as authoritative or ratify them.

**Axes** (NQ/NS own these; Standing does not):

```text
truth           substrate-state testimony (what is the world like?)
posture         classified verdicts derived from truth (how should we read it?)
ack             operator intent (what has a human resolved?)
```

`truth / posture / ack` are claim axes — categorical layers of what kind of claim is being made. Standing may evaluate standing over a request whose claim references one of these axes, but the axis itself is not Standing's vocabulary.

**Action-classes** (cartography doctrine + NQ-NS bilateral; Standing imports):

```text
read                            one-shot query; standing not durable
lifecycle                       ack / quiesce / suppress / close
configuration                   saved-query CRUD; declared-context updates
admin                           schema / migration / runtime controls
component-testimony             producer-side emit of self-attestation
component-testimony-subscription durable consumer-side standing to receive
action-preflight                inbound request to perform an action
```

`component-testimony` is a testimony / action surface — a producer-side emit. `component-testimony-subscription` is a separate action-class — durable consumer-side standing to receive. **Neither is an axis.** The temptation to write `axis = component-testimony-subscription` is exactly the schema-fossil to refuse.

Standing's resolver assesses requests carrying any of these action-classes; the wire shape per action-class remains sibling-owned (cartography + the consuming repo). Standing does not ratify additions to either list — recognise + compose, not enumerate + own.

## Scope matching semantics

String scopes are policy, not decoration. Matching rules for MVP:

```text
claim_kind        exact string match against the configured allowlist;
                  no wildcards, no case folding

subject_scope     exact match OR explicit suffix-* prefix match
                  ("labelwatch/*" matches "labelwatch/foo" and
                  "labelwatch/foo/bar", but not "labelwatchx").
                  No regex. No glob beyond a trailing *.
                  Wildcard only at the end of a /-delimited path.

audience          exact match. Must be instance-qualified
                  ("nq:linode", not "nq").
```

These rules are documented inline in the `StaticConfigResolver` source. Any change to matching semantics is a `kid`-level event — consumers must be able to assume that scope strings written into config files have stable meaning across upgrades.

## The boundary against Wicket's local "standing" vocabulary

Wicket already uses *standing* internally for an operation-phase ladder:

```text
Wicket StandingClass
  Observe < Interpret < Recommend < Authorize < Execute
```

Standing-the-tool's entitlement-to-assert is a different axis entirely:

```text
Standing-the-tool
  actor × claim_kind × subject_scope × audience × window
```

These ladders **must not be projected into each other.** Standing's `AssertionGrant` will not be flattened into Wicket's `ActorStanding{class, provenance}` shape.

> Wicket's standing is operation-phase standing. Standing's standing is speaker/requester standing.

Same word, different axis. The tax is paid in documentation.

When the consumer-integration phase has a real plant, Wicket will likely grow a separate field — tentatively `Intent.caller_assertion_standing` — that carries Standing's output without collapsing it into the operation-role ladder. Naming finalized when the bridge has traffic, not before. **The bridge stays unbuilt until then.**

## The four resolver modes (the pluggable seam)

Components **must not hard-link** to Standing-the-tool as a mandatory dependency.

> Standing integration should strengthen the remote boundary, not become the only way the system can run.

`StandingResolver` trait + implementations in `standing-policy::resolver`:

```text
DenyAllResolver
  Refuses every request. Panic-button; test scaffold.
  Consumer-facing name: DenyAllResolver.

LocalOnlyResolver
  Refuses any non-local actor. Default for `private_local`
  exposure profile.
  Consumer-facing name: AllowLocalOnlyResolver.

StaticConfigResolver
  Static allowlist of (actor, claim_kind, subject_scope, audience)
  tuples. Coarse, configuration-managed; no Standing service required.
  The MVP-enabling implementation.
  Consumer-facing name: StaticConfigResolver.

StoreResolver
  Defers to Standing's assertion-grant store (post-MVP). Real
  distributed-prod posture: caller identity + assertion grant with
  revocation, expiry, audience, claim-kind scope.
  Consumer-facing name: StandingToolResolver.
```

## Refusal modes the trait must express

```text
unknown_peer                  caller identity not recognized
unknown_issuer                grant carries unknown issuer (no realm trust)
standing_absent               no grant or config entry covers this request
standing_expired              matching grant exists but window has closed
grant_not_yet_valid           grant exists but not_before is in the future
claim_kind_out_of_scope       grant exists but does not cover this claim_kind
subject_out_of_scope          grant exists but does not cover this subject
audience_mismatch             grant exists but for a different audience
clock_skew_exceeded           verifier_time vs issuer_time delta > max skew
request_timestamp_out_of_window  request is too old or too new to evaluate
replay_detected               jti already seen in this audience's replay cache
receipt_missing               fail-closed: required receipt not produced
delegation_denied             request is on-behalf-of a third party; default deny
```

Each surfaces in `StandingDecision.standing_basis` so consumers and operators can distinguish them.

## Receipt attribution discipline

Every `StandingDecision` recorded by a consumer must carry these fields. They are not optional. The trait's `StandingDecision` carries them by construction so consumers cannot drop them silently:

```json
{
  "standing_mode": "visible_not_binding",
  "verification_mode": "static_config",
  "identity_substrate": "hmac_workload_id",
  "standing_enforced": false,
  "standing_verdict": "denied",
  "standing_basis": "static_config_no_match",
  "scope": ["sqlite_wal_state:host:storage01"],
  "audience": "nq:linode",
  "expires_at": null,
  "resolver": "StaticConfigResolver"
}
```

- `standing_mode` distinguishes `visible_not_binding` from `binding`. Mode is consumer-side; Standing records what the consumer told it.
- `verification_mode` distinguishes `static_config` from `store_grant` from `local_only` from `deny_all`. Different rigor; different basis.
- `identity_substrate` records how the principal was authenticated — `hmac_workload_id` today, `mtls`/`oidc`/`spiffe` future.
- `standing_enforced: false` makes it impossible to misread visible-not-binding as binding.

The cartography sin to refuse:

> Pretending `StaticConfigResolver` and `StandingToolResolver` are the same. The receipt's `resolver`, `verification_mode`, and `standing_basis` are how operators tell the difference.

## Visible before binding — and what that does not mean

Standing emits `StandingDecision` outputs that are *receipt-visible and advisory* before any consumer wires them as binding. Each consumer flips independently from `standing_visible_not_binding` to `standing_required` mode.

A consumer that wires Standing into a binding workflow must preserve the distinctions named in `docs/synthetic-boundary-probes.md` § "Hot-path readiness: visible before binding" — once binding, Standing must be capable of blocking, downgrading, routing, or requiring an open finding, not merely annotating.

**Visible-not-binding applies to *claim authority*, not to *storage abuse*.** A denied peer is still a peer who reached the ingestion surface. Even when standing is advisory, the receiving system must not give unauthenticated public access to its receipts table, its evidence store, or its state-transition surface. Standing is upstream of the admissibility decision; it is not upstream of the admission boundary itself.

> Standing may be advisory, but the ingestion surface still needs an admission boundary.

## Replay cache per audience

Replay defense is **mandatory before binding-grade enforcement**:

```text
each audience maintains a seen_jti cache
TTL tied to request validity window + max clock skew
binding mode: replay refused with `replay_detected`
visible mode: replay posture recorded, request still surfaceable
```

A single cross-audience replay table is **not** acceptable. Replays must be scoped to the audience the request was issued for — a jti accepted by `nq:linode` should not block the same jti issued for `nightshift:sushi-k`.

The slice-1 store already has `seen_jti` for grant requests; extending it per-audience for assertion-grade flows is post-MVP work.

## Delegation is denied by default

When NQ forwards evidence to Nightshift, or Nightshift forwards a request to Wicket, the question is: does the original actor's standing travel?

**Default answer: no.** Transitive standing is opt-in, not opt-out.

```text
No on-behalf-of without explicit delegable: true on the grant.
No multi-hop delegation chains without explicit max_delegation_depth.
A forwarding consumer asserts in its own name, with its own standing,
  unless the grant explicitly authorizes delegation.
```

This is the failure mode that Windows authentication performance art preserved at considerable cost.

## Revocation is TTL-first

Once a grant is out, instant revocation is hard. Standing's default discipline:

```text
short TTLs are the primary revocation mechanism
revocation lists are best-effort / online lookup
binding-grade consumers MUST define whether they require live
  revocation check, and the resolver MUST report whether the
  check happened
```

A consumer that needs instant revocation builds the online-enforcement path. Standing does not silently promise it.

## Clock-skew doctrine

Cross-host means clocks matter. Standing's contract for binding-grade enforcement:

```text
max_clock_skew                  bounded delta between verifier_time
                                and issuer-supplied timestamps;
                                slice-1 default 30s, configurable

not_before / not_after          inclusive lower bound, exclusive upper
evaluated_at                    verifier's clock at decision time;
                                recorded in StandingDecision

issuer_time vs verifier_time    delta recorded when material; refused
                                if outside max_clock_skew

refusal reasons surface as:
  clock_skew_exceeded
  grant_not_yet_valid
  grant_expired
  request_timestamp_out_of_window
```

No silent forgiveness. Time bugs become security bugs wearing a calendar.

## Authorization data is not truth

A repeated trap in ticket-shaped systems: the ticket carries authorization data that downstream readers treat as fact.

```text
standing allowed
  ≠ claim true
  ≠ evidence sufficient
  ≠ action admissible
```

Standing decisions carry basis and scope. They do not carry truth. NQ still evaluates whether the evidence supports the claim. Wicket still evaluates whether the proposed operation is admissible. Nightshift still evaluates posture. Standing's verdict is a precondition, not a substitute, for each of those evaluations.

## Component key material on disk

If Standing becomes the cross-machine boundary, every component holds some local secret/material — a keytab equivalent. Standing names this:

```text
component_key                   the local material a component uses
                                to issue or verify identity claims;
                                slice-1 form is the HMAC shared
                                secret consumed by --secret

required documentation:
  where it lives on disk
  who can read it (file permissions; secrets manager; tpm)
  rotation path (kid-overlap window; post-cutover refusal)
  blast radius if stolen (single component? whole audience?)
  kid association (which key produced which grant?)
```

This document does not yet specify the keytab format — `docs/identity-substrate-gap.md` (roadmap Phase 6) is the future home. Naming the doctrine now prevents the slice-1 single-shared-secret model from being mistaken for the forever model.

## Realm / federation explicitly unsupported

Standing borrows shape from Kerberos. People will look for realms. **MVP and 1.0 stance:**

```text
single issuer / local trust domain only
no federation
no cross-realm trust
no transitive trust
no multi-issuer conflict resolution
```

A grant from an unknown issuer surfaces as `unknown_issuer`. Not "maybe trust because the signature validates." Not "fall back to the static config." Not "log a warning and proceed." Unknown issuers are refused, full stop, until federation is *explicitly* designed — which it is not, and not in 1.0.

## Kerberos lineage, not Kerberos mechanism

Standing borrows the **shape** of grant/standing/request-proof from Kerberos-like systems. It does not implement Kerberos.

**Non-goal:** Standing is not Kerberos. It does not implement realms, AS-REQ/TGS-REQ exchanges, ticket-granting tickets, delegation, service discovery, single sign-on, or network login. It borrows the grant-vs-authenticator split, the audience restriction, the time bounds, and the replay defense — and refuses the rest.

The reason to name this explicitly is that the next agent who reads this doc will be tempted to ask *"should we add realms?"* and lose an evening. The answer is no.

## Kerberos-shaped scars to preserve

Summary of scars this design preserves rather than re-discovers:

```text
- grant ≠ request proof
- principal and audience names are canonical authorization inputs
- replay cache is per-audience and mandatory before binding
- delegation is denied by default
- revocation is TTL-first unless live checks are explicitly required
- key material on disk has named blast radius
- standing allowed does not mean claim true
- no federation / cross-realm trust in MVP or 1.0
- clock skew is explicit refusal, not silent forgiveness
- authorization data is not truth
```

## What components must explicitly refuse

Mirrored from cartography:

- **"VPN means trusted."** Private-substrate assumptions do not portable. Tailscale today is the internet tomorrow.
- **"Same LAN means trusted."** Component identity required regardless of network topology.
- **"Dashboard cookie reused as component identity."** Two different action classes; two different identity schemes.
- **"We added bearer auth, so we're good."** One layer of five.
- **"Standing tool isn't built yet, so we'll skip it."** The seam must exist even when the only resolver is `StaticConfigResolver`.
- **"Auth before we name the read boundary."** Auth without named read boundaries is a login screen on arbitrary SQL.

## The subscription inversion (deferred)

Standing's current shape — `StandingRequest`, `StandingDecision`, the four resolver modes, the assertion-grant lifecycle anticipated for Phase 4 — assumes **emission semantics**:

```text
actor (speaker, upstream) → audience (listener, downstream)
```

Subscription does not fit this shape cleanly. The `component-testimony-subscription` action-class imported above inverts the direction:

```text
actor (subscriber, downstream) ← source (producer, upstream)
```

In subscription, the actor is the would-be receiver; the standing being requested is *durable receive-standing* rather than *one-shot emit-standing*; and the natural "audience" of the subscription grant points upstream to the producer, opposite direction from emission. NQ-NS proposes subscription as a peer action-class precisely because lease-shaped Standing-tool primitives (expiry, revocation, per-audience scope) matter for subscription in a way they do not matter for one-shot reads.

Standing recognises the inversion but does not solve it here. The naming below is provisional and *not* a wire commitment:

```text
standing_kind = emit (assertion) | receive (subscription)
```

Subscription wire shape, `StandingRequest` field-naming for the receive case, audience-direction discipline in receipts, and lease semantics for durable receive-standing all belong to Phase 4 or later. Naming the hole; not pouring concrete into it while the plumbers are still yelling.

## What this document does not specify

Deferred until forcing cases converge:

- Concrete wire format for cross-process `StandingRequest` / `StandingDecision`. MVP is library-embedded.
- Cross-component receipt provenance format (NQ → Standing → Wicket → Nightshift).
- Cross-component revocation propagation semantics.
- Audit-aggregation surface (constellation-wide audit composition).
- Daemon / HTTP service shape. Library-embedded through MVP and probably through 1.0.
- **Producer-side time fields.** NQ-NS witness packets distinguish `generated_at` (producer-side, when the packet was minted) and `observed_at` (observer-side, when the underlying event was caught) from verifier-side `evaluated_at` / `now`. Standing today carries only verifier-side time. Phase 4 likely needs to carry producer-side time alongside; the MVP code is not retrofitted now.
- **Subscription / receive-standing shape.** See "The subscription inversion" above.
- **Full action-class and axis convergence.** Standing imports sibling vocabulary as provisional; cartography owns convergence; the lists in "Imported sibling vocabulary" are subject to extension from sibling filings.

## Composition with sibling filings (as of 2026-05-28)

The cross-constellation surface this document composes with is moving fast. Snapshot of who's filed what, so a reader does not have to triangulate it from a dozen repos:

```text
Cartography (constellation-shared)
  nq-REMOTE_STANDING_BOUNDARY.md             primitive / candidate doctrine
    (2026-05-27, NQ-Claude origin)
  NQ-NS-CHANNEL-SPLIT.md                     bilateral planning spike
    (2026-05-28, NS-Claude origin)
  SELF-SUBJECT-COLLAPSE.md                   cross-component shared gap
    (2026-05-28, three forcing instances:
     NS, NQ-on-NQ, agent_gov GOV_GAP_BASIS_001)
  wlp-notes-as-wire-layer-for-standing-boundary.md
    (2026-05-28, Wicket-Claude origin;
     constellation-side WLP cross-ref)

NQ
  REMOTE_SURFACE_AUTH_AND_STANDING_GAP.md    NQ-local manifestation
  NQ_NS_CHANNEL_SPLIT_NQ_SIDE.md             NQ half of bilateral spike
  WITNESS_IDENTITY_AND_ABSENCE_GAP.md §2     canonical absence taxonomy
                                              (7 states + MAY-split)

Wicket
  WICKET_REMOTE_STANDING_ADAPTER_GAP.md      filed 2026-05-27;
    consumer-gated adapter, not implemented.
    Names the vocabulary boundary:
    Standing AssertionGrant / StandingDecision
      ≠ Wicket ActorStanding / StandingClass.

WLP
  WLP_STANDING_BOUNDARY_CROSSREF.md          filed 2026-05-28;
    WLP is the wire layer BELOW the receipt/audit slot,
    not a peer component, not the reconciler.
    StandingDecision serialises as a WLP AuthorizationReceipt;
    WLP carries decisions, does not make them.

NS (Nightshift)
  NQ_NS_CHANNEL_SPLIT_NS_SIDE.md             pending; NS-Claude
    expected to file the NS-local channel-split half.
```

Standing's role across this set: speaker / requester entitlement, with `StandingDecision` as the artifact the others compose against. Standing does not own the per-component manifestation list; cartography curates it.

**Forcing pressures on Phase 4** (consumer-gated lease-shaped `AssertionGrant` lifecycle), updated:

```text
1. NQ binding flip — visible_not_binding → binding for remote
   preflight ingestion. The original wedge.
2. Wicket adapter — Intent.caller_assertion_standing or
   equivalent; gated on a Wicket consumer plant.
3. Self-subject external reconciliation — SELF-SUBJECT-COLLAPSE
   names operator-as-external-reconciler under lease-shaped
   Standing as one of three resolution paths. Standing-tool
   Phase 4 lease semantics are the gate for path (b).
4. component-testimony-subscription — durable receive-standing
   needs lease semantics in a way one-shot reads do not.
```

Any one of those gates Phase 4 by itself; the four together raise the priority but do not change the discipline. Standing waits for a concrete consumer to knock before building.

## Relationship to existing Standing docs

- `README.md` — names entitlement-to-act as current, entitlement-to-assert as roadmap. This document is the entrance of that roadmap.
- `docs/synthetic-boundary-probes.md` — pre-policy fence-line; remains valid. This document is the first named plant; probes are not superseded.
- `SLICE-1-CLOSEOUT.md` — entitlement-to-act baseline. Hardening items remain 1.0-blocking, not MVP-blocking.
- `DESIGN.md` — historical / provenance; not authoritative for this surface.
- `IDENTITY-SCARS.md` — identity layer scars; this document operates downstream of them. Identity is substrate.

## Keepers, restated

```text
A remote call is not just transport. It is a standing claim with a payload.

Identity proves who spoke. Standing decides whether that speaker had
the right to speak in that role.

Standing-to-assert does not mean the claim is true.

Same word, different axis: Wicket standing classifies the operation role.
Standing-the-tool classifies the speaker.

Visible before binding. Binding only after hardening.

Visible-not-binding applies to claim authority, not to storage abuse.

Standing borrows Kerberos shape, not Kerberos mechanism.

Principal canonicalization is authorization logic.

Time bugs become security bugs wearing a calendar.

Axes describe what is claimed. Action-classes describe what is being done.
Conflating them is tomorrow's schema fossil.

Loose coupling is allowed. Ambiguous standing is not.
```

## Provenance

Filed 2026-05-27 as Standing's local manifestation of `~/git/cartography/coordination/nq-REMOTE_STANDING_BOUNDARY.md`. Forcing case: NQ, Nightshift, and Wicket no longer co-located; the boundary that was implicit becomes explicit when calls cross machines.

Two review passes incorporated 2026-05-27: ChatGPT roadmap nits (phase numbering, MVP scope reduced to resolver+StaticConfig, lease-shaped not action-shaped, explicit `standing_enforced` receipt fields, ingestion-vs-claim-authority distinction, scope matching semantics, softened forward-compat claims) and a Kerberos-scars amendment set (grant-vs-request-proof split, canonical principal/audience naming, replay cache per audience, delegation-denied default, TTL-first revocation, keytab doctrine, clock-skew doctrine, authorization-data-is-not-truth, realm/federation explicitly unsupported, Kerberos-lineage-not-mechanism non-goal).

Paper-only reconciliation 2026-05-28 against sibling filings that landed between Standing's MVP commit and the next operator session: NQ-NS bilateral channel-split spike, SELF-SUBJECT-COLLAPSE shared gap, Wicket's `WICKET_REMOTE_STANDING_ADAPTER_GAP.md`, WLP's two cross-references, NQ's `NQ_NS_CHANNEL_SPLIT_NQ_SIDE.md`. Vocabulary discipline added: `subject_id` vs `subject_scope` distinction, axes (truth/posture/ack) recognised as sibling-owned, action-classes enumerated as imported/provisional, `component-testimony-subscription` recognised as an action-class **not** an axis, subscription/emission directional inversion named as a deferred design question, producer-side time fields named as deferred. Phase 4 forcing pressures updated to four. No code changed; no sibling repo artifacts edited from Standing.
