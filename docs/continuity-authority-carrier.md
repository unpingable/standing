# Continuity authority carrier v1

Status: qualified contract for the single closed relation
`substrate_incarnation`. This is a Standing-owned authority path and an
NQ-consumed acquisition prerequisite. It is not evidence that a transition
occurred.

## The warrant

`standing.continuity_authority_issuance_request.v1` asks Standing to issue a
warrant. The resulting `standing.continuity_authority.v1` binds exactly:

```text
subject_ref
relation = substrate_incarnation
predecessor_ref
successor_ref
authority_occurrence_ref
issuance_request_id
standing instance and issuance-receipt basis
NQ audience
issuer principal
replay identity
```

The genesis operator is the only issuer in v1. Issuance creates an append-only
Standing receipt and an Ed25519-signed export. The export's `issued_at` is
historical evidence only. It is not the proof that the warrant preceded an
observation.

The warrant means only:

> This Standing instance permits the exact transition to be used as an
> eligible continuity edge, provided later evidence establishes the successor
> state and its consumer independently finds the evidence admissible.

Its closed `nonclaims` set says what it does not establish: transition
occurrence, evidence truth, current attribution, or routine reliance. Standing
does not turn a subject claim into an empirical verdict.

## The causal fence

Before provider invocation, NQ preallocates its durable acquisition/intake
identity and computes the digest of its exact acquisition intent. It sends
`standing.continuity_acquisition_commitment_request.v1` to Standing using the
identity whose principal exactly equals the warrant's instance-qualified
`nq_audience`.

Standing atomically verifies that:

* the warrant occurrence exists and is not revoked for new commitments;
* the exact signed-authority payload digest matches;
* the NQ audience and authenticated requester match;
* the signing identity is the same pinned Standing key;
* request, replay, and acquisition identities are unused or resolve to the
  same exact stored request.

It then durably records and signs
`standing.continuity_acquisition_commitment.v1`, binding:

```text
authority occurrence + exact signed payload digest
acquisition identity + exact acquisition-basis digest
NQ audience + Standing instance
commitment occurrence + request/replay identity
```

Only after NQ durably records that signed commitment may it invoke the
provider. Provider intake and evidence must continue to carry the exact
acquisition and commitment identities. Thus the proof of causal precedence is
structural:

```text
warrant exists
→ acquisition commits exact warrant
→ provider may be invoked
→ dependent evidence may exist
```

It is not a comparison among `issued_at`, `committed_at`, `observed_at`, or
receipt times. A completed acquisition without the commitment cannot later be
amended or re-sealed to add one. A later, even backdated, warrant necessarily
lacks the original acquisition prerequisite and cannot license that evidence.

Nightshift may receive the evidence before separately receiving the authority
export. Delivery order does not alter the already signed acquisition chain.
When the exact export arrives, Nightshift can verify the historical fact that
NQ had committed it before invocation.

## Signatures and trust

The two signed envelopes are:

* `standing.signed_continuity_authority.v1`;
* `standing.signed_continuity_acquisition_commitment.v1`.

Each contains `key_id`, exact payload, SHA-256 of canonical JCS payload bytes,
and an Ed25519 signature over:

```text
signed-envelope schema ASCII || NUL || canonical payload bytes
```

Consumers pin the Standing key id and raw 32-byte Ed25519 public key. Public
verification material cannot mint Standing authority. Private-key storage,
rotation/revocation distribution, hardware isolation, and designated-host
custody remain deployment gates; this repository does not claim them merely
because the carrier is asymmetric.

The bundle verifier checks both signatures and the exact cross-object
occurrence, payload digest, audience, Standing-instance, and requested-edge
bindings. Trusting an arbitrary JSON file or an unpinned embedded key is not
verification.

## Replay, deliberate reissuance, and revocation

An exact issuance or commitment replay converges on its original immutable
occurrence. Reusing its request, replay, or acquisition identity with changed
bytes refuses. A deliberate new issuance uses new request and replay identities
and creates a distinct authority occurrence even for the same edge. There is no
mutable `continuity_authorized=true` state.

Revocation prevents new acquisitions from committing the warrant. It does not
erase the historical fact that an already committed acquisition named the
warrant while it was usable. Exact replay of that stored commitment therefore
converges after revocation; a new commitment refuses. Revocation does not make
historical evidence true or current.

## Independence and ownership

For the exact dependent observation produced by an acquisition, the
pre-provider prerequisite makes self-licensing impossible: that observation
cannot cause a warrant that the already committed acquisition had to contain
before the observation existed. NQ must refuse provider invocation until its
durable request contains the verified bundle.

This is not a universal causal ledger. Broader claims about indirect planning
influence outside this exact acquisition chain remain outside v1. No
`independent=true` assertion exists.

Standing issues permission. NQ owns the pre-provider gate and evidence
provenance. Nightshift consumes the proof when evaluating attribution and
reliance. AG and Docket are not involved: a continuity warrant is neither
effectful work nor execution custody.

## Explicit exclusions

V1 has no generic relation string and no positive support for mandate/scope
succession. It does not use subject-token equality, mutable current-substrate
fields, DNS, hostnames, IP addresses, or timestamps to infer continuity. It
adds no Linode or remote-host semantic, deployment mechanic, quarantine queue,
or authority for provider effects.
