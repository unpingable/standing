# standing

> **Status (2026-07-26): the Standing / mandate-custody office —
> separately instantiated, not part of the current operational vertical.**
> This repository implements the jurisdiction "may this actor act or assert,
> now, under what mandate — with expiry, revocation, replay-refusal, and
> delegation denied by default." It is **not absorbed** by AG ng or Docket:
> AG ng's authorization rests on an asserted principal-authentication
> premise (not mandate custody), and Docket's local standing is a
> domain-local execution capability, not the mandate. Its consumers are the
> classic lineage (AG classic `standing_client`, transition-kernel
> `StandingOutput`) at lab-backed strength — "lab-backed compatibility
> evidence, not live testimony" remains the honest bar. "**Mandate Custody
> (MC)**" is this office's operator-ratified (2026-07-17) but **unexecuted**
> rename (`RENAME-MANDATE-CUSTODY.md`); wire IDs `standing.*` survive any
> rename. New features on its own roadmap remain welcome; nothing here is
> deprecated.

Observable standing/entitlement for automation and workloads.

Modern systems are good at proving possession of credentials. They are much worse at proving entitlement to consequence.

Credential validity is not claim validity. Access to a boundary does not imply standing to perform a consequential action, or to make an assertion that downstream systems may treat as binding.

Standing records and exposes scoped entitlement at a boundary: who had standing, for what action, over what target, within what scope and time window, under what policy, and with what receipt chain.

Kerberos made service access presentable. Standing makes consequence entitlement observable.

Standing does not implement Kerberos-style ticket transport. Grants are recorded and verified against authoritative state rather than carried by workloads or agents as self-justifying legitimacy.

Standing models both **entitlement-to-act** (may an actor perform an operation
against a target?) and **entitlement-to-assert** (may a speaker introduce this
class of claim about this subject to this audience?). Assertion standing ships
as a time-bounded, use-budgeted lease with replay defense, freeze/thaw, binding
resolution, and receipt-bearing spends. The integration surface is lab-backed;
no live NQ, Wicket, or Nightshift deployment is claimed.

## 30-second specimen

A workload gets a grant — policy says allow, the grant activates, every check
is green. Then it tries to spend the grant one second past its window:

```bash
standing grant request --identity bot.id.json --secret bot-key \
  --action deploy --target prod/web-api --duration 1
standing grant activate --id <grant-id> --identity bot.id.json --secret bot-key
sleep 2
standing grant use --id <grant-id> --identity bot.id.json --secret bot-key \
  --evidence '{"deployed":"v1.2.3"}'
# error: grant expired at 2026-06-12T15:52:28.119267816+00:00   (exit 1)
```

The credential didn't change. The policy didn't change. Time passed — and the
grant that was valid when issued is not valid when spent. Then ask the system
to show its work:

```bash
standing query why --id <grant-id>
#   subject: wl:deploy-bot:host-abc (deploy-bot)
#   scope:   deploy → prod/web-api
#   state:   active
#   expires: 2026-06-12T15:52:28.119267816+00:00
#   policy decision:  verdict: "allow"  reason: "all checks passed"
#   grant issued:     digest: cbf2563a…  time: …:27.119
#   grant activated:  digest: 0c31ae4a…  time: …:27.132
```

The issued/activated receipt chain survives unchanged. The expired attempt is a
structured, non-consuming refusal: because no state transition occurred,
Standing emits no transition receipt for it. A later query still shows the last
authorized state and the window that caused refusal. Setup for this run
(identities + operator-fiat genesis) is the first four commands of the Quick
start below; the timestamps and digests above came from a real run.

## Invariants

```text
Standing is state, not cargo.
  A grant identifier is not authority. Authority is determined
  only by fresh verification against the authoritative standing
  store. The contrast Standing names is authoritative online
  verification vs portable self-sufficient legitimacy — JWTs,
  tickets, and macaroons are formats of the latter class
  whenever the verifier treats possession as sufficient.

Model is not principal.
  Models propose. Workloads invoke. Standing attaches to
  workloads and operators, never to models. Model identity is
  attribution; workload identity is authority.

No standing cache without explicit lease doctrine.
  Caching standing decisions for availability reintroduces
  bearer legitimacy unless the cache is itself governed as
  an explicit lease with bounded consequence.

Re-verify at every consequence-bearing gate.
  Standing is not checked once per run. It is checked at
  admission, at capacity / token consumption, at packet
  emission, at every later mutation gate.
```

## What it does

- Tracks grant lifecycles: request, issue/deny, activate, use, expire, revoke, abandon
- Tracks assertion-lease lifecycles: issue, activate, prove, exhaust, expire, revoke
- Produces content-addressed receipts at every state transition
- Answers "why was this allowed?" by walking receipt chains
- Evaluates policy decisions with pinned policy hashes
- Resolves assertion standing in advisory or binding mode, with replay and
  request-body binding on the binding path
- Freezes and thaws grant classes as a receipt-bearing incident-mode overlay
- Stores everything in SQLite with fail-closed atomic transitions

## What this is not

- Not an identity provider, policy engine, admissibility governor, actuator, workflow engine, or agent platform
- Not a truth or evidence evaluator; assertion standing says who may speak in a
  role, while systems such as [NQ](https://github.com/jbeck/nq) decide what the
  evidence can testify to
- Not an admissibility lock; an admissibility layer such as Wicket or a consuming [Governor](https://github.com/jbeck/agent_gov) decides whether entitlement may bind consequence
- Not a secret store, service mesh, workforce IAM, or PKI project

Standing may verify principals or workload identity at grant boundaries, but it does not issue identities. Identity is substrate.

## Conceptual stack

```text
Identity substrate      who/what is acting
Access authorization    may it reach the service or boundary
Standing                does it have scoped entitlement here
Admissibility layer     may this bind consequence
Continuity/afterlife    what remains live, stale, watched, or constrained later
```

## Quick start

```bash
cargo build
cargo test

# Create a verified workload identity
standing identity create --name deploy-bot --location host-abc --secret my-key > bot.id.json

# Name the chain root: operator-fiat genesis. Exactly one per instance.
standing identity create --name operator --location laptop --secret my-key > op.id.json
standing genesis install --identity op.id.json --secret my-key

# Request a grant (identity verified, policy evaluates, issues or denies)
standing grant request --identity bot.id.json --secret my-key \
  --action deploy --target prod/web-api --duration 300

# Activate and use it (identity verified at each step)
standing grant activate --id <grant-id> --identity bot.id.json --secret my-key
standing grant use --id <grant-id> --identity bot.id.json --secret my-key \
  --evidence '{"deployed":"v1.2.3"}'

# Query: why was this allowed?
standing query why --id <grant-id>

# Query: full receipt chain
standing query chain --id <grant-id>

# Sweep expired grants (system actor)
standing grant sweep

# Pure, non-authorizing effect classification: does this operation require
# assertion standing? This check neither finds nor spends a lease.
standing assert check \
  --principal component:nq:linode --consumer wicket:local \
  --claim-kind deploy_authorization --target prod/web-api \
  --effect binding

# The genesis operator issues a bounded assertion lease to a distinct speaker.
standing assert grant \
  --identity bot.id.json --secret my-key \
  --operator-identity op.id.json --operator-secret my-key \
  --claim-kind deploy_authorization --subject-scope 'prod/*' \
  --audience wicket:local --max-uses 3

# A binding consumer spends the lease. Binding requires a replay nonce and the
# SHA-256 digest of the request body; success emits an AssertionMade receipt.
standing assert resolve \
  --principal wl:deploy-bot:host-abc --consumer wicket:local \
  --claim-kind deploy_authorization --target prod/web-api --effect binding \
  --id <assertion-grant-id> --identity bot.id.json --secret my-key \
  --subject-id prod/web-api --jti <single-use-nonce> \
  --body-digest <sha256-of-request-body>
```

## Architecture

```
deploy-bot ──request──> [policy engine] ──decision receipt──> [grant issuer]
                                                                    |
                                                              issue / deny
                                                                    |
                                                              ┌─────v─────┐
                                                              │  SQLite   │
                                                              │ receipts  │
                                                              │  grants   │
                                                              └─────┬─────┘
                                                                    |
                                                         standing query why
```

The assertion path uses the same authoritative store and receipt kernel, but
splits authority explicitly: the genesis operator issues a lease to a distinct
speaker; the speaker presents a nonce- and body-bound proof; a binding resolver
spends the lease before the consumer may treat the claim as consequential.

Receipt format: canonical JSON (RFC 8785 / JCS) + SHA-256. WLP-compatible.

## Limitations

The fail-closed chain is only as strong as the identity substrate beneath it.
Standing verifies workload identity and request proofs with symmetric HMAC
keys. `kid`-based lookup and primary/legacy rotation are implemented, but key
distribution, storage, and asymmetric trust remain outside Standing. Receipts
inherit the cryptographic strength of that substrate, not more; see
[`docs/component-key-keytab.md`](docs/component-key-keytab.md) and
[`docs/compromise-recovery.md`](docs/compromise-recovery.md).

Standing is also a single point of authority by design. Authority unreachable means fail-closed means nothing acts. For consequence-bearing operations that is the correct polarity. A future proposal to "cache standing decisions for resilience" is the bearer-token failure mode sneaking back in through the availability door, and is refused by the no-cache-without-lease invariant above.

## License

Licensed under Apache-2.0.
