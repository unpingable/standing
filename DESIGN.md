# nq-standing

**Observable standing for automation and workloads**

## One-line pitch

Modern infra is good at telling you whether a service is alive and much worse at telling you whether it was entitled to do what it just did.

## Relationship to NQ

Sibling, not feature. Same philosophy, different object.

- **NQ** = diagnostic truth about state (health, freshness, failure domains)
- **nq-standing** = diagnostic truth about entitlement (grants, policy, receipts)

Same operator posture: queryable, generationed, local-first, anti-technique.

## The constitutional architecture

- **NQ** accuses (findings, evidence, classification)
- **nlai** interprets (claim/evidence/receipt kernel, stdlib-only)
- **Governor** authorizes (custody, approval, intervention for agents)
- **nq-standing** witnesses entitlement (grants, policy decisions, receipts for workloads)

## Core question

Who had standing to do what, when, under whose authority, under which policy, and with what observable consequence?

## Design stance

Keep the layers separate:
- **agent observes**
- **directory locates**
- **issuer grants**
- **policy decides**
- **receipts witness**

## Core concepts

| Concept | Question |
|---|---|
| Health | Can it run? |
| Identity | Who is it? |
| Standing | May it act? |
| Authority | Who granted standing? |
| Receipt | What proves the grant/use/denial/revocation happened? |

## Anti-goals

- Not a secret store or Vault replacement
- Not a service mesh
- Not workforce IAM
- Not a PKI grand unification project
- Not "zero trust" branding with no evidence model

## Components

1. **nq-agent** — signed heartbeats, workload identity, local freshness
2. **nq-directory** — service catalog with receipts, presence tracking
3. **nq-issuer** — short-lived scoped grants, renewal/revocation/expiry
4. **nq-policy** — decision point, allow/deny with receipts
5. **nq-query** — "why was this allowed?" query surface

## First vertical slice

Deploy bot → signed identity → short-lived grant → policy decision → receipt → queryable.

If that path snaps together cleanly, the architecture is real. If it demands ten abstractions and a PKI opera, it's theology.

## MVP phases

1. Signed workload identity (attestable presence)
2. Directory with receipts (who claims to exist where)
3. Standing grants (short-lived, scoped, explicit lifecycle)
4. Policy decision receipts (why was this allowed/denied)

## Failure modes to solve early

- Identity valid, heartbeat stale
- Heartbeat fresh, grant expired
- Grant valid, policy changed
- Grant revoked between issuance and use
- Decision succeeded but receipt write failed
- Receipt missing: action failed, or observation failed?
- Old grant replayed
- Workload identity rotated mid-lease

## Key architectural decision

**Fail-closed on receipts.** No receipt, no standing. For workload authorization, fail-open means "trust the gap," which is exactly Δw (write-authority drift).

## WLP bridge

nq-standing decision receipts are WLP DECISION messages. Build receipt format WLP-compatible from the start:
- Same canonical JSON (RFC 8785 / JCS)
- Same hash scheme (SHA-256)
- No signatures yet, hash mandatory
- Implement natively in Rust (not shared crate yet — just agree on schema)

## Buyer wedge

Entry point: automation and non-human actors (CI runners, deploy bots, controllers, service accounts, agentic workflows).

- SRE: "why was this allowed?" as cleanly as "was this up?"
- Security: fewer immortal credentials, visible least-privilege
- Compliance: machine-authority evidence for automation
- Developers: inspectable grant path and policy decision
