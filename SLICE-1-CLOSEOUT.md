# Slice 1 Closeout (historical v0.1 snapshot)

> **Status:** Historical closeout for tag `v0.1.0` (2026-05-20), not the
> current roadmap. The entitlement-to-act baseline below remains valid, while
> Phase 4b–6 subsequently added entitlement-to-assert, genesis-rooted chains,
> request-proof hardening, freeze/thaw, and the binding resolver surface.

Standing's first vertical slice was complete at this point in the history.

## What is behavior-closed

These are tested, enforced, and real:

| Scar | What | How |
|------|------|-----|
| 2 | Time in protocol | exp, iat, skew tolerance (30s), clock divergence budget (300s) |
| 3 | Short-lived grants | Leases with explicit expiry, sweep reaper |
| 7 | Audience restriction | aud field, strict fail-closed verification |
| 8 | Identity ≠ authorization | Principal / ActorContext / auth matrix are distinct layers |
| 10 | Stable naming | Opaque principal IDs (wl:name:location), separate display labels |
| 13 | Replay resistance | jti enforcement on grant request, SQLite-backed seen_jti |
| 17 | Role sprawl | Three roles (subject/admin/system), auth matrix as data |
| 18 | Explainability | query why shows actor, subject, role, policy hash, evidence |
| 19 | Audit lifecycle | Content-addressed receipts at every state transition |
| 25 | Assessment-compromised | Fires on temporal incoherence, clock divergence, storage failure |
| 28 | TOCTOU | CAS on head digest in Store::transition() |
| 29 | Negative decisions | Specific error types: InvalidTransition, Unauthorized, GrantExpired, etc. |
| 32 | Dangerous defaults | Empty subject/action/target rejected by policy |

## Original deferrals, reconciled with current code

These were the slice-1 gaps. Their current disposition is recorded so this
historical closeout does not masquerade as a current backlog:

| Scar | Slice-1 gap | Current disposition |
|------|-------------|---------------------|
| 1 | Bootstrap / secret zero | Still an explicit substrate boundary. HMAC proves the architecture; secret distribution and initial trust remain deployment concerns. |
| 6 | Bearer tokens are loot | Assertion spends now support a body-bound, fresh, replay-defended MAC proof. Workload identity remains symmetric-key based; possession/runtime binding is not claimed. |
| 12 | Key rotation | `kid`, `KeyResolver`, and primary/legacy `KeySet` overlap are implemented. Distribution, storage, and a real rotation drill remain external operations work. |
| 14 | Runtime binding | Still deferred. Identity binds to a declared name/location, not node, pod, or process attestation. |
| 20 | Exceptional access | Not a missing bypass verb. A defensible break-glass path is a cross-system governed lifecycle: predelegated request-bound authority, ordinary refusal revalidation at use time, single-use/replay defense, durable receipts, and a persistent reconciliation/disposition obligation. Standing owns some primitives but must not absorb the whole authority decision. |
| 22 | Policy/identity version drift | Closed for the local formats: identity and receipt schema versions are explicit and verified; policy hashes remain pinned. |
| 24 | Compromise recovery | Operating doctrine is documented in `docs/compromise-recovery.md`; detection, key distribution, and drills remain deployment-owned. |

## What is explicitly unsupported

These remain outside the current project scope unless a concrete consumer
changes the boundary:

- **Federation / multi-issuer** — single issuer, single trust domain
- **Runtime attestation** (SPIFFE-style node/pod binding) — name-based identity only
- **Complex delegation chains** — no delegation support
- **Human identity** — workload identity only
- **Caching / offline verification** — all verification is online, synchronous
- **Policy pluggability** — HardcodedPolicy only (trait exists for future work)
- **Key distribution / asymmetric PKI** — rotation primitives exist, but
  Standing is not a secrets manager or certificate authority
- **Fail-open on any path** — universally fail-closed; action-specific failure policy is deferred

## Current runway after Phase 4b–6

1. **Wire a real assertion-standing consumer.** The NQ/Wicket/Nightshift
   surface is lab-backed compatibility evidence, not deployment testimony.
2. **Exercise key custody operationally.** Run a real overlap rotation and a
   compromise drill; keep key distribution outside Standing.
3. **Choose a stronger identity substrate only when required.** Runtime
   attestation, asymmetric trust, and bootstrap remain explicit forcing-case
   decisions.
4. **Compose exceptional access across authority domains.** Do not add an ad
   hoc Standing bypass; promotion requires the full governed lifecycle and a
   consumer that can carry its reconciliation obligation.
5. **Release closure.** Reconcile naming, release metadata, and adoption notes
   after the current hardening pass.

## Stats at the v0.1.0 tag

- 80 tests (16 identity, 10 auth matrix, 25 store, 12 integration, 8 receipt, 4 policy, 4 replay, 1 CLI)
- 9 commits
- 6 crates
- ~2500 lines of Rust
