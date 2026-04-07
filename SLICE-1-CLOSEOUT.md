# Slice 1 Closeout

Standing v0.1 — first vertical slice complete.

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

## What is deferred

These are real gaps, acknowledged and prioritized for future work:

| Scar | What | Why deferred | When |
|------|------|-------------|------|
| 1 | Bootstrap / secret zero | HMAC shared secret is adequate for proving architecture. Real bootstrap is a design project. | v1 hardening or v2 |
| 6 | Bearer tokens are loot | No proof-of-possession. Bearer + short TTL + aud + jti + replay is the current mitigation. | v1 hardening decision: accept bearer with docs, or add minimal PoP |
| 12 | Key rotation | No kid, no overlap windows. Single shared secret. | v1 hardening — add kid/schema_version groundwork |
| 14 | Runtime binding | Identity binds to declared name, not runtime attestation. | v2 |
| 20 | Break-glass | No emergency access path. | v1 hardening |
| 22 | Policy/identity version drift | Policy hash pinned in receipts. No identity schema version. | v1 hardening — add schema_version |
| 24 | Compromise recovery | No documented procedure for key rotation or trust anchor replacement. | v1 hardening |

## What is explicitly unsupported

These are out of scope for v1. Not "later" — **not this project version**:

- **Federation / multi-issuer** — single issuer, single trust domain
- **Runtime attestation** (SPIFFE-style node/pod binding) — name-based identity only
- **Complex delegation chains** — no delegation support
- **Human identity** — workload identity only
- **Caching / offline verification** — all verification is online, synchronous
- **Policy pluggability** — HardcodedPolicy only (trait exists for future work)
- **Key rotation** — no rotation support; secret compromise = full reissue
- **Fail-open on any path** — universally fail-closed; action-specific failure policy is deferred

## Completion runway

1. **Integrate into Agent Governor** — first real consumer, replace trusted actor construction
2. **Add schema_version + kid** — cheap future-proofing before migrations get expensive
3. **Decide bearer vs PoP** — the central theft story for v1
4. **Break-glass + compromise recovery** — emergency honesty
5. **Release closure** — tag, docs, demo, adoption notes

## Stats

- 80 tests (16 identity, 10 auth matrix, 25 store, 12 integration, 8 receipt, 4 policy, 4 replay, 1 CLI)
- 9 commits
- 6 crates
- ~2500 lines of Rust
