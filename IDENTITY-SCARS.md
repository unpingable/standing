# Identity Scars

Lessons from Kerberos, Vault, OAuth, SPIFFE, and IAM — translated into
standing invariants and design constraints. This is a scar catalog, not
a design doc. It exists so we don't reenact community theater.

Source: audit of standing's identity model against known failure patterns
across production identity systems.

## Current standing status vs these scars

| Scar | Standing status | Notes |
|------|----------------|-------|
| 1. Bootstrap / secret zero | HMAC shared secret | Placeholder, not a real bootstrap story. Adequate for slice 1. |
| 2. Time in the protocol | No iat/nbf/exp on identity claims | WorkloadId has created_at but no expiry. Receipts have timestamps. |
| 3. Revocation as consolation prize | Short-lived grants by design | Good. Revocation is acceleration, not foundation. |
| 4. Renewal storms | No renewal mechanism yet | Not a problem yet. Will matter when grants auto-renew. |
| 5. Identity service availability | SQLite, local-first | No hot-path central dependency currently. Good. |
| 6. Bearer tokens are loot | HMAC identity is bearer | No proof-of-possession yet. Secret + identity file = loot. |
| 7. Audience restriction | Not implemented | No aud field on identity or grants. |
| 8. Identity ≠ authorization | Clean separation | Principal/ActorContext/auth matrix are distinct. Good. |
| 9. Delegation chains | Not implemented | No delegation yet. When it comes, attenuate. |
| 10. Naming | Stable principal IDs (wl:name:location) | Separate from display labels. Good. |
| 11. Federation | Single issuer | Not a problem yet. |
| 12. Key rotation | No key rotation | Single shared secret, no kid, no overlap. |
| 13. Replay resistance | No jti/nonce | Receipts are content-addressed but identity claims aren't replay-resistant. |
| 14. Runtime binding | HMAC to name+location | Binding is to declared name, not to runtime attestation. |
| 15. Sidecars as shadow authority | N/A | No sidecars yet. |
| 16. Human vs workload identity | Workload only | Good scope boundary. |
| 17. Group/role sprawl | Three roles: subject/admin/system | Minimal. Keep it that way. |
| 18. Explainability | query why shows actor/subject/role/policy | Good for current scope. |
| 19. Audit lifecycle | Receipts at every transition | Good. Covers issuance through terminal state. |
| 20. Break-glass | Not implemented | Will need it eventually. |
| 21. Fail-open vs fail-closed | Fail-closed globally | May need action-specific policy later. |
| 22. Policy/identity version drift | Policy hash pinned in receipts | Good. No identity schema version yet. |
| 23. Caches | No caching layer | No problem yet. |
| 24. Compromise recovery | No plan | Shared secret compromise = full reissue. |
| 25. Assessment-compromised state | Not implemented | Only yes/no currently. |
| 26. Canonicalization | RFC 8785 / JCS for receipts | Good. Identity claims use serde defaults. |
| 27. Attribute provenance | Subject from verified identity, role from ActorContext | Adequate. No derived attributes yet. |
| 28. TOCTOU | CAS on head digest | Good for grant state. Identity check is point-in-time. |
| 29. Negative decision semantics | Distinct error types | InvalidTransition, Unauthorized, GrantExpired, GrantNotFound. Good. |
| 30. Retry behavior | Not defined | CLI is fire-and-forget. Programmatic callers need guidance. |
| 31. Multi-tenancy | Not implemented | Single namespace. |
| 32. Dangerous defaults | Absent fields rejected | Policy rejects empty subject/action/target. Good. |
| 33. Unknown claim handling | Not applicable yet | Fixed schema. |
| 34. Identity resurrection | Stable principal IDs help | wl:name:location won't collide accidentally. |
| 35. Authorization shadowing | Single auth path | Only one policy evaluation per transition. Good. |
| 36. Temporary exception paths | None exist | Keep it that way. |
| 37. Root store creep | Single shared secret | Nothing to sprawl yet. |
| 38. Crypto agility | SHA-256 + HMAC-SHA-256 only | No algorithm negotiation. Fine for now. |
| 39. Logging as exfil | Receipts contain evidence, not secrets | Signatures are in identity files, not in receipts. Good. |
| 40. Policy simulation | sweep --dry-run exists | No general "would this work?" mode yet. |
| 41. Drills | Not planned | Need compromise recovery drill eventually. |
| 42. Success-path skepticism | query why explains the path | Shows which policy, which actor, which role. Good start. |

## Invariants derived from this audit

These augment the existing invariants in CLAUDE.md:

1. **Identity assertion is not authority.** It is a signed proposal about
   subject, issuer, audience, freshness. The store decides authority.
2. **Short-lived by default.** Expiry carries the security load. Revocation
   is acceleration, not foundation.
3. **Receipts record the story, not just the outcome.** Actor, subject, role,
   policy hash, evidence, timestamps. Postmortems need receipts, not myths.
4. **Assessment-compromised is a valid result.** When trust state is
   incoherent, the honest answer is "I cannot determine standing right now."
5. **Bootstrap is the real system.** Secret zero deserves paranoid design,
   not decorative prose. Current HMAC shared secret is a placeholder.

## What to build next (priority order from this audit)

1. **Audience restriction on identity claims** (scar 7) — aud field on
   WorkloadId, verifier checks it strictly
2. **Identity expiry** (scar 2) — exp on WorkloadId, reject expired
   identity at verification, record verifier time in receipts
3. **Replay resistance for sensitive ops** (scar 13) — jti on identity
   claims, nonce/challenge for destructive transitions
4. **Assessment-compromised state** (scar 25) — third verdict type beyond
   allow/deny
5. **Compromise recovery plan** (scar 24) — documented procedure for
   shared secret rotation

## The general law

Identity systems do not usually die because signatures are fake. They die
because semantics drift while the signatures remain perfectly real.

The scariest failures are the ones that look like success.
