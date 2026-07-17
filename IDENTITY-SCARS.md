# Identity Scars

Lessons from Kerberos, Vault, OAuth, SPIFFE, and IAM — translated into
standing invariants and design constraints. This is a scar catalog, not
a design doc. It exists so we don't reenact community theater.

Source: audit of standing's identity model against known failure patterns
across production identity systems.

> **Status:** Living scar catalog, reconciled 2026-07-17 after Phase 4b–6.
> Older slice-1 priorities are retained below as history; this table is the
> current implementation view.

## Current standing status vs these scars

| Scar | Standing status | Notes |
|------|----------------|-------|
| 1. Bootstrap / secret zero | HMAC shared secret | Explicit substrate limit, not a complete bootstrap story. Distribution and initial trust are deployment-owned. |
| 2. Time in the protocol | Implemented | Identity claims carry issued/expiry time and verification applies skew and validity bounds. Grant and assertion windows are enforced fail-closed. |
| 3. Revocation as consolation prize | Short-lived grants by design | Good. Revocation is acceleration, not foundation. |
| 4. Renewal storms | No automatic renewal | Still intentionally absent; leases expire rather than silently renew. |
| 5. Identity service availability | SQLite, local-first, fail-closed | Binding resolution reads authoritative state on the hot path. Store unavailability refuses consequence. |
| 6. Bearer tokens are loot | Partly mitigated | Assertion request proofs can be body-bound, MAC-verified, fresh, and replay-defended. Workload identity remains symmetric-key based; secret + claim material is still sensitive. |
| 7. Audience restriction | Implemented | Identity claims, assertion leases, proofs, and replay records are audience-bound. |
| 8. Identity ≠ authorization | Clean separation | Principal/ActorContext/auth matrix are distinct. Good. |
| 9. Delegation chains | Explicitly denied | No on-behalf-of or transitive standing; forwarding components speak under their own standing. |
| 10. Naming | Stable principal IDs (wl:name:location) | Separate from display labels. Good. |
| 11. Federation | Single issuer | Not a problem yet. |
| 12. Key rotation | Library support implemented | Signed `kid`, `KeyResolver`, and primary/legacy `KeySet` overlap exist. Storage, distribution, and rotation drills remain external. |
| 13. Replay resistance | Implemented on sensitive paths | Identity/grant requests use `jti`; assertion spends use a per-audience replay ledger. |
| 14. Runtime binding | HMAC to name+location | Binding is to declared name, not to runtime attestation. |
| 15. Sidecars as shadow authority | N/A | No sidecars yet. |
| 16. Human vs workload identity | Workload only | Good scope boundary. |
| 17. Group/role sprawl | Three roles: subject/admin/system | Minimal. Keep it that way. |
| 18. Explainability | query why shows actor/subject/role/policy | Good for current scope. |
| 19. Audit lifecycle | Receipts at every transition | Good. Covers issuance through terminal state. |
| 20. Exceptional access | Cross-system, consumer-gated | This is not a missing bypass command. A valid design needs predelegated request-bound authority, use-time ordinary refusal checks, single-use/replay defense, durable receipts, and a persistent reconciliation/disposition obligation across authority domains. Standing owns only some of those primitives. |
| 21. Fail-open vs fail-closed | Fail-closed globally | May need action-specific policy later. |
| 22. Policy/identity version drift | Implemented locally | Policy hashes are pinned; identity and receipt schema versions are explicit, signed/hashed, and verified. |
| 23. Caches | No caching layer | No problem yet. |
| 24. Compromise recovery | Doctrine documented | `docs/compromise-recovery.md` covers repudiation, freeze, revocation, re-key, and genesis compromise. Detection and drills remain operational. |
| 25. Assessment-compromised state | Implemented | Temporal incoherence, excessive divergence, and storage failures surface separately from allow/deny. |
| 26. Canonicalization | Versioned formats | Receipts use RFC 8785/JCS + SHA-256; identity signatures cover a fixed versioned field set. |
| 27. Attribute provenance | Subject from verified identity, role from ActorContext | Adequate. No derived attributes yet. |
| 28. TOCTOU | CAS on head digest | Good for grant state. Identity check is point-in-time. |
| 29. Negative decision semantics | Distinct error types | InvalidTransition, Unauthorized, GrantExpired, GrantNotFound. Good. |
| 30. Retry behavior | Partly defined | Assertion spends use bounded CAS retry; replay is a named refusal. Wider programmatic retry guidance remains useful. |
| 31. Multi-tenancy | Not implemented | Single namespace. |
| 32. Dangerous defaults | Absent fields rejected | Policy rejects empty subject/action/target. Good. |
| 33. Unknown claim handling | Conservative refusal | Consumer contracts require unknown decision variants and refusal modes to fail closed. |
| 34. Identity resurrection | Stable principal IDs help | wl:name:location won't collide accidentally. |
| 35. Authorization shadowing | Single auth path | Only one policy evaluation per transition. Good. |
| 36. Temporary exception paths | None exist | Keep it that way. |
| 37. Root store creep | Named key custody boundary | Key sets make rotation expressible, but Standing deliberately does not become a secret store or PKI. |
| 38. Crypto agility | SHA-256 + HMAC-SHA-256 only | No algorithm negotiation. Fine for now. |
| 39. Logging as exfil | Receipts contain evidence, not secrets | Signatures are in identity files, not in receipts. Good. |
| 40. Policy simulation | Preview surfaces exist | `sweep --dry-run`, pure `assert check`, and non-authorizing assertion preview exist; previews never authorize effect. |
| 41. Drills | Doctrine exists, exercise external | The compromise ladder is written; a real key-rotation/compromise drill remains deployment work. |
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

## Historical slice-1 priority order and disposition

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

**Current disposition:** Items 1–4 shipped in slice 1. The compromise-recovery
doctrine shipped with Phase 5 in `docs/compromise-recovery.md`; detection,
distribution, and drills remain outside the library.

## Current promotion boundary

The next meaningful identity work is operational and consumer-driven: wire a
real binding consumer, exercise key rotation and repudiation, and require a
stronger bootstrap/runtime-attestation substrate only when that deployment
forces it. Exceptional access must remain a composed, receipt-bearing lifecycle
across authority domains; an ad hoc Standing override would erase the very
separation this catalog protects.

## The general law

Identity systems do not usually die because signatures are fake. They die
because semantics drift while the signatures remain perfectly real.

The scariest failures are the ones that look like success.
