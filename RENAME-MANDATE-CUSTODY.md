# Rename plan — `standing` → Mandate Custody (MC)

**Status:** name **ratified** (operator, 2026-07-17). Execution **deferred** to a coordinated
pre-ag-ng window. This is a non-binding plan doc — **no code renamed yet.** It exists to state
what this repo actually owns and to frame the decisions the mechanical rename will need, so the
rename becomes boring instead of a wire-format adventure.

## Why rename

`standing` is overloaded across competing ontological roles: the repo/product, the runtime
grant state, the *formal judgment*, the entitlement source. Survivable inside the theory,
corrosive as a product name (every sentence needs a parenthetical). The fix is a semantic split,
not a synonym:

> **Mandate Custody** — issuance / activation / lifecycle / expiry / revocation / receipt
> machinery around bounded mandates (what this repo does).
> **Standing** — the present judgment that a specific mandate supports *this* act or assertion
> (what this repo *produces*, and what keeps the word).

**Vocabulary ladder:** Mandate (bounded source of entitlement) → **Mandate Custody**
(the machinery) → **Standing** (the judgment) → **Authority** (follows only when standing +
other gates hold).

## The custody house pattern (why "custody" is safe, not a re-overload)

`custody-of-X` is a *parametric* family — custody-of-secrets, -state, -receipts, -mandates —
each qualified by its object, not competing roles. Stable job of any custody surface:

> preserve identity, provenance, lifecycle, transfer history, and valid disposition of an
> object **without treating possession as authority.**

Negative law (on-brand): **custody does not mint standing; possession ≠ authority.** MC governs
the mandate *from which* a standing judgment may be derived — it never confers the judgment.
Discipline: never name anything merely `custody`; always qualify by object; do **not** build a
universal `Custody<T>` just because the pattern is visible.

## Decisions to make BEFORE the mechanical rename (open — for repo owner + operator)

The semantic split means **not every `standing-*` crate becomes `mandate-custody-*`.** Some are
custody machinery (→ MC); the judgment/verdict surface *keeps* "standing." Map each deliberately:

| crate            | likely role            | candidate name (CONFIRM, do not assume) |
|------------------|------------------------|------------------------------------------|
| `standing-grant`   | custody (lifecycle)    | `mandate-custody-grant` / `mc-grant`     |
| `standing-store`   | custody (persistence)  | `mandate-custody-store` / `mc-store`     |
| `standing-policy`  | custody or judgment?   | depends where policy is evaluated        |
| `standing-receipt` | receipt custody        | `mandate-custody-receipt` (but see wire) |
| `standing-identity`| identity binding       | likely custody-side                      |
| `standing-cli`     | operator surface       | `mc` / `mandate-custody-cli`             |
| (new?)             | the **judgment**       | keep `standing-*` — this is the word that survives |

**Wire / schema — the crux (leading option: NO break):** receipt schema IDs like
`standing.grant_use.v1` are consumed by AG (`standing_client`) and transition-kernel
(`StandingOutput`). Because **"standing" survives as the judgment**, these schema IDs can
plausibly **stay** — a receipt attesting a standing judgment is legitimately `standing.*` even
when the producing repo is Mandate Custody. If confirmed, the rename touches **product + crate
names only, not wire identifiers** → no lockstep consumer break. (Fallback if a schema rename is
truly wanted: version + dual-emit through a transition, never a hard cut.)

**Surfaces to split at the type level:** `ActMandate` / `AssertMandate` — the two things
`standing` straddled (entitlement-to-act vs -to-assert). Same anti-laundering family as the
existing read↔write non-coercion.

## Coordinated-rename checklist (the window op, when it runs)

1. Confirm the crate map + the "standing survives for the judgment" split above.
2. Confirm schema IDs stay (`standing.*`) → **no wire break**; else version + dual-emit.
3. Rename crates / workspace / CLI binary.
4. Update consumers only if any *renamed* symbol crosses the boundary: AG `standing_client`,
   transition-kernel `StandingOutput`, wlp, `standing_spendability`. (If schema stays, most
   consumers are untouched.)
5. Update `README` / `DESIGN.md` / `GOVERNOR-CROSSWALK.md` / `AGENTS.md` / `CLAUDE.md`.
6. Tag.

## Timing

After the Lean gate cooks and AG-classic is brought up to speed, **before** ag-ng imports these
concepts into crate/schema names (after that, the names sediment). Do it deliberately in that
window — not as a drive-by, because it's a coordinated cross-repo operation the operator owns.
