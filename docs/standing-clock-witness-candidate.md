# Standing Clock Witness — the measuring stick, not the guillotine (candidate)

> **Status:** `candidate / non-binding`. Names a surface Standing may expose; authorizes no implementation and admits no architecture. A handle for review.
> **Originated:** 2026-06-18.
> **Authorized by:** agent_gov, as constellation-governor / cross-repo custody root. AG authorizes the *filing*; Standing owns the *doctrine*. See AG `docs/cross-tool/managed-repo-candidate-filing-note.md`.
> **Provenance:** lifted from agent_gov's clock-witness discipline (`src/governor/clock_witness.py`) and the standing→spendability seam (`src/governor/standing_spendability.py`), as a per-office choke-point steal — *"steal the choke point, not the throne"* (the pattern NQ used in `nq/docs/working/decisions/PREFLIGHT_CORE_CANDIDATE.md`).
> **Composes with:** `docs/remote-standing-boundary.md` (entitlement-to-assert at the boundary); AG `docs/cross-tool/receipt-sovereignty-microkernel-note.md` (Standing is the one office whose refusal is non-mechanical).

## Why this document exists

There is a tempting wrong import. The kernel arch has a clean choke-point pattern — *only one private constructor mints the official verdict; evaluators return findings, never verdicts* (NQ took exactly this for its preflight). Standing looks like it wants the same thing: `facts -> standing verdict`, mechanized and unpleadable.

**That import would mechanize the soul and call it elegance.** Standing's refusal is the one non-mechanical refusal in the constellation — *the asker does not get to grant its own entitlement; model identity is attribution, not authority.* The moment standing becomes a pure predicate over facts, it becomes gameable: whoever controls the facts controls the verdict, and the political/contextual judgment Standing exists to hold evaporates.

So Standing steals something narrower and genuinely useful: the **clock witness**, and an explicit fence against taking the rest.

## The keeper

> Standing gets the measuring stick, not the guillotine.

A gap is a difference between **compatible clock witnesses, not numbers.** Wall clocks step backward under NTP; subtracting two timestamps across a step is garbage with an ISO 8601 smile. The licensed primitive is a typed reading on a declared, compatible basis — refuse incompatible source / epoch / direction rather than emit a confident wrong number. (AG enforces exactly this by type in `clock_witness.py`: `elapsed_ns` is the only licensed subtraction.)

A standing receipt is *valid when observed, void when spent.* That two-clock structure — observed-then-exercised — is where the temporal basis of standing lives, and Standing is the office that should expose it.

## The candidate surface

```text
StandingClockWitness {
  subject
  claim
  observed_at        # typed clock reading on a declared basis — when standing was observed
  exercise_at        # typed clock reading on a compatible basis — when it is being spent
  basis              # the clock basis (source + epoch); a witness, not a scalar
  compatibility      # do observed_at and exercise_at share a compatible basis?
}
```

Standing **exposes** these witnesses and the compatibility fact. Downstream policy (AG / the consuming office) **decides** whether the gap is acceptable for *this* use. AG's gate already states this split: *the witness exposes the clocks, the policy decides the gap.* This note pins Standing's half of it.

## Non-goals — the load-bearing half

These are the point of the document. The witness type is easy; the fence is what prevents the bad import.

- **No private-mint standing verdict constructor.** Standing does not adopt the `facts -> verdict` choke point. It produces witnesses and compatibility facts, not an official "has standing" predicate.
- **No closed mechanical standing admission.** Standing's refusal stays contextual; it is not reduced to an enum lookup over a fact table.
- **No conversion of pleadable standing into a pure predicate.** If a future change makes standing decidable by a fixed function of stored facts, that is the failure, not the feature.
- **No implementation authorized.** This names a surface; it does not build one.

## The one universal, in Standing's dialect

The cross-office rule every constellation office inherits: **UNKNOWN poisons PASS** — *no office may convert unknown, unavailable, incompatible, or unverified evidence into a clean affirmative result merely because the local path lacks a refusal branch.*

Standing's chalice for that poison:

```text
BasisIncompatible       # observed_at and exercise_at do not share a compatible clock basis — refuse the gap, do not compute it
StandingGapUnwitnessed  # the temporal gap cannot be witnessed — it is not "fine", it is unknown
```

An unwitnessable gap is not a pass with a caveat. It is a typed non-result.

## Doctrine lines

- Standing witnesses the temporal basis of standing; it does not mechanize standing into an unpleadable verdict.
- A gap is a difference between compatible clock witnesses, not numbers.
- Standing gets the measuring stick, not the guillotine.

---

*Candidate. Name early, ratify lazily. No implementation authorized by this record.*
