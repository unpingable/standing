# Provenance

This project is human-directed and AI-assisted. Final design authority,
acceptance criteria, and editorial control rest with the human author.
AI contributions were material and are categorized below by function.

## Human authorship

The author defined the project direction, requirements, and design intent.
AI systems contributed proposals, drafts, implementation, and critique under
author supervision; they did not independently determine project goals or
deployment decisions. The author reviewed, revised, or rejected AI-generated
output throughout development.

## AI-assisted collaboration

### Architectural design and constraint model

Lead collaboration: ChatGPT (OpenAI). Design documents (DESIGN.md,
GOVERNOR-CROSSWALK.md, NOTES-interruption.md), constitutional architecture,
failure mode taxonomy, receipt/custody pattern crosswalk from Governor,
and scope boundary definition.

### Implementation, tests, and integration

Lead collaboration: Claude (Anthropic) via Claude Code. Full implementation
of the Rust workspace: receipt kernel, grant lifecycle state machine, policy
engine, workload identity, SQLite storage, and CLI driver. All test suites,
build configuration, and end-to-end wiring.

## Provenance basis and limits

This document is a functional attribution record based on commit history,
co-author trailers (where present), project notes, and documented working
sessions. It is not a complete forensic account of all contributions.

Some AI contributions (especially design critique, rejected alternatives,
and footguns avoided) may not appear in repository artifacts or commit
metadata.

Model names/tools are recorded at the platform level (e.g., ChatGPT,
Claude Code); exact model versions may vary across sessions and are not
exhaustively reconstructed here.

## What this document does not claim

- No exact proportional attribution. Contributions are categorized by
  function, not quantified by token count or lines of code.
- Design and implementation were not cleanly sequential. Architecture
  informed code, code revealed design gaps, and the feedback loop was
  continuous.
- "Footguns avoided" and "ideas that didn't ship" are real contributions
  that leave no artifact. This document cannot fully account for them.

---

This document reflects the project state as of 2026-04-03 and may be revised.
