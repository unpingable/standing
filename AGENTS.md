# AGENTS.md — Working in this repo

This file is a **travel guide**, not a law.
If anything here conflicts with the user's explicit instructions, the user wins.

> Instruction files shape behavior; the user determines direction.

---

## Quick start

```bash
cargo build
cargo test
cargo run -p standing-cli -- grant request --actor deploy-bot --action deploy --target prod/web-api
```

## Tests

```bash
cargo test
```

Always run tests before proposing commits. Never claim tests pass without running them.

---

## Safety and irreversibility

### Do not do these without explicit user confirmation
- Push to remote, create/close PRs or issues
- Delete or rewrite git history
- Modify dependency files in ways that change the lock file
- Changing receipt format (WLP compatibility constraint)
- Changing fail-closed receipt semantics

### Preferred workflow
- Make changes in small, reviewable steps
- Run tests locally before proposing commits
- For any operation that affects external state, require explicit user confirmation

---

## Repository layout

```
crates/
  standing-receipt/   Receipt kernel (content-addressed, canonical JSON + SHA-256)
  standing-grant/     Grant lifecycle state machine
  standing-policy/    Policy evaluator (trait + hardcoded impl)
  standing-identity/  HMAC-signed workload identity
  standing-store/     SQLite storage, atomic transitions, query surface
  standing-cli/       CLI binary ("standing")
DESIGN.md             Architecture and design intent
GOVERNOR-CROSSWALK.md Correspondence with Governor concepts
NOTES-interruption.md Interruption as first-class state
```

---

## Coding conventions

- Rust 2024 edition
- Tests as `#[cfg(test)]` modules in each crate
- One crate per concern; dependencies flow inward (cli → store → grant → receipt)

---

## Invariants

1. Every grant state transition produces a content-addressed receipt
2. Receipt write failure aborts the state transition (fail-closed)
3. Receipt format: canonical JSON + SHA-256 (WLP-compatible)
4. Interruption states (abandoned, lease_expired) are first-class, not edge cases

---

## What this is not

- Not health observability (NQ does that)
- Not agent governance (Governor does that)
- Not a secret store, service mesh, or PKI project

---

## When you're unsure

Ask for clarification rather than guessing, especially around:
- Whether a change affects receipt format (WLP compatibility)
- Whether a new grant state should be terminal or non-terminal
- Anything that changes fail-closed receipt semantics

---

## Agent-specific instruction files

| Agent | File | Role |
|-------|------|------|
| Claude Code | `CLAUDE.md` | Full operational context, build details, conventions |
| Codex | `AGENTS.md` (this file) | Operating context + defaults |
| Any future agent | `AGENTS.md` (this file) | Start here |
