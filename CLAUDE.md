# CLAUDE.md — Instructions for Claude Code

## What This Is

standing: Observable standing/entitlement for automation and workloads.

Core question: "Was this actor entitled to do that, under what grant, with what provenance, and what receipts attach consequence to authority?"

## What This Is Not

- Not health observability (that's NQ)
- Not agent governance (that's Governor)
- Not a secret store, service mesh, workforce IAM, or PKI project

## Invariants

1. **Fail-closed on receipts.** No receipt, no standing. If a receipt write fails, the state transition must roll back.
2. **Every grant state transition produces a receipt.** No silent transitions.
3. **Receipts are content-addressed.** Canonical JSON (RFC 8785 / JCS) + SHA-256. Immutable once created.
4. **Interruption is first-class.** Grant states include abandoned and lease_expired — not just success/failure.

## Quick Start

```bash
cargo build
cargo test
# Create a verified identity
standing identity create --name deploy-bot --location host-abc --secret my-key > bot.id.json
# End-to-end: request → activate → use → query
standing grant request --identity bot.id.json --secret my-key --action deploy --target prod/web-api --duration 300
standing grant activate --id <grant-id> --identity bot.id.json --secret my-key
standing grant use --id <grant-id> --identity bot.id.json --secret my-key --evidence '{"deployed":"v1.2.3"}'
standing query why --id <grant-id>
standing query chain --id <grant-id>
# Sweep expired grants
standing grant sweep --dry-run
standing grant sweep
```

## Project Structure

- `crates/standing-receipt/` — Receipt kernel: content-addressed receipts, chains, canonical JSON
- `crates/standing-grant/` — Grant lifecycle state machine, Principal/ActorContext, auth matrix
- `crates/standing-policy/` — Policy evaluator trait + hardcoded policy (slice 1)
- `crates/standing-identity/` — HMAC-signed workload identity, verification, principal resolution
- `crates/standing-store/` — SQLite storage with atomic receipt+state transitions
- `crates/standing-cli/` — CLI driver (`standing` binary)

## Conventions

- License: Apache-2.0
- Rust 2024 edition
- Tests live in each crate as `#[cfg(test)]` modules
- Entry point: `cargo run -p standing-cli -- <args>`
- Receipt format is WLP-compatible (canonical JSON, SHA-256, no signatures yet)

## Debugging Discipline

Shared doctrine across the constellation (annotated source: `agent_gov/CLAUDE.md`):

- **Default to reduction.** Escalate to integration only after reduction has failed to discriminate.
- **Belief must be earned by the cheapest available falsification, not constructed by accretion.**

**In this project**, "load-bearing" means the moment a grant is about to activate, an identity claim is about to be accepted, or a receipt is about to be emitted that downstream systems will rely on. The cheapest discriminating test is usually: re-verify the HMAC and re-read the current grant state from the store, not from the in-memory copy. The fail-closed-on-receipts invariant is the static version; this is its dynamic version.

## Don't

- Don't collapse into agent governance or health monitoring
- Don't let identity become the project (distinguish known from unknown is enough)
- Don't upgrade HMAC identity to full PKI without real need
- Don't build a policy cathedral — hardcoded policy is fine until it isn't
- Don't let CLI do identity resolution beyond the boundary — store receives canonical ActorContext
