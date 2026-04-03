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
# End-to-end: request → activate → use → query
standing grant request --actor deploy-bot --action deploy --target prod/web-api --duration 300
standing grant activate --id <grant-id>
standing grant use --id <grant-id> --evidence '{"deployed":"v1.2.3"}'
standing query why --id <grant-id>
standing query chain --id <grant-id>
```

## Project Structure

- `crates/standing-receipt/` — Receipt kernel: content-addressed receipts, chains, canonical JSON
- `crates/standing-grant/` — Grant lifecycle state machine with receipts at every transition
- `crates/standing-policy/` — Policy evaluator trait + hardcoded policy (slice 1)
- `crates/standing-identity/` — HMAC-signed workload identity (minimal)
- `crates/standing-store/` — SQLite storage with atomic receipt+state transitions
- `crates/standing-cli/` — CLI driver (`standing` binary)

## Conventions

- License: Apache-2.0
- Rust 2024 edition
- Tests live in each crate as `#[cfg(test)]` modules
- Entry point: `cargo run -p standing-cli -- <args>`
- Receipt format is WLP-compatible (canonical JSON, SHA-256, no signatures yet)

## Don't

- Don't collapse into agent governance or health monitoring
- Don't let identity become the project (distinguish known from unknown is enough)
- Don't add signatures before the receipt format is proven
- Don't build a policy cathedral — hardcoded policy is fine until it isn't
