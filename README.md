# standing

Observable standing/entitlement for automation and workloads.

Modern infra is good at telling you whether a service is alive and much worse at telling you whether it was entitled to do what it just did.

## What it does

- Tracks grant lifecycles: request, issue/deny, activate, use, expire, revoke, abandon
- Produces content-addressed receipts at every state transition
- Answers "why was this allowed?" by walking receipt chains
- Evaluates policy decisions with pinned policy hashes
- Stores everything in SQLite with fail-closed atomic transitions

## What this is not

- Not health observability (see [NQ](https://github.com/jbeck/nq))
- Not agent governance (see [Governor](https://github.com/jbeck/agent_gov))
- Not a secret store, service mesh, workforce IAM, or PKI project

## Quick start

```bash
cargo build
cargo test

# Create a verified workload identity
standing identity create --name deploy-bot --location host-abc --secret my-key > bot.id.json

# Request a grant (identity verified, policy evaluates, issues or denies)
standing grant request --identity bot.id.json --secret my-key \
  --action deploy --target prod/web-api --duration 300

# Activate and use it (identity verified at each step)
standing grant activate --id <grant-id> --identity bot.id.json --secret my-key
standing grant use --id <grant-id> --identity bot.id.json --secret my-key \
  --evidence '{"deployed":"v1.2.3"}'

# Query: why was this allowed?
standing query why --id <grant-id>

# Query: full receipt chain
standing query chain --id <grant-id>

# Sweep expired grants (system actor)
standing grant sweep
```

## Architecture

```
deploy-bot ──request──> [policy engine] ──decision receipt──> [grant issuer]
                                                                    |
                                                              issue / deny
                                                                    |
                                                              ┌─────v─────┐
                                                              │  SQLite   │
                                                              │ receipts  │
                                                              │  grants   │
                                                              └─────┬─────┘
                                                                    |
                                                         standing query why
```

Receipt format: canonical JSON (RFC 8785 / JCS) + SHA-256. WLP-compatible.

## License

Licensed under Apache-2.0.
