# standing

Observable standing/entitlement for automation and workloads.

Modern systems are good at proving possession of credentials. They are much worse at proving entitlement to consequence.

Credential validity is not claim validity. Access to a boundary does not imply standing to perform a consequential action, or to make an assertion that downstream systems may treat as binding.

Standing records and exposes scoped entitlement at a boundary: who had standing, for what action, over what target, within what scope and time window, under what policy, and with what receipt chain.

Kerberos made service access presentable. Standing makes consequence entitlement observable.

Standing does not implement Kerberos-style ticket transport. Grants are recorded and verified against authoritative state rather than carried by workloads or agents as self-justifying legitimacy.

Current Standing models **entitlement-to-act**: whether an actor may perform an operation against a target. Agentic systems also expose a neighboring need, **entitlement-to-assert**, where the relevant object is a claim that may affect downstream consequence. That surface is roadmap only; its schema and receipt format are not yet designed.

## What it does

- Tracks grant lifecycles: request, issue/deny, activate, use, expire, revoke, abandon
- Produces content-addressed receipts at every state transition
- Answers "why was this allowed?" by walking receipt chains
- Evaluates policy decisions with pinned policy hashes
- Stores everything in SQLite with fail-closed atomic transitions

## What this is not

- Not an identity provider, policy engine, admissibility governor, actuator, workflow engine, or agent platform
- Not claim preflight or witness/testimony infrastructure; adjacent systems such as [NQ](https://github.com/jbeck/nq) answer what can be said from evidence
- Not an admissibility lock; an admissibility layer such as Wicket or a consuming [Governor](https://github.com/jbeck/agent_gov) decides whether entitlement may bind consequence
- Not a secret store, service mesh, workforce IAM, or PKI project

Standing may verify principals or workload identity at grant boundaries, but it does not issue identities. Identity is substrate.

## Conceptual stack

```text
Identity substrate      who/what is acting
Access authorization    may it reach the service or boundary
Standing                does it have scoped entitlement here
Admissibility layer     may this bind consequence
Continuity/afterlife    what remains live, stale, watched, or constrained later
```

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
