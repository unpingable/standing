use clap::{Parser, Subcommand};
use standing_grant::{ActorContext, GrantMachine, GrantRequest, GrantScope, Principal};
use standing_identity::{WorkloadId, verify_and_resolve, CreateOptions, VerifyOptions};
use standing_policy::{HardcodedPolicy, PolicyEvaluator, Verdict};
use standing_store::{GrantMeta, Store};

#[derive(Parser)]
#[command(name = "standing", about = "Standing/entitlement observability")]
struct Cli {
    /// Path to the SQLite database
    #[arg(long, default_value = "standing.db")]
    db: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create and manage workload identities
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Request, use, and manage grants
    Grant {
        #[command(subcommand)]
        action: GrantAction,
    },
    /// Query standing: why was something allowed/denied?
    Query {
        #[command(subcommand)]
        action: QueryAction,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Create a signed workload identity (writes JSON to stdout)
    Create {
        /// Workload name (e.g., "deploy-bot")
        #[arg(long)]
        name: String,
        /// Workload location (e.g., "host-abc")
        #[arg(long)]
        location: String,
        /// Shared secret for HMAC signing
        #[arg(long)]
        secret: String,
        /// Audience (default: "standing")
        #[arg(long, default_value = "standing")]
        audience: String,
        /// TTL in seconds (default: 3600)
        #[arg(long, default_value = "3600")]
        ttl: i64,
    },
    /// Verify an existing identity file
    Verify {
        /// Path to identity JSON file
        #[arg(long)]
        identity: String,
        /// Shared secret for HMAC verification
        #[arg(long)]
        secret: String,
        /// Expected audience (default: "standing")
        #[arg(long, default_value = "standing")]
        audience: String,
    },
}

#[derive(Subcommand)]
enum GrantAction {
    /// Request a new grant, evaluate policy, and issue/deny it
    Request {
        /// Path to signed identity JSON file
        #[arg(long)]
        identity: String,
        /// Shared secret for identity verification
        #[arg(long)]
        secret: String,
        /// Action to perform (e.g., "deploy")
        #[arg(long)]
        action: String,
        /// Target of the action (e.g., "prod/web-api")
        #[arg(long)]
        target: String,
        /// Duration in seconds
        #[arg(long, default_value = "300")]
        duration: u64,
    },
    /// Activate an issued grant
    Activate {
        /// Grant ID
        #[arg(long)]
        id: String,
        /// Path to signed identity JSON file
        #[arg(long)]
        identity: String,
        /// Shared secret for identity verification
        #[arg(long)]
        secret: String,
    },
    /// Record use of an active grant
    Use {
        /// Grant ID
        #[arg(long)]
        id: String,
        /// Path to signed identity JSON file
        #[arg(long)]
        identity: String,
        /// Shared secret for identity verification
        #[arg(long)]
        secret: String,
        /// Evidence of what was done (JSON string)
        #[arg(long, default_value = "{}")]
        evidence: String,
    },
    /// Revoke a grant (subject self-revoke or admin revoke)
    Revoke {
        /// Grant ID
        #[arg(long)]
        id: String,
        /// Path to signed identity JSON file
        #[arg(long)]
        identity: String,
        /// Shared secret for identity verification
        #[arg(long)]
        secret: String,
        /// Revoke as admin (default: revoke as subject)
        #[arg(long, default_value = "false")]
        admin: bool,
        /// Reason for revocation
        #[arg(long)]
        reason: String,
    },
    /// Sweep expired grants (system actor)
    Sweep {
        /// Dry run: show what would be expired without doing it
        #[arg(long)]
        dry_run: bool,
    },
    /// List grants
    List {
        /// Filter by state
        #[arg(long)]
        state: Option<String>,
    },
}

#[derive(Subcommand)]
enum QueryAction {
    /// Show the receipt chain for a grant
    Chain {
        /// Grant ID
        #[arg(long)]
        id: String,
    },
    /// Why was this grant allowed or denied?
    Why {
        /// Grant ID
        #[arg(long)]
        id: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Identity { action } => handle_identity(action),
        Commands::Grant { action } => handle_grant(&cli.db, action),
        Commands::Query { action } => handle_query(&cli.db, action),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Load and verify a workload identity from a JSON file.
/// Fail-closed: any error is fatal.
fn resolve_identity(
    identity_path: &str,
    secret: &str,
) -> Result<(Principal, WorkloadId), Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(identity_path)
        .map_err(|e| format!("cannot read identity file {identity_path}: {e}"))?;
    let wid: WorkloadId = serde_json::from_str(&data)
        .map_err(|e| format!("malformed identity file {identity_path}: {e}"))?;
    let opts = VerifyOptions::default();
    let verified = verify_and_resolve(&wid, secret.as_bytes(), &opts)
        .map_err(|e| format!("identity verification failed: {e}"))?;
    let principal = Principal::new(verified.principal_id, verified.label);
    Ok((principal, wid))
}

fn handle_identity(action: IdentityAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        IdentityAction::Create {
            name,
            location,
            secret,
            audience,
            ttl,
        } => {
            let opts = CreateOptions {
                ttl_secs: ttl,
                audience,
            };
            let id = standing_identity::create_identity(&name, &location, secret.as_bytes(), &opts)?;
            let json = serde_json::to_string_pretty(&id)?;
            println!("{json}");
        }
        IdentityAction::Verify {
            identity,
            secret,
            audience,
        } => {
            let data = std::fs::read_to_string(&identity)
                .map_err(|e| format!("cannot read identity file: {e}"))?;
            let wid: WorkloadId = serde_json::from_str(&data)
                .map_err(|e| format!("malformed identity file: {e}"))?;
            let opts = VerifyOptions {
                expected_audience: audience,
                ..VerifyOptions::default()
            };
            let verified = verify_and_resolve(&wid, secret.as_bytes(), &opts)
                .map_err(|e| format!("identity verification failed: {e}"))?;
            println!("verified: {}", verified.principal_id);
            println!("  label: {}", verified.label);
            println!("  audience: {}", verified.audience);
            println!("  jti: {}", verified.jti);
            println!("  expires: {}", wid.expires_at.to_rfc3339());
        }
    }
    Ok(())
}

fn handle_grant(db_path: &str, action: GrantAction) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = Store::open(db_path)?;

    match action {
        GrantAction::Request {
            identity,
            secret,
            action,
            target,
            duration,
        } => {
            let (principal, _wid) = resolve_identity(&identity, &secret)?;

            let req = GrantRequest {
                subject: principal.clone(),
                scope: GrantScope {
                    action: action.clone(),
                    target: target.clone(),
                },
                duration_secs: duration,
                context: serde_json::json!({}),
            };

            let mut machine = GrantMachine::request(&req)?;
            let grant_id = machine.grant_id();

            let requested_receipt = machine.chain.tip().clone();
            store.record_transition(
                grant_id,
                &machine.state,
                &requested_receipt,
                Some(GrantMeta {
                    subject_id: principal.id.clone(),
                    actor: principal.label.clone(),
                    action: action.clone(),
                    target: target.clone(),
                    issued_at: None,
                    expires_at: None,
                }),
            )?;

            let policy = HardcodedPolicy;
            let decision =
                policy.evaluate(&req, &grant_id.to_string(), &requested_receipt.digest)?;

            store.record_transition(grant_id, &machine.state, &decision.receipt, None)?;

            match decision.verdict {
                Verdict::Allow => {
                    machine.issue(
                        duration,
                        &decision.policy_hash,
                        serde_json::json!({"verdict": "allow", "reason": decision.reason}),
                    )?;
                    let issue_receipt = machine.chain.tip().clone();
                    let state = machine.state.clone();
                    let grant = machine.grant.as_ref().unwrap();
                    let issued_at = grant.issued_at;
                    let expires_at = grant.expires_at;
                    store.record_transition(
                        grant_id,
                        &state,
                        &issue_receipt,
                        Some(GrantMeta {
                            subject_id: principal.id,
                            actor: principal.label,
                            action,
                            target,
                            issued_at: Some(issued_at),
                            expires_at: Some(expires_at),
                        }),
                    )?;
                    println!("granted {grant_id}");
                    println!("  subject: {}", req.subject.id);
                    println!("  expires: {}", expires_at.to_rfc3339());
                    println!("  receipt: {}", issue_receipt.digest);
                }
                Verdict::Deny => {
                    machine.deny(
                        &decision.policy_hash,
                        serde_json::json!({"verdict": "deny", "reason": decision.reason}),
                    )?;
                    let deny_receipt = machine.chain.tip().clone();
                    let state = machine.state.clone();
                    store.record_transition(grant_id, &state, &deny_receipt, None)?;
                    println!("denied {grant_id}");
                    println!("  reason: {}", decision.reason);
                    println!("  receipt: {}", deny_receipt.digest);
                }
            }
        }
        GrantAction::Activate {
            id,
            identity,
            secret,
        } => {
            let (principal, _wid) = resolve_identity(&identity, &secret)?;
            let actor_ctx = ActorContext::subject(principal);
            let result = store.transition(
                &id,
                standing_grant::GrantState::Active,
                standing_receipt::ReceiptKind::GrantActivated,
                &actor_ctx,
                serde_json::Value::Null,
                None,
            )?;
            println!("activated {id}");
            println!("  receipt: {}", result.receipt_digest);
        }
        GrantAction::Use {
            id,
            identity,
            secret,
            evidence,
        } => {
            let (principal, _wid) = resolve_identity(&identity, &secret)?;
            let actor_ctx = ActorContext::subject(principal);
            let evidence: serde_json::Value = serde_json::from_str(&evidence)?;
            let result = store.transition(
                &id,
                standing_grant::GrantState::Used,
                standing_receipt::ReceiptKind::GrantUsed,
                &actor_ctx,
                evidence,
                None,
            )?;
            println!("used {id}");
            println!("  receipt: {}", result.receipt_digest);
        }
        GrantAction::Revoke {
            id,
            identity,
            secret,
            admin,
            reason,
        } => {
            let (principal, _wid) = resolve_identity(&identity, &secret)?;
            let actor_ctx = if admin {
                ActorContext::admin(principal)
            } else {
                ActorContext::subject(principal)
            };
            let result = store.transition(
                &id,
                standing_grant::GrantState::Revoked,
                standing_receipt::ReceiptKind::GrantRevoked,
                &actor_ctx,
                serde_json::json!({"reason": reason}),
                None,
            )?;
            println!("revoked {id}");
            println!("  reason: {reason}");
            println!("  receipt: {}", result.receipt_digest);
        }
        GrantAction::Sweep { dry_run } => {
            let system_ctx = ActorContext::system();
            let grants = store.list_grants(None)?;
            let now = chrono::Utc::now();
            let mut expired_count = 0;

            for g in &grants {
                // Only sweep non-terminal grants with an expiry in the past
                if g.state == "issued" || g.state == "active" {
                    if let Some(ref exp_str) = g.expires_at {
                        if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(exp_str) {
                            if now >= exp.to_utc() {
                                if dry_run {
                                    println!(
                                        "would expire: {} {} {} → {} (expired {})",
                                        g.id, g.actor, g.action, g.target, exp_str
                                    );
                                } else {
                                    match store.transition(
                                        &g.id,
                                        standing_grant::GrantState::Expired,
                                        standing_receipt::ReceiptKind::GrantExpired,
                                        &system_ctx,
                                        serde_json::json!({"swept_at": now.to_rfc3339()}),
                                        None,
                                    ) {
                                        Ok(r) => {
                                            println!("expired {} (receipt: {})", g.id, r.receipt_digest);
                                        }
                                        Err(e) => {
                                            // CAS conflict or already transitioned — tolerate
                                            eprintln!("skip {}: {e}", g.id);
                                        }
                                    }
                                }
                                expired_count += 1;
                            }
                        }
                    }
                }
            }

            if expired_count == 0 {
                println!("no expired grants found");
            } else if dry_run {
                println!("\n{expired_count} grant(s) would be expired");
            } else {
                println!("\n{expired_count} grant(s) swept");
            }
        }
        GrantAction::List { state } => {
            let grants = store.list_grants(state.as_deref())?;
            if grants.is_empty() {
                println!("no grants found");
                return Ok(());
            }
            for g in &grants {
                println!(
                    "{} [{}] {} {} → {} (subject: {})",
                    g.id, g.state, g.actor, g.action, g.target, g.subject_id
                );
                if let Some(ref exp) = g.expires_at {
                    println!("  expires: {exp}");
                }
            }
        }
    }

    Ok(())
}

fn print_actor_from_evidence(evidence_str: &str) {
    if let Ok(ev) = serde_json::from_str::<serde_json::Value>(evidence_str) {
        if let Some(actor) = ev.get("actor") {
            if let Some(pid) = actor.get("principal_id") {
                print!("    actor:  {pid}");
                if let Some(role) = actor.get("role") {
                    print!(" (role: {role})");
                }
                println!();
            }
            if let Some(label) = actor.get("label") {
                if label.as_str() != actor.get("principal_id").and_then(|v| v.as_str()) {
                    println!("    label:  {label}");
                }
            }
        }
        if let Some(detail) = ev.get("detail") {
            if !detail.is_null() && detail != &serde_json::Value::Object(serde_json::Map::new()) {
                println!("    detail: {detail}");
            }
        }
    }
}

fn handle_query(db_path: &str, action: QueryAction) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(db_path)?;

    match action {
        QueryAction::Chain { id } => {
            let chain = store.receipt_chain(&id)?;
            if chain.is_empty() {
                println!("no receipts for grant {id}");
                return Ok(());
            }
            println!("receipt chain for {id} ({} receipts):\n", chain.len());
            for (i, r) in chain.iter().enumerate() {
                println!("  [{i}] {} {}", r.kind, r.digest);
                println!("      actor: {}", r.actor);
                println!("      time:  {}", r.timestamp);
                if let Some(ref parent) = r.parent_digest {
                    println!("      parent: {parent}");
                }
                if let Some(ref ph) = r.policy_hash {
                    println!("      policy: {ph}");
                }
                if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&r.evidence) {
                    if !ev.is_null() {
                        // Show structured actor/subject if present
                        if let Some(actor) = ev.get("actor") {
                            if let Some(pid) = actor.get("principal_id") {
                                print!("      principal: {pid}");
                                if let Some(role) = actor.get("role") {
                                    print!(" (role: {role})");
                                }
                                println!();
                            }
                        }
                        if let Some(sid) = ev.get("subject_id") {
                            println!("      subject: {sid}");
                        }
                        // Show detail (the user-provided evidence)
                        if let Some(detail) = ev.get("detail") {
                            if !detail.is_null() {
                                println!("      detail: {detail}");
                            }
                        }
                        // For receipts without the actor/subject structure, show raw
                        if ev.get("actor").is_none() {
                            println!(
                                "      evidence: {}",
                                serde_json::to_string_pretty(&ev)?
                                    .lines()
                                    .collect::<Vec<_>>()
                                    .join("\n               ")
                            );
                        }
                    }
                }
                println!();
            }
        }
        QueryAction::Why { id } => {
            let grant = store.get_grant(&id)?;
            let chain = store.receipt_chain(&id)?;
            if chain.is_empty() {
                println!("no receipts for grant {id}");
                return Ok(());
            }

            println!("why was grant {id} allowed/denied?\n");

            // Show grant identity binding
            if let Some(ref g) = grant {
                println!("  subject: {} ({})", g.subject_id, g.actor);
                println!("  scope:   {} → {}", g.action, g.target);
                println!("  state:   {}", g.state);
                if let Some(ref exp) = g.expires_at {
                    println!("  expires: {exp}");
                }
                println!();
            }

            for r in &chain {
                match r.kind.as_str() {
                    "policy_decision" => {
                        println!("  policy decision:");
                        println!("    digest: {}", r.digest);
                        if let Some(ref ph) = r.policy_hash {
                            println!("    policy: {ph}");
                        }
                        if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&r.evidence) {
                            if let Some(verdict) = ev.get("verdict") {
                                println!("    verdict: {verdict}");
                            }
                            if let Some(reason) = ev.get("reason") {
                                println!("    reason: {reason}");
                            }
                        }
                    }
                    "grant_issued" => {
                        println!("\n  grant issued:");
                        println!("    digest: {}", r.digest);
                        println!("    time:   {}", r.timestamp);
                        print_actor_from_evidence(&r.evidence);
                    }
                    "grant_denied" => {
                        println!("\n  grant denied:");
                        println!("    digest: {}", r.digest);
                        println!("    time:   {}", r.timestamp);
                        if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&r.evidence) {
                            if let Some(reason) = ev.get("reason") {
                                println!("    reason: {reason}");
                            }
                        }
                    }
                    "grant_activated" | "grant_used" | "grant_revoked" | "grant_expired" | "grant_abandoned" => {
                        println!("\n  {}:", r.kind.replace('_', " "));
                        println!("    digest: {}", r.digest);
                        println!("    time:   {}", r.timestamp);
                        print_actor_from_evidence(&r.evidence);
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
