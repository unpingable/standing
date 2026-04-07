use clap::{Parser, Subcommand};
use standing_grant::{ActorContext, GrantMachine, GrantRequest, GrantScope, Principal};
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
enum GrantAction {
    /// Request a new grant, evaluate policy, and issue/deny it
    Request {
        /// Actor requesting the grant (e.g., "deploy-bot")
        #[arg(long)]
        actor: String,
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
    },
    /// Record use of an active grant
    Use {
        /// Grant ID
        #[arg(long)]
        id: String,
        /// Evidence of what was done (JSON string)
        #[arg(long, default_value = "{}")]
        evidence: String,
    },
    /// Revoke a grant
    Revoke {
        /// Grant ID
        #[arg(long)]
        id: String,
        /// Reason for revocation
        #[arg(long)]
        reason: String,
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
        Commands::Grant { action } => handle_grant(&cli.db, action),
        Commands::Query { action } => handle_query(&cli.db, action),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn handle_grant(db_path: &str, action: GrantAction) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = Store::open(db_path)?;

    match action {
        GrantAction::Request {
            actor,
            action,
            target,
            duration,
        } => {
            // CLI resolves identity at the boundary, passes canonical Principal
            let principal = Principal::new(&actor, &actor);
            let req = GrantRequest {
                subject: principal.clone(),
                scope: GrantScope {
                    action: action.clone(),
                    target: target.clone(),
                },
                duration_secs: duration,
                context: serde_json::json!({}),
            };

            // Step 1: Create the grant request (emits GrantRequested receipt)
            let mut machine = GrantMachine::request(&req)?;
            let grant_id = machine.grant_id();

            // Record the request
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

            // Step 2: Evaluate policy (emits PolicyDecision receipt)
            let policy = HardcodedPolicy;
            let decision = policy.evaluate(&req, &grant_id.to_string(), &requested_receipt.digest)?;

            // Store the policy decision receipt
            store.record_transition(
                grant_id,
                &machine.state,
                &decision.receipt,
                None,
            )?;

            // Step 3: Issue or deny based on policy
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
        GrantAction::Activate { id } => {
            let grant = store.get_grant(&id)?
                .ok_or_else(|| format!("grant not found: {id}"))?;
            let actor_ctx = ActorContext::subject(
                Principal::new(&grant.subject_id, &grant.actor),
            );
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
        GrantAction::Use { id, evidence } => {
            let grant = store.get_grant(&id)?
                .ok_or_else(|| format!("grant not found: {id}"))?;
            let actor_ctx = ActorContext::subject(
                Principal::new(&grant.subject_id, &grant.actor),
            );
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
        GrantAction::Revoke { id, reason } => {
            let grant = store.get_grant(&id)?
                .ok_or_else(|| format!("grant not found: {id}"))?;
            // For CLI revoke, treat as admin action (proper auth would
            // come from identity resolution at the boundary)
            let actor_ctx = ActorContext::admin(
                Principal::new(&grant.subject_id, &grant.actor),
            );
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
        GrantAction::List { state } => {
            let grants = store.list_grants(state.as_deref())?;
            if grants.is_empty() {
                println!("no grants found");
                return Ok(());
            }
            for g in &grants {
                println!(
                    "{} {} {} → {} [{}]",
                    g.id, g.actor, g.action, g.target, g.state
                );
                if let Some(ref exp) = g.expires_at {
                    println!("  expires: {exp}");
                }
            }
        }
    }

    Ok(())
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
            println!("receipt chain for {id} ({} receipts):", chain.len());
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
                // Parse and pretty-print evidence
                if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&r.evidence) {
                    if !ev.is_null() {
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
        }
        QueryAction::Why { id } => {
            let chain = store.receipt_chain(&id)?;
            if chain.is_empty() {
                println!("no receipts for grant {id}");
                return Ok(());
            }

            // Find the policy decision and the grant issued/denied receipts
            println!("why was grant {id} allowed/denied?\n");
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
                        println!("    time: {}", r.timestamp);
                    }
                    "grant_denied" => {
                        println!("\n  grant denied:");
                        println!("    digest: {}", r.digest);
                        println!("    time: {}", r.timestamp);
                        if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&r.evidence) {
                            if let Some(reason) = ev.get("reason") {
                                println!("    reason: {reason}");
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
