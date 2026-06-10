use clap::{Parser, Subcommand};
use standing_grant::{ActorContext, GrantMachine, GrantRequest, GrantScope, Principal};
use standing_identity::{WorkloadId, verify_and_resolve, verify_and_resolve_with_replay, CreateOptions, ReplayGuard, VerifyOptions};
use standing_policy::{
    check_assert, AssertCheckRequest, DenyAllResolver, EffectClass, HardcodedPolicy,
    LocalOnlyResolver, PolicyEvaluator, ResolverMode, StandingRequest, StandingResolver,
    StaticConfig, StaticConfigResolver, Verdict,
};
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
    /// Remote-boundary standing resolver (entitlement-to-assert).
    /// See docs/remote-standing-boundary.md.
    Resolver {
        #[command(subcommand)]
        action: ResolverAction,
    },
    /// Genesis: name the operator-fiat root of this Standing instance.
    /// See docs/genesis-receipt.md.
    Genesis {
        #[command(subcommand)]
        action: GenesisAction,
    },
    /// Assertion-standing preflight surface (Phase 4a — door, not room).
    /// Consumers ask "do I need assert-standing for this effect?" and get
    /// a structured answer. Does not authorize. See docs/remote-standing-boundary.md.
    Assert {
        #[command(subcommand)]
        action: AssertAction,
    },
}

#[derive(Subcommand)]
enum AssertAction {
    /// Preflight check: would this operation require assert-standing,
    /// and if so, can Standing supply it? Pure inquiry; no state change.
    Check {
        /// Canonical principal id of the asking actor
        #[arg(long)]
        principal: String,
        /// Instance-qualified consumer name (e.g. "nq:linode")
        #[arg(long)]
        consumer: String,
        /// Claim kind being asserted (e.g. "sqlite_wal_state")
        #[arg(long, name = "claim-kind")]
        claim_kind: String,
        /// Resource the claim is about
        #[arg(long)]
        target: String,
        /// Effect class: descriptive | advisory | binding | mutating
        #[arg(long)]
        effect: String,
    },
}

#[derive(Subcommand)]
enum GenesisAction {
    /// Install the genesis receipt #0. Exactly one per instance; a second
    /// install is refused. Records operator (from verified identity),
    /// policy source + hash, and the explicit-fiat basis.
    Install {
        /// Path to signed identity JSON file (operator identity)
        #[arg(long)]
        identity: String,
        /// Shared secret for identity verification
        #[arg(long)]
        secret: String,
        /// Policy source marker. For HardcodedPolicy, leave as the default.
        /// For external policy artifacts, a path / URL / canonical identifier.
        #[arg(long, name = "policy-source", default_value = "hardcoded:v1")]
        policy_source: String,
    },
    /// Show this instance's genesis receipt, if one has been installed.
    Show,
}

#[derive(Subcommand)]
enum ResolverAction {
    /// Evaluate a StandingRequest against a resolver and print the
    /// StandingDecision as canonical JSON.
    Test {
        /// Resolver to evaluate against: deny_all, local_only, static_config
        #[arg(long, default_value = "static_config")]
        resolver: String,
        /// Path to TOML config (required for static_config)
        #[arg(long)]
        config: Option<String>,
        /// Canonical principal id of the calling actor (e.g.
        /// "component:nq:linode", "human:jbeck", "workload:bot:host-a")
        #[arg(long)]
        actor: String,
        /// Claim kind being asserted (e.g. "sqlite_wal_state")
        #[arg(long, name = "claim-kind")]
        claim_kind: String,
        /// Subject scope (e.g. "labelwatch/foo", "host:storage01")
        #[arg(long, name = "subject-scope")]
        subject_scope: String,
        /// Instance-qualified audience (e.g. "nq:main")
        #[arg(long)]
        audience: String,
        /// Resolver mode: visible_not_binding (default) | binding
        #[arg(long, default_value = "visible_not_binding")]
        mode: String,
    },
    /// List the resolver modes Standing ships with.
    ListModes,
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
        Commands::Resolver { action } => handle_resolver(action),
        Commands::Genesis { action } => handle_genesis(&cli.db, action),
        Commands::Assert { action } => handle_assert(&cli.db, action),
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
    replay_guard: Option<&mut dyn ReplayGuard>,
) -> Result<(Principal, WorkloadId), Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(identity_path)
        .map_err(|e| format!("cannot read identity file {identity_path}: {e}"))?;
    let wid: WorkloadId = serde_json::from_str(&data)
        .map_err(|e| format!("malformed identity file {identity_path}: {e}"))?;
    let opts = VerifyOptions::default();
    let verified = verify_and_resolve_with_replay(&wid, secret.as_bytes(), &opts, replay_guard)
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
                ..CreateOptions::default()
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
    let mut replay_guard = store.replay_guard()?;

    match action {
        GrantAction::Request {
            identity,
            secret,
            action,
            target,
            duration,
        } => {
            // Replay guard on grant request: same identity assertion
            // cannot request two grants. Fresh identity per request.
            let (principal, _wid) = resolve_identity(&identity, &secret, Some(&mut replay_guard))?;

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
            let (principal, _wid) = resolve_identity(&identity, &secret, None)?;
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
            let (principal, _wid) = resolve_identity(&identity, &secret, None)?;
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
            let (principal, _wid) = resolve_identity(&identity, &secret, None)?;
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

fn handle_resolver(action: ResolverAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ResolverAction::ListModes => {
            // Mirror docs/remote-standing-boundary.md § "The four resolver modes".
            println!("Standing ships four resolver modes (StandingResolver implementations):");
            println!();
            println!("  deny_all       refuses every request; panic-button / test scaffold");
            println!("                 (consumer-facing name: DenyAllResolver)");
            println!();
            println!("  local_only     refuses any non-local actor; default for the");
            println!("                 `private_local` exposure profile");
            println!("                 (consumer-facing name: AllowLocalOnlyResolver)");
            println!();
            println!("  static_config  static (actor, claim_kind, subject_scope, audience)");
            println!("                 allowlist from TOML; the MVP-enabling resolver");
            println!("                 (consumer-facing name: StaticConfigResolver)");
            println!();
            println!("  store_grant    (post-MVP) defers to Standing's assertion-grant store;");
            println!("                 real distributed-prod posture with grant lifecycle");
            println!("                 (consumer-facing name: StandingToolResolver)");
        }
        ResolverAction::Test {
            resolver,
            config,
            actor,
            claim_kind,
            subject_scope,
            audience,
            mode,
        } => {
            let mode = match mode.as_str() {
                "binding" => ResolverMode::Binding,
                "visible_not_binding" => ResolverMode::VisibleNotBinding,
                other => {
                    return Err(format!(
                        "unknown mode {other:?}: expected `visible_not_binding` or `binding`"
                    )
                    .into());
                }
            };

            let principal = Principal::new(actor.clone(), actor);
            let request = StandingRequest::new(
                principal,
                claim_kind,
                subject_scope,
                audience,
                chrono::Utc::now(),
            )?;

            let decision = match resolver.as_str() {
                "deny_all" => DenyAllResolver::new(mode).assess(&request)?,
                "local_only" => LocalOnlyResolver::new(mode).assess(&request)?,
                "static_config" => {
                    let path = config.ok_or_else(|| {
                        "static_config resolver requires --config <path-to-toml>"
                    })?;
                    let cfg = StaticConfig::load(std::path::Path::new(&path))?;
                    StaticConfigResolver::new(cfg, mode).assess(&request)?
                }
                other => {
                    return Err(format!(
                        "unknown resolver {other:?}: expected deny_all, local_only, static_config"
                    )
                    .into());
                }
            };

            let json = serde_json::to_string_pretty(&decision)?;
            println!("{json}");
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

            // Footer the chain at the named genesis root if one exists.
            // Grant receipts are not cryptographically parented to genesis in
            // the MVP, but the policy authority every decision under this
            // instance derived from terminates here, citably, not in silence.
            print_genesis_footer(&store)?;
        }
    }

    Ok(())
}

fn print_genesis_footer(store: &Store) -> Result<(), Box<dyn std::error::Error>> {
    match store.get_genesis()? {
        Some(g) => {
            println!("\n  ── chain root ──");
            println!("  genesis install (operator fiat):");
            println!("    digest:   {}", g.digest);
            println!("    operator: {}", g.actor);
            println!("    instance: {}", g.subject);
            println!("    time:     {}", g.timestamp);
            if let Some(ref ph) = g.policy_hash {
                println!("    policy:   {ph}");
            }
            if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&g.evidence) {
                if let Some(src) = ev.get("policy_source") {
                    println!("    source:   {src}");
                }
                if let Some(basis) = ev.get("basis") {
                    println!("    basis:    {basis}");
                }
            }
        }
        None => {
            println!("\n  ── chain root ──");
            println!(
                "  no genesis receipt installed — chain terminates in silence."
            );
            println!(
                "  run `standing genesis install` to make the operator-fiat root citable."
            );
        }
    }
    Ok(())
}

fn handle_genesis(
    db_path: &str,
    action: GenesisAction,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        GenesisAction::Install {
            identity,
            secret,
            policy_source,
        } => {
            let (principal, _wlid) = resolve_identity(&identity, &secret, None)?;

            let mut store = Store::open(db_path)?;
            let receipt = store.install_genesis(&principal.id, &policy_source)?;

            let evidence: serde_json::Value =
                serde_json::from_value(receipt.evidence.clone()).unwrap_or(serde_json::Value::Null);
            let instance_id = evidence
                .get("instance_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            println!("genesis installed.");
            println!("  digest:     {}", receipt.digest);
            println!("  operator:   {}", receipt.actor);
            println!("  instance:   {instance_id}");
            println!("  policy:     {}", receipt.policy_hash.as_deref().unwrap_or(""));
            println!("  source:     {policy_source}");
            println!("  basis:      operator_fiat");
            println!("  time:       {}", receipt.timestamp);
            Ok(())
        }
        GenesisAction::Show => {
            let store = Store::open(db_path)?;
            match store.get_genesis()? {
                Some(g) => {
                    let evidence: serde_json::Value =
                        serde_json::from_str(&g.evidence).unwrap_or(serde_json::Value::Null);
                    let out = serde_json::json!({
                        "digest": g.digest,
                        "id": g.id,
                        "kind": g.kind,
                        "timestamp": g.timestamp,
                        "operator": g.actor,
                        "instance_id": g.subject,
                        "policy_hash": g.policy_hash,
                        "evidence": evidence,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                    Ok(())
                }
                None => {
                    println!(
                        "no genesis receipt installed for this instance — \
                         run `standing genesis install` to establish one."
                    );
                    Ok(())
                }
            }
        }
    }
}

fn handle_assert(db_path: &str, action: AssertAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        AssertAction::Check {
            principal,
            consumer,
            claim_kind,
            target,
            effect,
        } => {
            let effect = match effect.as_str() {
                "descriptive" => EffectClass::Descriptive,
                "advisory" => EffectClass::Advisory,
                "binding" => EffectClass::Binding,
                "mutating" => EffectClass::Mutating,
                other => {
                    return Err(format!(
                        "unknown effect: {other:?} (expected: descriptive | advisory | binding | mutating)"
                    )
                    .into());
                }
            };

            let request = AssertCheckRequest::new(
                &principal,
                &consumer,
                &claim_kind,
                &target,
                effect,
            )?;

            // Pull genesis + policy citation from the store so the answer
            // is grounded in the instance's actual authority context.
            let store = Store::open(db_path)?;
            let genesis = store.get_genesis()?;
            let genesis_digest = genesis.as_ref().map(|g| g.digest.as_str());
            let policy_hash = genesis.as_ref().and_then(|g| g.policy_hash.as_deref());

            let result = check_assert(&request, genesis_digest, policy_hash);
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}
