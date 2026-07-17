use clap::{Parser, Subcommand};
use standing_grant::{
    ActorContext, AssertionGrantRequest, AssertionGrantState, AssertionScope, GrantRequest,
    GrantScope, GrantState, Principal, RequestProof,
};
use standing_identity::{
    CreateOptions, ReplayGuard, VerifyOptions, WorkloadId, verify_and_resolve,
    verify_and_resolve_with_replay,
};
use standing_policy::{
    AssertCheckRequest, DenyAllResolver, EffectClass, HardcodedPolicy, LocalOnlyResolver,
    ResolverMode, StandingRequest, StandingResolver, StaticConfig, StaticConfigResolver,
    check_assert,
};
use standing_store::Store;

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
    /// Assertion-standing preflight, lease lifecycle, proof, and resolution.
    /// Checks are non-authorizing; lease spends can authorize binding effects.
    /// See docs/remote-standing-boundary.md.
    Assert {
        #[command(subcommand)]
        action: AssertAction,
    },
    /// Policy-level freezes (incident mode): deny a grant class without
    /// revoking individual grants. See docs/lifecycle-freeze.md.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Freeze a grant class (deny-overlay). Requires an operator identity.
    Freeze {
        /// Incident handle / freeze id (citable).
        #[arg(long)]
        handle: String,
        /// What to freeze on: claim_kind | action | actor | audience
        #[arg(long, name = "class-type")]
        class_type: String,
        #[arg(long, name = "class-value")]
        class_value: String,
        /// Optionally screen only this audience (a freeze scoped to B does not
        /// screen B').
        #[arg(long)]
        audience: Option<String>,
        #[arg(long)]
        reason: String,
        /// Optional lazy-expiry (RFC 3339). After this the freeze stops
        /// matching — a deny-overlay predicate, not a scheduler; no auto-thaw.
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        secret: String,
    },
    /// Lift a freeze (explicit thaw). Same grant class is authorizable again
    /// with no re-issue.
    Thaw {
        #[arg(long)]
        handle: String,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        secret: String,
    },
    /// List freezes (active by default; `--all` includes thawed).
    ListFreezes {
        #[arg(long)]
        all: bool,
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
    /// Open an assertion lease (entitlement-to-assert, Phase 4b). Requires a
    /// genesis to be installed (the prior settlement-witness). Bind it to a
    /// verified identity; scope it by claim_kind × subject_scope × audience;
    /// bound it by a validity window and a use budget.
    Grant {
        /// Verified identity of the lease actor (the speaker receiving
        /// entitlement-to-assert).
        #[arg(long)]
        identity: String,
        #[arg(long)]
        secret: String,
        /// Verified genesis operator identity authorizing this issuance. Must
        /// match the installed genesis actor and differ from the lease actor.
        #[arg(long, name = "operator-identity")]
        operator_identity: String,
        #[arg(long, name = "operator-secret")]
        operator_secret: String,
        #[arg(long, name = "claim-kind")]
        claim_kind: String,
        /// Coverage pattern (exact or trailing-`/*`), e.g. "labelwatch/*"
        #[arg(long, name = "subject-scope")]
        subject_scope: String,
        #[arg(long)]
        audience: String,
        /// Front of the validity window (RFC 3339). Defaults to now.
        #[arg(long, name = "not-before")]
        not_before: Option<String>,
        /// Lease duration in seconds from not_before.
        #[arg(long, default_value_t = 3600)]
        duration: u64,
        /// Use-count budget (the certified-sound bounded middle, L1).
        #[arg(long, name = "max-uses")]
        max_uses: Option<u64>,
        /// Opt into an UNBOUNDED lease. Not certified sound (kind-scope
        /// laundering surface); the decision surface stamps it as such.
        #[arg(long)]
        unbounded: bool,
    },
    /// Activate a lease (Issued → Active). Optional — the first `prove`
    /// auto-activates.
    Activate {
        #[arg(long)]
        id: String,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        secret: String,
    },
    /// Revoke a lease (terminal).
    Revoke {
        #[arg(long)]
        id: String,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        secret: String,
        /// Act as admin rather than the bound subject.
        #[arg(long)]
        admin: bool,
        #[arg(long)]
        reason: String,
    },
    /// List assertion leases.
    List {
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        audience: Option<String>,
    },
    /// Spend a lease once (the RequestProof per-request path). Records a
    /// single-use jti and emits an AssertionMade receipt.
    Prove {
        #[arg(long)]
        id: String,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        secret: String,
        #[arg(long, name = "claim-kind")]
        claim_kind: String,
        /// Concrete subject id (matched against the lease's subject_scope).
        #[arg(long, name = "subject-id")]
        subject_id: String,
        #[arg(long)]
        audience: String,
        /// Single-use replay nonce (unique per audience).
        #[arg(long)]
        jti: String,
        /// SHA-256 of the request body this assertion attests to.
        #[arg(long, name = "body-digest")]
        body_digest: Option<String>,
        /// Use the MAC-verified path: sign the proof with --secret (the shared
        /// audience key) and verify it, with clock-window enforcement. Without
        /// this, the spend trusts the transport (no per-request MAC).
        #[arg(long)]
        mac: bool,
    },
    /// Resolve a binding preflight against a lease: returns the four-variant
    /// decision (RequiredAndAvailable / RequiredButDenied / ...). `--preview`
    /// is a dry run that authorizes nothing; without it, the spend path runs.
    Resolve {
        #[arg(long)]
        principal: String,
        #[arg(long)]
        consumer: String,
        #[arg(long, name = "claim-kind")]
        claim_kind: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        effect: String,
        /// Lease id to resolve against.
        #[arg(long)]
        id: String,
        #[arg(long)]
        identity: String,
        #[arg(long)]
        secret: String,
        #[arg(long, name = "subject-id")]
        subject_id: String,
        #[arg(long)]
        jti: String,
        #[arg(long, name = "body-digest")]
        body_digest: Option<String>,
        /// Dry run: check availability without recording or authorizing.
        #[arg(long)]
        preview: bool,
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
        /// Optional front of the validity window (RFC 3339). The grant cannot
        /// activate or be used before this time. Defaults to immediate.
        #[arg(long, name = "not-before")]
        not_before: Option<String>,
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
        /// Action being attempted — must match the grant's bound scope
        #[arg(long)]
        action: String,
        /// Target being attempted — must match the grant's bound scope
        #[arg(long)]
        target: String,
        /// Evidence of what was done (JSON string)
        #[arg(long, default_value = "{}")]
        evidence: String,
        /// Emit a standing.grant_use.v1 JSON witness packet to stdout (machine-readable)
        #[arg(long)]
        json: bool,
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
        Commands::Policy { action } => handle_policy(&cli.db, action),
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
            let id =
                standing_identity::create_identity(&name, &location, secret.as_bytes(), &opts)?;
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
            let wid: WorkloadId =
                serde_json::from_str(&data).map_err(|e| format!("malformed identity file: {e}"))?;
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

/// Map a grant-use `StoreError` to a closed `standing.grant_use.v1` `refusal_class`, or
/// `None` for internal/transport-class errors. `None` means "not a typed grant refusal" — the
/// error surfaces as prose so a consumer reads it as *cannot verify*, never as a Standing
/// refusal. Closed set per D010c.
fn grant_use_refusal_class(err: &standing_store::StoreError) -> Option<&'static str> {
    use standing_store::StoreError as E;
    match err {
        E::ScopeMismatch { .. } => Some("scope_mismatch"),
        E::GrantExpired(_) => Some("expired"),
        E::Unauthorized { .. } => Some("subject_mismatch"),
        E::GrantNotFound(_) => Some("not_found"),
        E::InvalidTransition { from, .. } if from.contains("used") => Some("already_spent"),
        _ => None,
    }
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
            not_before,
        } => {
            // Replay guard on grant request: same identity assertion
            // cannot request two grants. Fresh identity per request.
            let (principal, _wid) = resolve_identity(&identity, &secret, Some(&mut replay_guard))?;

            let not_before = match not_before {
                Some(s) => Some(
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .map_err(|e| format!("bad --not-before: {e}"))?
                        .to_utc(),
                ),
                None => None,
            };

            let req = GrantRequest {
                subject: principal.clone(),
                scope: GrantScope {
                    action: action.clone(),
                    target: target.clone(),
                },
                duration_secs: duration,
                not_before,
                context: serde_json::json!({}),
            };

            let policy = HardcodedPolicy;
            let created = store.create_grant(&req, &policy)?;

            match created.state {
                GrantState::Issued => {
                    let expires_at = created
                        .expires_at
                        .expect("an issued grant always has an expiry");
                    println!("granted {}", created.grant_id);
                    println!("  subject: {}", req.subject.id);
                    println!("  expires: {}", expires_at.to_rfc3339());
                    println!("  receipt: {}", created.final_receipt.digest);
                }
                GrantState::Denied => {
                    println!("denied {}", created.grant_id);
                    println!("  reason: {}", created.reason);
                    println!("  receipt: {}", created.final_receipt.digest);
                }
                state => unreachable!("create_grant returned unexpected state {state}"),
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
            action,
            target,
            evidence,
            json,
        } => {
            let (principal, _wid) = resolve_identity(&identity, &secret, None)?;
            let subject_id = principal.id.clone();
            let actor_ctx = ActorContext::subject(principal);
            let evidence: serde_json::Value = serde_json::from_str(&evidence)?;
            let attempted = standing_grant::GrantScope {
                action: action.clone(),
                target: target.clone(),
            };
            // The grant's bound scope (if it exists) for the witness packet.
            let granted = store
                .get_grant(&id)
                .ok()
                .flatten()
                .map(|g| (g.action, g.target));
            let result = store.transition_scoped(
                &id,
                standing_grant::GrantState::Used,
                standing_receipt::ReceiptKind::GrantUsed,
                &actor_ctx,
                evidence,
                None,
                &attempted,
            );

            if json {
                // standing.grant_use.v1 — machine-readable witness packet (D010c).
                let granted_json = granted
                    .as_ref()
                    .map(|(a, t)| serde_json::json!({ "action": a, "target": t }));
                match result {
                    Ok(r) => {
                        let packet = serde_json::json!({
                            "schema": "standing.grant_use.v1",
                            "result": "used",
                            "grant_id": id,
                            "subject": subject_id,
                            "attempted": { "action": action, "target": target },
                            "granted": granted_json,
                            "receipt_digest": r.receipt_digest,
                            "receipt_kind": "grant_used",
                        });
                        println!("{}", serde_json::to_string(&packet)?);
                    }
                    Err(e) => match grant_use_refusal_class(&e) {
                        // A typed grant-domain refusal: emit the refused packet. Asymmetric
                        // custody (D010c) — no transition occurred, so receipt_digest is null.
                        Some(class) => {
                            let packet = serde_json::json!({
                                "schema": "standing.grant_use.v1",
                                "result": "refused",
                                "grant_id": id,
                                "subject": subject_id,
                                "attempted": { "action": action, "target": target },
                                "granted": granted_json,
                                "refusal_class": class,
                                "receipt_digest": serde_json::Value::Null,
                                "receipt_kind": serde_json::Value::Null,
                                "detail": e.to_string(),
                            });
                            println!("{}", serde_json::to_string(&packet)?);
                            std::process::exit(1);
                        }
                        // Not a typed grant refusal (internal/transport-class error): let it
                        // surface as a prose error so a consumer reads it as "cannot verify",
                        // NOT as a Standing refusal.
                        None => return Err(e.into()),
                    },
                }
            } else {
                let r = result?;
                println!("used {id}");
                println!("  receipt: {}", r.receipt_digest);
            }
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
                if (g.state == "issued" || g.state == "active")
                    && let Some(ref exp_str) = g.expires_at
                    && let Ok(exp) = chrono::DateTime::parse_from_rfc3339(exp_str)
                    && now >= exp.to_utc()
                {
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
            if let Some(label) = actor.get("label")
                && label.as_str() != actor.get("principal_id").and_then(|v| v.as_str())
            {
                println!("    label:  {label}");
            }
        }
        if let Some(detail) = ev.get("detail")
            && !detail.is_null()
            && detail != &serde_json::Value::Object(serde_json::Map::new())
        {
            println!("    detail: {detail}");
        }
    }
}

fn handle_resolver(action: ResolverAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        ResolverAction::ListModes => {
            println!("`standing resolver test` supports three resolver implementations:");
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
            println!("Store-backed assertion leases use `standing assert resolve`, not");
            println!("`standing resolver test`.");
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
                    let path =
                        config.ok_or("static_config resolver requires --config <path-to-toml>")?;
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
                if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&r.evidence)
                    && !ev.is_null()
                {
                    // Show structured actor/subject if present
                    if let Some(actor) = ev.get("actor")
                        && let Some(pid) = actor.get("principal_id")
                    {
                        print!("      principal: {pid}");
                        if let Some(role) = actor.get("role") {
                            print!(" (role: {role})");
                        }
                        println!();
                    }
                    if let Some(sid) = ev.get("subject_id") {
                        println!("      subject: {sid}");
                    }
                    // Show detail (the user-provided evidence)
                    if let Some(detail) = ev.get("detail")
                        && !detail.is_null()
                    {
                        println!("      detail: {detail}");
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
                println!();
            }

            // If the chain's first receipt is parented to this instance's
            // genesis, say so — the walk terminates AT the operator-fiat root.
            if let Some(root_parent) = chain.first().and_then(|r| r.parent_digest.as_ref())
                && let Some(g) = store.get_genesis()?
            {
                if &g.digest == root_parent {
                    println!("  ✓ chain cryptographically rooted at genesis {}", g.digest);
                } else {
                    println!("  root parent {root_parent} is not this instance's genesis");
                }
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
                        if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&r.evidence)
                            && let Some(reason) = ev.get("reason")
                        {
                            println!("    reason: {reason}");
                        }
                    }
                    "grant_activated" | "grant_used" | "grant_revoked" | "grant_expired"
                    | "grant_abandoned" => {
                        println!("\n  {}:", r.kind.replace('_', " "));
                        println!("    digest: {}", r.digest);
                        println!("    time:   {}", r.timestamp);
                        print_actor_from_evidence(&r.evidence);
                    }
                    _ => {}
                }
            }

            // Footer the chain at the named genesis root if one exists. Grants
            // created after a genesis is installed are cryptographically
            // parented to it (the first receipt's parent_digest IS the genesis
            // digest); the walk terminates here, citably, not in silence.
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
            println!("  no genesis receipt installed — chain terminates in silence.");
            println!("  run `standing genesis install` to make the operator-fiat root citable.");
        }
    }
    Ok(())
}

fn handle_genesis(db_path: &str, action: GenesisAction) -> Result<(), Box<dyn std::error::Error>> {
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
            println!(
                "  policy:     {}",
                receipt.policy_hash.as_deref().unwrap_or("")
            );
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

            let request =
                AssertCheckRequest::new(&principal, &consumer, &claim_kind, &target, effect)?;

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

        AssertAction::Grant {
            identity,
            secret,
            operator_identity,
            operator_secret,
            claim_kind,
            subject_scope,
            audience,
            not_before,
            duration,
            max_uses,
            unbounded,
        } => {
            // Use budget is mandatory: pick the certified-sound bounded middle
            // (--max-uses) or consciously opt into the unbounded frontier (L1).
            let max_uses = match (max_uses, unbounded) {
                (Some(n), false) => Some(n),
                (None, true) => None,
                (Some(_), true) => {
                    return Err("pass either --max-uses N or --unbounded, not both".into());
                }
                (None, false) => {
                    return Err("assertion leases require a use budget: pass --max-uses N \
                                (certified sound) or --unbounded (opt into the kind-scope \
                                laundering surface, L1)"
                        .into());
                }
            };

            let mut store = Store::open(db_path)?;
            let (principal, _wid) = resolve_identity(&identity, &secret, None)?;
            let (operator, _operator_wid) =
                resolve_identity(&operator_identity, &operator_secret, None)?;
            let not_before = match not_before {
                Some(s) => chrono::DateTime::parse_from_rfc3339(&s)
                    .map_err(|e| format!("bad --not-before: {e}"))?
                    .to_utc(),
                None => chrono::Utc::now(),
            };

            let req = AssertionGrantRequest {
                actor: principal.clone(),
                scope: AssertionScope {
                    claim_kind: claim_kind.clone(),
                    subject_scope: subject_scope.clone(),
                    audience: audience.clone(),
                },
                not_before,
                duration_secs: duration,
                max_uses,
                context: serde_json::json!({}),
            };

            let created = store.create_assertion_lease(&req, &operator)?;
            let grant = &created.grant;
            println!("assertion lease granted {}", created.grant_id);
            println!("  actor: {}", principal.id);
            println!("  authorized by genesis operator: {}", created.operator_id);
            println!(
                "  scope: {}:{} @ {}",
                grant.scope.claim_kind, grant.scope.subject_scope, grant.scope.audience
            );
            println!(
                "  window: {} .. {}",
                grant.not_before.to_rfc3339(),
                grant.expires_at.to_rfc3339()
            );
            match max_uses {
                Some(n) => println!("  budget: {n} uses (bounded — certified sound)"),
                None => println!("  budget: UNBOUNDED (kind-scope; NOT certified sound, L1)"),
            }
            println!("  settlement_witness (genesis): {}", created.genesis_digest);
            println!("  receipt: {}", created.issued_receipt.digest);
            Ok(())
        }

        AssertAction::Activate {
            id,
            identity,
            secret,
        } => {
            let mut store = Store::open(db_path)?;
            let (principal, _wid) = resolve_identity(&identity, &secret, None)?;
            let ctx = ActorContext::subject(principal);
            let r = store.transition_assertion(
                &id,
                AssertionGrantState::Active,
                standing_receipt::ReceiptKind::AssertionGrantActivated,
                &ctx,
                serde_json::json!({}),
                None,
                chrono::Utc::now(),
            )?;
            println!("activated {id}");
            println!("  receipt: {}", r.digest);
            Ok(())
        }

        AssertAction::Revoke {
            id,
            identity,
            secret,
            admin,
            reason,
        } => {
            let mut store = Store::open(db_path)?;
            let (principal, _wid) = resolve_identity(&identity, &secret, None)?;
            let ctx = if admin {
                ActorContext::admin(principal)
            } else {
                ActorContext::subject(principal)
            };
            let r = store.transition_assertion(
                &id,
                AssertionGrantState::Revoked,
                standing_receipt::ReceiptKind::AssertionGrantRevoked,
                &ctx,
                serde_json::json!({ "reason": reason }),
                None,
                chrono::Utc::now(),
            )?;
            println!("revoked {id}");
            println!("  receipt: {}", r.digest);
            Ok(())
        }

        AssertAction::List { state, audience } => {
            let store = Store::open(db_path)?;
            let rows = store.list_assertion_grants(state.as_deref(), audience.as_deref())?;
            let out: Vec<_> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "actor": r.actor,
                        "claim_kind": r.claim_kind,
                        "subject_scope": r.subject_scope,
                        "audience": r.audience,
                        "state": r.state,
                        "not_before": r.not_before,
                        "expires_at": r.expires_at,
                        "max_uses": r.max_uses,
                        "spend_count": r.spend_count,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }

        AssertAction::Prove {
            id,
            identity,
            secret,
            claim_kind,
            subject_id,
            audience,
            jti,
            body_digest,
            mac,
        } => {
            let mut store = Store::open(db_path)?;
            let (principal, _wid) = resolve_identity(&identity, &secret, None)?;
            let grant_id = uuid::Uuid::parse_str(&id).map_err(|e| format!("bad --id: {e}"))?;
            let proof = RequestProof {
                grant_id,
                actor: principal.id,
                claim_kind,
                subject_id,
                audience,
                jti,
                body_digest,
                issued_at: chrono::Utc::now(),
            };
            let now = chrono::Utc::now();
            let result = if mac {
                // Sign with --secret (the shared audience key) and verify.
                let tag = standing_store::sign_proof(&proof, secret.as_bytes())?;
                store.spend_assertion_verified(&proof, Some(&tag), secret.as_bytes(), now)?
            } else {
                store.spend_assertion(&proof, now)?
            };
            if mac {
                println!("asserted (spend #{}, MAC-verified)", result.spend_seq);
            } else {
                println!("asserted (spend #{})", result.spend_seq);
            }
            println!("  receipt: {}", result.receipt_digest);
            if result.exhausted {
                println!("  lease now EXHAUSTED — use budget spent, re-witness required");
            }
            Ok(())
        }

        AssertAction::Resolve {
            principal,
            consumer,
            claim_kind,
            target,
            effect,
            id,
            identity,
            secret,
            subject_id,
            jti,
            body_digest,
            preview,
        } => {
            let effect = parse_effect(&effect)?;
            let request =
                AssertCheckRequest::new(&principal, &consumer, &claim_kind, &target, effect)?;
            let mut store = Store::open(db_path)?;
            let (verified, _wid) = resolve_identity(&identity, &secret, None)?;
            let grant_id = uuid::Uuid::parse_str(&id).map_err(|e| format!("bad --id: {e}"))?;
            let proof = RequestProof {
                grant_id,
                actor: verified.id,
                claim_kind,
                subject_id,
                audience: consumer,
                jti,
                body_digest,
                issued_at: chrono::Utc::now(),
            };
            let result = if preview {
                store.resolve_assert_preview(&request, &proof, chrono::Utc::now())?
            } else {
                store.resolve_assert_spend(&request, &proof, chrono::Utc::now())?
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}

fn handle_policy(db_path: &str, action: PolicyAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        PolicyAction::Freeze {
            handle,
            class_type,
            class_value,
            audience,
            reason,
            until,
            identity,
            secret,
        } => {
            if !["claim_kind", "action", "actor", "audience"].contains(&class_type.as_str()) {
                return Err(format!(
                    "unknown --class-type {class_type:?} (expected: claim_kind | action | actor | audience)"
                )
                .into());
            }
            let mut store = Store::open(db_path)?;
            let (op, _wid) = resolve_identity(&identity, &secret, None)?;
            let until = match until {
                Some(s) => Some(
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .map_err(|e| format!("bad --until: {e}"))?
                        .to_utc(),
                ),
                None => None,
            };
            let r = store.install_freeze(
                &handle,
                &class_type,
                &class_value,
                audience.as_deref(),
                &reason,
                until,
                &op.id,
                chrono::Utc::now(),
            )?;
            println!("frozen {handle}");
            println!("  class: {class_type}={class_value}");
            if let Some(a) = &audience {
                println!("  audience_scope: {a}");
            }
            println!("  reason: {reason}");
            println!("  receipt: {}", r.digest);
            Ok(())
        }
        PolicyAction::Thaw {
            handle,
            identity,
            secret,
        } => {
            let mut store = Store::open(db_path)?;
            let (op, _wid) = resolve_identity(&identity, &secret, None)?;
            let r = store.thaw_freeze(&handle, &op.id, chrono::Utc::now())?;
            println!("thawed {handle}");
            println!("  receipt: {}", r.digest);
            Ok(())
        }
        PolicyAction::ListFreezes { all } => {
            let store = Store::open(db_path)?;
            let rows = store.list_freezes(!all)?;
            let out: Vec<_> = rows
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "handle": f.handle,
                        "class_type": f.class_type,
                        "class_value": f.class_value,
                        "audience_scope": f.audience_scope,
                        "reason": f.reason,
                        "frozen_at": f.frozen_at,
                        "frozen_until": f.frozen_until,
                        "thawed_at": f.thawed_at,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
    }
}

/// Parse an effect-class string into an [`EffectClass`], with a helpful error.
fn parse_effect(effect: &str) -> Result<EffectClass, Box<dyn std::error::Error>> {
    match effect {
        "descriptive" => Ok(EffectClass::Descriptive),
        "advisory" => Ok(EffectClass::Advisory),
        "binding" => Ok(EffectClass::Binding),
        "mutating" => Ok(EffectClass::Mutating),
        other => Err(format!(
            "unknown effect: {other:?} (expected: descriptive | advisory | binding | mutating)"
        )
        .into()),
    }
}
