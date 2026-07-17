//! Integration tests: drive the `standing` binary end-to-end.

use std::process::Command;

const BODY_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn standing() -> Command {
    Command::new(env!("CARGO_BIN_EXE_standing"))
}

fn temp_db() -> tempfile::NamedTempFile {
    tempfile::NamedTempFile::new().unwrap()
}

fn temp_identity(name: &str, location: &str, secret: &str) -> tempfile::NamedTempFile {
    let output = standing()
        .args([
            "identity",
            "create",
            "--name",
            name,
            "--location",
            location,
            "--secret",
            secret,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "identity create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut f = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut f, &output.stdout).unwrap();
    f
}

fn run(cmd: &mut Command) -> (bool, String, String) {
    let output = cmd.output().unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn extract_grant_id(stdout: &str) -> String {
    // "granted <uuid>" or "denied <uuid>"
    stdout
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string()
}

const SECRET: &str = "integration-test-secret";

// ---------------------------------------------------------------
// Identity
// ---------------------------------------------------------------

#[test]
fn identity_create_and_verify() {
    let id_file = temp_identity("test-bot", "host-1", SECRET);

    let (ok, stdout, _) = run(standing().args([
        "identity",
        "verify",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
    ]));
    assert!(ok);
    assert!(stdout.contains("wl:test-bot:host-1"));
}

#[test]
fn identity_verify_wrong_secret_fails() {
    let id_file = temp_identity("test-bot", "host-1", SECRET);

    let (ok, _, stderr) = run(standing().args([
        "identity",
        "verify",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        "wrong",
    ]));
    assert!(!ok);
    assert!(stderr.contains("verification failed"));
}

#[test]
fn identity_missing_file_fails() {
    let db = temp_db();
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "grant",
        "request",
        "--identity",
        "/tmp/nonexistent-standing-id.json",
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
    ]));
    assert!(!ok);
    assert!(stderr.contains("cannot read identity file"));
}

// ---------------------------------------------------------------
// Happy path: request → activate → use → query
// ---------------------------------------------------------------

#[test]
fn full_lifecycle_happy_path() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let id_file = temp_identity("deploy-bot", "host-abc", SECRET);
    let id_path = id_file.path().to_str().unwrap();

    // Request
    let (ok, stdout, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod/web-api",
        "--duration",
        "300",
    ]));
    assert!(ok, "request failed: {stderr}");
    assert!(stdout.contains("granted"));
    let grant_id = extract_grant_id(&stdout);

    // Activate
    let (ok, stdout, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "activate",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
    ]));
    assert!(ok, "activate failed: {stderr}");
    assert!(stdout.contains("activated"));

    // Use
    let (ok, stdout, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod/web-api",
        "--evidence",
        r#"{"deployed":"v1.0"}"#,
    ]));
    assert!(ok, "use failed: {stderr}");
    assert!(stdout.contains("used"));

    // Query chain
    let (ok, stdout, _) =
        run(standing().args(["--db", db_path, "query", "chain", "--id", &grant_id]));
    assert!(ok);
    assert!(stdout.contains("grant_requested"));
    assert!(stdout.contains("grant_issued"));
    assert!(stdout.contains("grant_activated"));
    assert!(stdout.contains("grant_used"));

    // Query why
    let (ok, stdout, _) =
        run(standing().args(["--db", db_path, "query", "why", "--id", &grant_id]));
    assert!(ok);
    assert!(stdout.contains("verdict"));
    assert!(stdout.contains("allow"));
    assert!(stdout.contains("wl:deploy-bot:host-abc"));
}

// ---------------------------------------------------------------
// Policy denial
// ---------------------------------------------------------------

#[test]
fn policy_denies_excessive_duration() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let id_file = temp_identity("deploy-bot", "host-abc", SECRET);
    let id_path = id_file.path().to_str().unwrap();

    let (ok, stdout, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "7200",
    ]));
    assert!(ok); // CLI exits 0 even on deny — it's a valid outcome
    assert!(stdout.contains("denied"));
    assert!(stdout.contains("exceeds max"));
}

// ---------------------------------------------------------------
// Wrong principal rejected
// ---------------------------------------------------------------

#[test]
fn wrong_principal_cannot_activate() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let bot1 = temp_identity("bot-1", "host-a", SECRET);
    let bot2 = temp_identity("bot-2", "host-b", SECRET);

    // Request as bot-1
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        bot1.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "300",
    ]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    // Try to activate as bot-2 — should fail
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "activate",
        "--id",
        &grant_id,
        "--identity",
        bot2.path().to_str().unwrap(),
        "--secret",
        SECRET,
    ]));
    assert!(!ok);
    assert!(stderr.contains("unauthorized"));
}

// ---------------------------------------------------------------
// Double-use rejected
// ---------------------------------------------------------------

#[test]
fn double_use_rejected() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let id_file = temp_identity("bot", "host", SECRET);
    let id_path = id_file.path().to_str().unwrap();

    let (ok, stdout, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "300",
    ]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    // Activate
    let (ok, _, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "activate",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
    ]));
    assert!(ok);

    // Use
    let (ok, _, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
    ]));
    assert!(ok);

    // Second use — should fail
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
    ]));
    assert!(!ok);
    assert!(stderr.contains("invalid transition"));
}

// ---------------------------------------------------------------
// Spend-time scope matching (Model X / D010, D010a)
// ---------------------------------------------------------------

#[test]
fn use_with_wrong_scope_is_refused_and_does_not_consume() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let id_file = temp_identity("deploy-bot", "host-abc", SECRET);
    let id_path = id_file.path().to_str().unwrap();

    // Grant scoped to deploy/prod.
    let (ok, stdout, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "300",
    ]));
    assert!(ok, "request failed: {stderr}");
    let grant_id = extract_grant_id(&stdout);
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "activate",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
    ]));
    assert!(ok, "activate failed: {stderr}");

    // Use with the WRONG target → refused with scope mismatch.
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "staging",
    ]));
    assert!(!ok, "wrong-scope use must be refused");
    assert!(stderr.contains("scope mismatch"), "stderr: {stderr}");

    // Non-consuming: the correctly-scoped use still succeeds (grant not burned).
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
    ]));
    assert!(ok, "grant must be unspent after a scope mismatch: {stderr}");
}

// ---------------------------------------------------------------
// standing.grant_use.v1 JSON witness packet (D010b/D010c)
// ---------------------------------------------------------------

/// Set up a fresh activated grant scoped deploy/prod; return (db_path-owner, id_owner, grant_id).
fn activated_grant(db: &tempfile::NamedTempFile, id_file: &tempfile::NamedTempFile) -> String {
    let db_path = db.path().to_str().unwrap();
    let id_path = id_file.path().to_str().unwrap();
    let (ok, stdout, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "300",
    ]));
    assert!(ok, "request failed: {stderr}");
    let grant_id = extract_grant_id(&stdout);
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "activate",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
    ]));
    assert!(ok, "activate failed: {stderr}");
    grant_id
}

#[test]
fn grant_use_json_success_packet() {
    let db = temp_db();
    let id_file = temp_identity("deploy-bot", "host-abc", SECRET);
    let grant_id = activated_grant(&db, &id_file);
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--json",
    ]));
    assert!(ok);
    assert!(
        stdout.contains(r#""schema":"standing.grant_use.v1""#),
        "{stdout}"
    );
    assert!(stdout.contains(r#""result":"used""#), "{stdout}");
    assert!(
        stdout.contains(r#""receipt_kind":"grant_used""#),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""receipt_digest":""#),
        "digest required on used: {stdout}"
    );
}

#[test]
fn grant_use_json_scope_mismatch_refusal() {
    let db = temp_db();
    let id_file = temp_identity("deploy-bot", "host-abc", SECRET);
    let grant_id = activated_grant(&db, &id_file);
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "staging",
        "--json",
    ]));
    assert!(!ok, "wrong scope must exit nonzero");
    assert!(stdout.contains(r#""result":"refused""#), "{stdout}");
    assert!(
        stdout.contains(r#""refusal_class":"scope_mismatch""#),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""receipt_digest":null"#),
        "refusal digest must be null: {stdout}"
    );
}

#[test]
fn grant_use_json_not_found_refusal() {
    let db = temp_db();
    let id_file = temp_identity("deploy-bot", "host-abc", SECRET);
    // A syntactically valid but nonexistent grant id.
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "grant",
        "use",
        "--id",
        "00000000-0000-0000-0000-000000000000",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--json",
    ]));
    assert!(!ok);
    assert!(
        stdout.contains(r#""refusal_class":"not_found""#),
        "{stdout}"
    );
    assert!(stdout.contains(r#""receipt_digest":null"#), "{stdout}");
}

#[test]
fn grant_use_json_subject_mismatch_refusal() {
    let db = temp_db();
    let owner = temp_identity("deploy-bot", "host-abc", SECRET);
    let grant_id = activated_grant(&db, &owner);
    // A different principal attempts to use the grant.
    let other = temp_identity("evil-bot", "host-xyz", SECRET);
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        other.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--json",
    ]));
    assert!(!ok);
    assert!(
        stdout.contains(r#""refusal_class":"subject_mismatch""#),
        "{stdout}"
    );
}

#[test]
fn grant_use_json_already_spent_refusal() {
    let db = temp_db();
    let id_file = temp_identity("deploy-bot", "host-abc", SECRET);
    let grant_id = activated_grant(&db, &id_file);
    let db_path = db.path().to_str().unwrap();
    let id_path = id_file.path().to_str().unwrap();
    // First (valid) spend.
    let (ok, _, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--json",
    ]));
    assert!(ok);
    // Second spend → already_spent.
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "use",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--json",
    ]));
    assert!(!ok);
    assert!(
        stdout.contains(r#""refusal_class":"already_spent""#),
        "{stdout}"
    );
}

// ---------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------

#[test]
fn admin_revoke_then_activate_fails() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let id_file = temp_identity("bot", "host", SECRET);
    let id_path = id_file.path().to_str().unwrap();

    let (ok, stdout, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "300",
    ]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    // Revoke as admin
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "revoke",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--admin",
        "--reason",
        "security",
    ]));
    assert!(ok);
    assert!(stdout.contains("revoked"));

    // Try to activate — should fail
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "activate",
        "--id",
        &grant_id,
        "--identity",
        id_path,
        "--secret",
        SECRET,
    ]));
    assert!(!ok);
    assert!(stderr.contains("invalid transition"));
}

// ---------------------------------------------------------------
// Sweep
// ---------------------------------------------------------------

#[test]
fn sweep_expires_stale_grants() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let id_file = temp_identity("bot", "host", SECRET);
    let id_path = id_file.path().to_str().unwrap();

    // Request with 1-second duration
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "1",
    ]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    // Wait for expiry
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Dry run
    let (ok, stdout, _) = run(standing().args(["--db", db_path, "grant", "sweep", "--dry-run"]));
    assert!(ok);
    assert!(stdout.contains("would expire"));

    // Real sweep
    let (ok, stdout, _) = run(standing().args(["--db", db_path, "grant", "sweep"]));
    assert!(ok);
    assert!(stdout.contains("expired"));
    assert!(stdout.contains(&grant_id));

    // Verify state
    let (ok, stdout, _) =
        run(standing().args(["--db", db_path, "grant", "list", "--state", "expired"]));
    assert!(ok);
    assert!(stdout.contains(&grant_id));
}

// ---------------------------------------------------------------
// Grant list
// ---------------------------------------------------------------

#[test]
fn list_grants_shows_entries() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let id_file = temp_identity("bot", "host", SECRET);
    let id_path = id_file.path().to_str().unwrap();

    // Empty
    let (ok, stdout, _) = run(standing().args(["--db", db_path, "grant", "list"]));
    assert!(ok);
    assert!(stdout.contains("no grants found"));

    // Create one
    let (ok, _, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "300",
    ]));
    assert!(ok);

    // Now has one
    let (ok, stdout, _) = run(standing().args(["--db", db_path, "grant", "list"]));
    assert!(ok);
    assert!(stdout.contains("deploy"));
    assert!(stdout.contains("wl:bot:host"));
}

// ---------------------------------------------------------------
// Replay detection on grant request
// ---------------------------------------------------------------

#[test]
fn replay_same_identity_on_grant_request_rejected() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let id_file = temp_identity("bot", "host", SECRET);
    let id_path = id_file.path().to_str().unwrap();

    // First request succeeds
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "300",
    ]));
    assert!(ok);
    assert!(stdout.contains("granted"));

    // Second request with SAME identity file (same jti) should be rejected
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id_path,
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "staging",
        "--duration",
        "300",
    ]));
    assert!(!ok);
    assert!(stderr.contains("ReplayDetected") || stderr.contains("replay"));
}

#[test]
fn fresh_identity_after_replay_works() {
    let db = temp_db();
    let db_path = db.path().to_str().unwrap();
    let id1 = temp_identity("bot", "host", SECRET);
    let id2 = temp_identity("bot", "host", SECRET);

    // First request with id1
    let (ok, _, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id1.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod",
        "--duration",
        "300",
    ]));
    assert!(ok);

    // Second request with id2 (different jti) succeeds
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db_path,
        "grant",
        "request",
        "--identity",
        id2.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "staging",
        "--duration",
        "300",
    ]));
    assert!(ok);
    assert!(stdout.contains("granted"));
}

// ---------------------------------------------------------------
// Resolver (entitlement-to-assert, remote-boundary entitlement seam)
// ---------------------------------------------------------------

fn example_config_path() -> String {
    // CARGO_MANIFEST_DIR is crates/standing-cli; the example lives at
    // <repo>/examples/static-config.toml.
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("examples");
    p.push("static-config.toml");
    p.to_str().unwrap().to_string()
}

fn parse_decision(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).expect("resolver output must be canonical JSON")
}

#[test]
fn resolver_list_modes_matches_test_surface() {
    let (ok, stdout, _) = run(standing().args(["resolver", "list-modes"]));
    assert!(ok);
    for mode in ["deny_all", "local_only", "static_config"] {
        assert!(
            stdout.contains(mode),
            "resolver list-modes must mention {mode}: {stdout}"
        );
    }
    assert!(
        !stdout.contains("store_grant"),
        "unsupported mode must not be listed: {stdout}"
    );
    assert!(stdout.contains("standing assert resolve"));
}

#[test]
fn resolver_deny_all_returns_denied() {
    let (ok, stdout, _) = run(standing().args([
        "resolver",
        "test",
        "--resolver",
        "deny_all",
        "--actor",
        "workload:bot:host-a",
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/foo",
        "--audience",
        "nq:main",
    ]));
    assert!(ok, "stdout: {stdout}");
    let d = parse_decision(&stdout);
    assert_eq!(d["verdict"], "denied");
    assert_eq!(d["standing_basis"], "deny_default");
    assert_eq!(d["standing_enforced"], false);
    assert_eq!(d["resolver"], "DenyAllResolver");
}

#[test]
fn resolver_deny_all_binding_mode_sets_enforced() {
    let (ok, stdout, _) = run(standing().args([
        "resolver",
        "test",
        "--resolver",
        "deny_all",
        "--actor",
        "workload:bot:host-a",
        "--claim-kind",
        "k",
        "--subject-scope",
        "s",
        "--audience",
        "nq:main",
        "--mode",
        "binding",
    ]));
    assert!(ok);
    let d = parse_decision(&stdout);
    assert_eq!(d["standing_enforced"], true);
}

#[test]
fn resolver_local_only_admits_workload_actor() {
    let (ok, stdout, _) = run(standing().args([
        "resolver",
        "test",
        "--resolver",
        "local_only",
        "--actor",
        "workload:bot:host-a",
        "--claim-kind",
        "k",
        "--subject-scope",
        "s",
        "--audience",
        "nq:main",
    ]));
    assert!(ok);
    let d = parse_decision(&stdout);
    assert_eq!(d["verdict"], "allowed");
    assert_eq!(d["resolver"], "LocalOnlyResolver");
}

#[test]
fn resolver_local_only_refuses_component() {
    let (ok, stdout, _) = run(standing().args([
        "resolver",
        "test",
        "--resolver",
        "local_only",
        "--actor",
        "component:nq:linode",
        "--claim-kind",
        "k",
        "--subject-scope",
        "s",
        "--audience",
        "nq:main",
    ]));
    assert!(ok);
    let d = parse_decision(&stdout);
    assert_eq!(d["verdict"], "denied");
    assert_eq!(d["standing_basis"], "non_local_actor");
}

#[test]
fn resolver_static_config_admits_each_nq_claim_kind() {
    // The example config covers all four NQ Track-A claim kinds.
    // Exercising each through the resolver is the MVP smoke test for
    // Phase 3 (NQ visible-not-binding integration).
    let cfg = example_config_path();
    let cases = [
        ("sqlite_wal_state", "labelwatch/foo"),
        ("disk_state", "host:storage01"),
        ("dns_state", "vantage:nq-linode/resolver:dns/example.com"),
        ("ingest_state", "instance:nq:linode"),
    ];
    for (claim_kind, subject_scope) in cases {
        let (ok, stdout, _) = run(standing().args([
            "resolver",
            "test",
            "--resolver",
            "static_config",
            "--config",
            &cfg,
            "--actor",
            "component:nq:linode",
            "--claim-kind",
            claim_kind,
            "--subject-scope",
            subject_scope,
            "--audience",
            "nq:main",
        ]));
        assert!(ok, "claim_kind={claim_kind}: stdout={stdout}");
        let d = parse_decision(&stdout);
        assert_eq!(
            d["verdict"], "allowed",
            "claim_kind={claim_kind} subject_scope={subject_scope} must match: {d:?}"
        );
        assert_eq!(d["resolver"], "StaticConfigResolver");
        assert_eq!(d["standing_basis"], "static_config_match");
    }
}

#[test]
fn resolver_static_config_unknown_peer_denied() {
    let cfg = example_config_path();
    let (ok, stdout, _) = run(standing().args([
        "resolver",
        "test",
        "--resolver",
        "static_config",
        "--config",
        &cfg,
        "--actor",
        "component:nq:rogue",
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/foo",
        "--audience",
        "nq:main",
    ]));
    assert!(ok);
    let d = parse_decision(&stdout);
    assert_eq!(d["verdict"], "denied");
    assert_eq!(d["standing_basis"], "unknown_peer");
}

#[test]
fn resolver_static_config_wrong_claim_kind_denied() {
    let cfg = example_config_path();
    // component:nq:sushi-k is configured for sqlite_wal_state + disk_state
    // but NOT dns_state.
    let (ok, stdout, _) = run(standing().args([
        "resolver",
        "test",
        "--resolver",
        "static_config",
        "--config",
        &cfg,
        "--actor",
        "component:nq:sushi-k",
        "--claim-kind",
        "dns_state",
        "--subject-scope",
        "vantage:foo",
        "--audience",
        "nq:main",
    ]));
    assert!(ok);
    let d = parse_decision(&stdout);
    assert_eq!(d["verdict"], "denied");
    assert_eq!(d["standing_basis"], "claim_kind_out_of_scope");
}

#[test]
fn resolver_static_config_wrong_audience_denied() {
    let cfg = example_config_path();
    let (ok, stdout, _) = run(standing().args([
        "resolver",
        "test",
        "--resolver",
        "static_config",
        "--config",
        &cfg,
        "--actor",
        "component:nq:linode",
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/foo",
        "--audience",
        "nq:somewhere-else",
    ]));
    assert!(ok);
    let d = parse_decision(&stdout);
    assert_eq!(d["verdict"], "denied");
    assert_eq!(d["standing_basis"], "audience_mismatch");
}

#[test]
fn resolver_rejects_bare_audience() {
    // Canonical-naming validation: audience must be instance-qualified.
    let cfg = example_config_path();
    let (ok, _, stderr) = run(standing().args([
        "resolver",
        "test",
        "--resolver",
        "static_config",
        "--config",
        &cfg,
        "--actor",
        "component:nq:linode",
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/foo",
        "--audience",
        "nq", // bare — not instance-qualified
    ]));
    assert!(!ok, "bare audience must be refused");
    assert!(
        stderr.contains("instance-qualified") || stderr.contains("audience"),
        "stderr: {stderr}"
    );
}

#[test]
fn resolver_decision_records_full_attribution() {
    // The receipt-attribution discipline named in
    // docs/remote-standing-boundary.md requires every decision to carry
    // standing_mode/verification_mode/identity_substrate/standing_enforced/
    // resolver/standing_basis. Validate the CLI surfaces all of them.
    let cfg = example_config_path();
    let (ok, stdout, _) = run(standing().args([
        "resolver",
        "test",
        "--resolver",
        "static_config",
        "--config",
        &cfg,
        "--actor",
        "component:nq:linode",
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/foo",
        "--audience",
        "nq:main",
    ]));
    assert!(ok);
    let d = parse_decision(&stdout);
    for field in [
        "verdict",
        "reason",
        "verification_mode",
        "identity_substrate",
        "standing_enforced",
        "resolver",
        "standing_basis",
        "scope",
        "audience",
        "evaluated_at",
    ] {
        assert!(d.get(field).is_some(), "missing attribution field {field}");
    }
}

// ---------------------------------------------------------------
// Genesis — chain-root receipt, exactly one per instance
// ---------------------------------------------------------------

#[test]
fn genesis_install_then_show_returns_receipt() {
    let db = temp_db();
    let id_file = temp_identity("jbeck", "laptop", SECRET);

    let (ok, stdout, stderr) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "genesis",
        "install",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
    ]));
    assert!(ok, "install failed: {stderr}");
    assert!(stdout.contains("genesis installed."));
    assert!(stdout.contains("operator_fiat"));
    assert!(stdout.contains("wl:jbeck:laptop"));

    let (ok, stdout, _) =
        run(standing().args(["--db", db.path().to_str().unwrap(), "genesis", "show"]));
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["kind"], "genesis_install");
    assert_eq!(v["operator"], "wl:jbeck:laptop");
    assert_eq!(v["evidence"]["basis"], "operator_fiat");
    assert_eq!(v["evidence"]["version"], "standing.genesis.v1");
    assert_eq!(v["evidence"]["policy_source"], "hardcoded:v1");
    assert!(v["evidence"]["prior_grant"].is_null());
    assert!(v["evidence"]["instance_id"].as_str().is_some());
    assert!(v["policy_hash"].as_str().is_some());
}

#[test]
fn second_genesis_install_is_refused() {
    let db = temp_db();
    let id_file = temp_identity("jbeck", "laptop", SECRET);

    let (ok, _, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "genesis",
        "install",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
    ]));
    assert!(ok);

    let (ok, _, stderr) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "genesis",
        "install",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
    ]));
    assert!(!ok, "second install must fail");
    assert!(
        stderr.contains("genesis already installed"),
        "stderr was: {stderr}"
    );
}

#[test]
fn genesis_show_before_install_reports_absence() {
    let db = temp_db();
    let (ok, stdout, _) =
        run(standing().args(["--db", db.path().to_str().unwrap(), "genesis", "show"]));
    assert!(ok);
    assert!(stdout.contains("no genesis receipt installed"));
}

#[test]
fn query_why_footers_genesis_when_present() {
    let db = temp_db();
    let id_file = temp_identity("deploy-bot", "host-a", SECRET);

    // First install genesis.
    let (ok, _, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "genesis",
        "install",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
    ]));
    assert!(ok);

    // Then create a grant and walk why.
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "grant",
        "request",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod/web-api",
        "--duration",
        "60",
    ]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "query",
        "why",
        "--id",
        &grant_id,
    ]));
    assert!(ok);
    assert!(stdout.contains("── chain root ──"));
    assert!(stdout.contains("genesis install (operator fiat):"));
    assert!(stdout.contains("operator: wl:deploy-bot:host-a"));
    assert!(stdout.contains("basis:    \"operator_fiat\""));
}

#[test]
fn query_why_footers_silence_when_no_genesis() {
    let db = temp_db();
    let id_file = temp_identity("deploy-bot", "host-a", SECRET);

    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "grant",
        "request",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--action",
        "deploy",
        "--target",
        "prod/web-api",
        "--duration",
        "60",
    ]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "query",
        "why",
        "--id",
        &grant_id,
    ]));
    assert!(ok);
    assert!(stdout.contains("── chain root ──"));
    assert!(stdout.contains("chain terminates in silence"));
    assert!(stdout.contains("standing genesis install"));
}

// ---------------------------------------------------------------
// Assertion-standing preflight surface (Phase 4a — door, not room)
// ---------------------------------------------------------------

#[test]
fn assert_check_descriptive_does_not_require() {
    let db = temp_db();
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "assert",
        "check",
        "--principal",
        "component:nq:linode",
        "--consumer",
        "nq:linode",
        "--claim-kind",
        "sqlite_wal_state",
        "--target",
        "labelwatch/foo",
        "--effect",
        "descriptive",
    ]));
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "not_required");
    assert_eq!(v["reason"], "effect_non_binding");
    assert_eq!(v["act_standing_sufficient"], true);
    assert_eq!(v["assert_standing_required"], false);
    assert!(v["required_for"].is_null());
    assert_eq!(v["consumer"], "nq:linode");
    assert_eq!(v["claim_kind"], "sqlite_wal_state");
}

#[test]
fn assert_check_advisory_does_not_require() {
    let db = temp_db();
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "assert",
        "check",
        "--principal",
        "component:nq:linode",
        "--consumer",
        "wicket:local",
        "--claim-kind",
        "host_state",
        "--target",
        "host:storage01",
        "--effect",
        "advisory",
    ]));
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "not_required");
    assert_eq!(v["assert_standing_required"], false);
}

#[test]
fn assert_check_binding_refused_as_not_implemented() {
    let db = temp_db();
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "assert",
        "check",
        "--principal",
        "component:nq:linode",
        "--consumer",
        "wicket:local",
        "--claim-kind",
        "deploy_authorization",
        "--target",
        "prod/web-api",
        "--effect",
        "binding",
    ]));
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "required_not_implemented");
    assert_eq!(v["reason"], "assertion_standing_not_implemented");
    assert_eq!(v["required_for"], "binding_claim");
    assert_eq!(v["act_standing_sufficient"], false);
    assert_eq!(v["assert_standing_required"], true);
}

#[test]
fn assert_check_mutating_refused_as_not_implemented() {
    let db = temp_db();
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "assert",
        "check",
        "--principal",
        "component:nightshift:sushi-k",
        "--consumer",
        "ag:local",
        "--claim-kind",
        "watchbill_close",
        "--target",
        "wb-42",
        "--effect",
        "mutating",
    ]));
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "required_not_implemented");
    assert_eq!(v["required_for"], "mutating_claim");
}

#[test]
fn assert_check_cites_genesis_when_installed() {
    let db = temp_db();
    let id_file = temp_identity("jbeck", "laptop", SECRET);

    // Install genesis first.
    let (ok, _, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "genesis",
        "install",
        "--identity",
        id_file.path().to_str().unwrap(),
        "--secret",
        SECRET,
    ]));
    assert!(ok);

    // Now check assert; result should cite genesis digest + policy hash.
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "assert",
        "check",
        "--principal",
        "component:nq:linode",
        "--consumer",
        "wicket:local",
        "--claim-kind",
        "deploy",
        "--target",
        "prod/web-api",
        "--effect",
        "binding",
    ]));
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        v["why"]["genesis"].as_str().is_some(),
        "why.genesis must cite digest when genesis is installed: {v}"
    );
    assert!(
        v["why"]["policy"].as_str().is_some(),
        "why.policy must cite hash when genesis is installed: {v}"
    );
}

#[test]
fn assert_check_silent_when_no_genesis() {
    let db = temp_db();
    let (ok, stdout, _) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "assert",
        "check",
        "--principal",
        "component:nq:linode",
        "--consumer",
        "wicket:local",
        "--claim-kind",
        "deploy",
        "--target",
        "prod/web-api",
        "--effect",
        "binding",
    ]));
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["why"]["genesis"].is_null());
    assert!(v["why"]["policy"].is_null());
    assert!(
        v["why"]["note"].as_str().is_some_and(|n| !n.is_empty()),
        "why.note must always carry operator-readable text"
    );
}

#[test]
fn assert_check_rejects_bare_consumer_name() {
    let db = temp_db();
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "assert",
        "check",
        "--principal",
        "component:nq:linode",
        "--consumer",
        "nq",
        "--claim-kind",
        "sqlite_wal_state",
        "--target",
        "labelwatch/foo",
        "--effect",
        "descriptive",
    ]));
    assert!(!ok, "bare consumer name must be refused");
    assert!(
        stderr.contains("audience") || stderr.contains("instance"),
        "stderr should explain canonicalization failure: {stderr}"
    );
}

#[test]
fn assert_check_rejects_unknown_effect() {
    let db = temp_db();
    let (ok, _, stderr) = run(standing().args([
        "--db",
        db.path().to_str().unwrap(),
        "assert",
        "check",
        "--principal",
        "component:nq:linode",
        "--consumer",
        "nq:linode",
        "--claim-kind",
        "sqlite_wal_state",
        "--target",
        "labelwatch/foo",
        "--effect",
        "binding-ish",
    ]));
    assert!(!ok);
    assert!(stderr.contains("unknown effect"), "stderr was: {stderr}");
}

// ---------------------------------------------------------------
// Assertion leases (Phase 4b)
// ---------------------------------------------------------------

fn install_genesis(db: &str, op: &str) {
    let (ok, _o, e) = run(standing().args([
        "--db",
        db,
        "genesis",
        "install",
        "--identity",
        op,
        "--secret",
        SECRET,
    ]));
    assert!(ok, "genesis install failed: {e}");
}

#[test]
fn assert_grant_requires_genesis() {
    let db = temp_db();
    let dbp = db.path().to_str().unwrap();
    let op = temp_identity("operator", "laptop", SECRET);
    let speaker = temp_identity("speaker", "host1", SECRET);
    // No genesis installed yet — issuance must fail closed (L4).
    let (ok, _o, e) = run(standing().args([
        "--db",
        dbp,
        "assert",
        "grant",
        "--identity",
        speaker.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--operator-identity",
        op.path().to_str().unwrap(),
        "--operator-secret",
        SECRET,
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/*",
        "--audience",
        "nq:main",
        "--max-uses",
        "2",
    ]));
    assert!(!ok);
    assert!(
        e.contains("no genesis"),
        "expected genesis fail-closed, got: {e}"
    );
}

#[test]
fn assert_grant_requires_a_budget_choice() {
    let db = temp_db();
    let dbp = db.path().to_str().unwrap();
    let op = temp_identity("operator", "laptop", SECRET);
    let opp = op.path().to_str().unwrap();
    install_genesis(dbp, opp);
    let speaker = temp_identity("speaker", "host1", SECRET);
    // Neither --max-uses nor --unbounded → refused (L1: must choose).
    let (ok, _o, e) = run(standing().args([
        "--db",
        dbp,
        "assert",
        "grant",
        "--identity",
        speaker.path().to_str().unwrap(),
        "--secret",
        SECRET,
        "--operator-identity",
        opp,
        "--operator-secret",
        SECRET,
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/*",
        "--audience",
        "nq:main",
    ]));
    assert!(!ok);
    assert!(
        e.contains("use budget"),
        "expected budget-required refusal, got: {e}"
    );
}

#[test]
fn assert_grant_requires_genesis_operator_and_refuses_self_grant() {
    let db = temp_db();
    let dbp = db.path().to_str().unwrap();
    let op = temp_identity("operator", "laptop", SECRET);
    let opp = op.path().to_str().unwrap();
    install_genesis(dbp, opp);
    let speaker = temp_identity("speaker", "host1", SECRET);
    let sp = speaker.path().to_str().unwrap();
    let impostor = temp_identity("impostor", "laptop", SECRET);
    let ip = impostor.path().to_str().unwrap();

    let grant = |actor: &str, authorizer: &str| {
        run(standing().args([
            "--db",
            dbp,
            "assert",
            "grant",
            "--identity",
            actor,
            "--secret",
            SECRET,
            "--operator-identity",
            authorizer,
            "--operator-secret",
            SECRET,
            "--claim-kind",
            "sqlite_wal_state",
            "--subject-scope",
            "labelwatch/*",
            "--audience",
            "nq:main",
            "--max-uses",
            "2",
        ]))
    };

    let (ok, _, e) = grant(sp, ip);
    assert!(!ok);
    assert!(
        e.contains("requires genesis operator wl:operator:laptop"),
        "{e}"
    );

    let (ok, _, e) = grant(opp, opp);
    assert!(!ok);
    assert!(e.contains("cannot authorize its own lease"), "{e}");

    let (ok, out, e) = run(standing().args(["--db", dbp, "assert", "list"]));
    assert!(ok, "assert list failed: {e}");
    assert_eq!(
        out.trim(),
        "[]",
        "refused issuance must write no lease: {out}"
    );
}

#[test]
fn assert_lease_spend_reuse_replay_and_exhaustion() {
    let db = temp_db();
    let dbp = db.path().to_str().unwrap();
    let op = temp_identity("operator", "laptop", SECRET);
    let opp = op.path().to_str().unwrap();
    install_genesis(dbp, opp);
    let speaker = temp_identity("speaker", "host1", SECRET);
    let sp = speaker.path().to_str().unwrap();

    let (ok, out, e) = run(standing().args([
        "--db",
        dbp,
        "assert",
        "grant",
        "--identity",
        sp,
        "--secret",
        SECRET,
        "--operator-identity",
        opp,
        "--operator-secret",
        SECRET,
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/*",
        "--audience",
        "nq:main",
        "--max-uses",
        "2",
    ]));
    assert!(ok, "grant failed: {e}");
    assert!(out.contains("authorized by genesis operator: wl:operator:laptop"));
    let gid = extract_grant_id(&out.lines().next().unwrap().replace("assertion lease", ""));

    let (ok, chain, e) = run(standing().args(["--db", dbp, "query", "chain", "--id", &gid]));
    assert!(ok, "query chain failed: {e}");
    assert!(
        chain.contains(r#""operator_id": "wl:operator:laptop""#),
        "{chain}"
    );

    let prove = |jti: &str, subject: &str| {
        run(standing().args([
            "--db",
            dbp,
            "assert",
            "prove",
            "--id",
            &gid,
            "--identity",
            sp,
            "--secret",
            SECRET,
            "--claim-kind",
            "sqlite_wal_state",
            "--subject-id",
            subject,
            "--audience",
            "nq:main",
            "--jti",
            jti,
        ]))
    };

    // Spend #1 ok (auto-activates).
    let (ok, out, _) = prove("j1", "labelwatch/foo");
    assert!(ok);
    assert!(out.contains("spend #1"));

    // Replay of j1 refused.
    let (ok, _o, e) = prove("j1", "labelwatch/foo");
    assert!(!ok);
    assert!(e.contains("replay detected"), "got: {e}");

    // Out-of-scope subject refused, non-consuming.
    let (ok, _o, e) = prove("j-oops", "other/x");
    assert!(!ok);
    assert!(e.contains("out of lease scope"), "got: {e}");

    // Spend #2 exhausts the budget of 2.
    let (ok, out, _) = prove("j2", "labelwatch/bar");
    assert!(ok);
    assert!(
        out.contains("EXHAUSTED"),
        "expected exhaustion notice, got: {out}"
    );

    // Spend #3 refused — budget spent.
    let (ok, _o, e) = prove("j3", "labelwatch/baz");
    assert!(!ok);
    assert!(e.contains("budget exhausted"), "got: {e}");
}

#[test]
fn resolve_preview_authorizes_nothing_spend_authorizes() {
    let db = temp_db();
    let dbp = db.path().to_str().unwrap();
    let op = temp_identity("operator", "laptop", SECRET);
    let opp = op.path().to_str().unwrap();
    install_genesis(dbp, opp);
    let speaker = temp_identity("speaker", "host1", SECRET);
    let sp = speaker.path().to_str().unwrap();

    let (_ok, out, _e) = run(standing().args([
        "--db",
        dbp,
        "assert",
        "grant",
        "--identity",
        sp,
        "--secret",
        SECRET,
        "--operator-identity",
        opp,
        "--operator-secret",
        SECRET,
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/*",
        "--audience",
        "nq:main",
        "--max-uses",
        "5",
    ]));
    let gid = extract_grant_id(&out.lines().next().unwrap().replace("assertion lease", ""));

    let resolve = |jti: &str, extra: &[&str]| {
        let mut args = vec![
            "--db",
            dbp,
            "assert",
            "resolve",
            "--principal",
            "wl:speaker:host1",
            "--consumer",
            "nq:main",
            "--claim-kind",
            "sqlite_wal_state",
            "--target",
            "labelwatch/foo",
            "--effect",
            "binding",
            "--id",
            &gid,
            "--identity",
            sp,
            "--secret",
            SECRET,
            "--subject-id",
            "labelwatch/foo",
            "--jti",
            jti,
            "--body-digest",
            BODY_DIGEST,
        ];
        args.extend_from_slice(extra);
        run(standing().args(&args))
    };

    // Preview: RequiredAndAvailable but authorizes_effect=false, no receipt.
    let (ok, out, _) = resolve("rp1", &["--preview"]);
    assert!(ok);
    assert!(out.contains("\"required_and_available\""));
    assert!(
        out.contains("\"authorizes_effect\": false"),
        "preview must not authorize: {out}"
    );
    assert!(out.contains("\"preview\""));

    // Spend: authorizes_effect=true, emits a receipt digest.
    let (ok, out, _) = resolve("rp2", &[]);
    assert!(ok);
    assert!(
        out.contains("\"authorizes_effect\": true"),
        "spend must authorize: {out}"
    );
    assert!(out.contains("emitted_receipt_digest"));
    assert!(out.contains("within_validity"));
}

#[test]
fn policy_freeze_denies_then_thaw_restores() {
    let db = temp_db();
    let dbp = db.path().to_str().unwrap();
    let op = temp_identity("operator", "laptop", SECRET);
    let opp = op.path().to_str().unwrap();
    install_genesis(dbp, opp);
    let speaker = temp_identity("speaker", "host1", SECRET);
    let sp = speaker.path().to_str().unwrap();
    let impostor = temp_identity("impostor", "laptop", SECRET);
    let ip = impostor.path().to_str().unwrap();

    let (_ok, out, _) = run(standing().args([
        "--db",
        dbp,
        "assert",
        "grant",
        "--identity",
        sp,
        "--secret",
        SECRET,
        "--operator-identity",
        opp,
        "--operator-secret",
        SECRET,
        "--claim-kind",
        "sqlite_wal_state",
        "--subject-scope",
        "labelwatch/*",
        "--audience",
        "nq:main",
        "--max-uses",
        "5",
    ]));
    let gid = extract_grant_id(&out.lines().next().unwrap().replace("assertion lease", ""));

    let prove = |jti: &str| {
        run(standing().args([
            "--db",
            dbp,
            "assert",
            "prove",
            "--id",
            &gid,
            "--identity",
            sp,
            "--secret",
            SECRET,
            "--claim-kind",
            "sqlite_wal_state",
            "--subject-id",
            "labelwatch/foo",
            "--audience",
            "nq:main",
            "--jti",
            jti,
        ]))
    };

    // A verified non-genesis principal still cannot install a freeze.
    let (ok, _o, e) = run(standing().args([
        "--db",
        dbp,
        "policy",
        "freeze",
        "--handle",
        "inc-impostor",
        "--class-type",
        "claim_kind",
        "--class-value",
        "sqlite_wal_state",
        "--reason",
        "unauthorized",
        "--identity",
        ip,
        "--secret",
        SECRET,
    ]));
    assert!(!ok);
    assert!(
        e.contains("requires genesis operator wl:operator:laptop"),
        "{e}"
    );

    // Freeze the claim_kind class.
    let (ok, _o, e) = run(standing().args([
        "--db",
        dbp,
        "policy",
        "freeze",
        "--handle",
        "inc-1",
        "--class-type",
        "claim_kind",
        "--class-value",
        "sqlite_wal_state",
        "--reason",
        "storage incident",
        "--identity",
        opp,
        "--secret",
        SECRET,
    ]));
    assert!(ok, "freeze failed: {e}");

    // Spend refused with class_frozen.
    let (ok, _o, e) = prove("f1");
    assert!(!ok);
    assert!(
        e.contains("class frozen"),
        "expected class_frozen, got: {e}"
    );

    // List shows the active freeze.
    let (ok, out, _) = run(standing().args(["--db", dbp, "policy", "list-freezes"]));
    assert!(ok);
    assert!(out.contains("inc-1"));

    // A non-genesis principal cannot thaw it, and the freeze remains active.
    let (ok, _o, e) = run(standing().args([
        "--db",
        dbp,
        "policy",
        "thaw",
        "--handle",
        "inc-1",
        "--identity",
        ip,
        "--secret",
        SECRET,
    ]));
    assert!(!ok);
    assert!(
        e.contains("requires genesis operator wl:operator:laptop"),
        "{e}"
    );
    let (ok, _o, e) = prove("f-still-frozen");
    assert!(!ok);
    assert!(e.contains("class frozen"), "{e}");

    // Genesis operator thaw, then the same lease spends again.
    let (ok, _o, e) = run(standing().args([
        "--db",
        dbp,
        "policy",
        "thaw",
        "--handle",
        "inc-1",
        "--identity",
        opp,
        "--secret",
        SECRET,
    ]));
    assert!(ok, "thaw failed: {e}");
    let (ok, out, _) = prove("f2");
    assert!(ok, "spend after thaw should succeed");
    assert!(out.contains("spend #1"));

    // `action` is a supported freeze class for act grants.
    let (ok, _o, e) = run(standing().args([
        "--db",
        dbp,
        "policy",
        "freeze",
        "--handle",
        "inc-action",
        "--class-type",
        "action",
        "--class-value",
        "deploy",
        "--reason",
        "deploy pause",
        "--identity",
        opp,
        "--secret",
        SECRET,
    ]));
    assert!(ok, "action-class freeze failed: {e}");
}
