//! Integration tests: drive the `standing` binary end-to-end.

use std::process::Command;

fn standing() -> Command {
    Command::new(env!("CARGO_BIN_EXE_standing"))
}

fn temp_db() -> tempfile::NamedTempFile {
    tempfile::NamedTempFile::new().unwrap()
}

fn temp_identity(name: &str, location: &str, secret: &str) -> tempfile::NamedTempFile {
    let output = standing()
        .args(["identity", "create", "--name", name, "--location", location, "--secret", secret])
        .output()
        .unwrap();
    assert!(output.status.success(), "identity create failed: {}", String::from_utf8_lossy(&output.stderr));

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

    let (ok, stdout, _) = run(standing()
        .args(["identity", "verify", "--identity", id_file.path().to_str().unwrap(), "--secret", SECRET]));
    assert!(ok);
    assert!(stdout.contains("wl:test-bot:host-1"));
}

#[test]
fn identity_verify_wrong_secret_fails() {
    let id_file = temp_identity("test-bot", "host-1", SECRET);

    let (ok, _, stderr) = run(standing()
        .args(["identity", "verify", "--identity", id_file.path().to_str().unwrap(), "--secret", "wrong"]));
    assert!(!ok);
    assert!(stderr.contains("verification failed"));
}

#[test]
fn identity_missing_file_fails() {
    let db = temp_db();
    let (ok, _, stderr) = run(standing()
        .args(["--db", db.path().to_str().unwrap(),
               "grant", "request",
               "--identity", "/tmp/nonexistent-standing-id.json",
               "--secret", SECRET,
               "--action", "deploy", "--target", "prod"]));
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
    let (ok, stdout, stderr) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id_path, "--secret", SECRET,
               "--action", "deploy", "--target", "prod/web-api", "--duration", "300"]));
    assert!(ok, "request failed: {stderr}");
    assert!(stdout.contains("granted"));
    let grant_id = extract_grant_id(&stdout);

    // Activate
    let (ok, stdout, stderr) = run(standing()
        .args(["--db", db_path, "grant", "activate",
               "--id", &grant_id, "--identity", id_path, "--secret", SECRET]));
    assert!(ok, "activate failed: {stderr}");
    assert!(stdout.contains("activated"));

    // Use
    let (ok, stdout, stderr) = run(standing()
        .args(["--db", db_path, "grant", "use",
               "--id", &grant_id, "--identity", id_path, "--secret", SECRET,
               "--evidence", r#"{"deployed":"v1.0"}"#]));
    assert!(ok, "use failed: {stderr}");
    assert!(stdout.contains("used"));

    // Query chain
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "query", "chain", "--id", &grant_id]));
    assert!(ok);
    assert!(stdout.contains("grant_requested"));
    assert!(stdout.contains("grant_issued"));
    assert!(stdout.contains("grant_activated"));
    assert!(stdout.contains("grant_used"));

    // Query why
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "query", "why", "--id", &grant_id]));
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

    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id_path, "--secret", SECRET,
               "--action", "deploy", "--target", "prod", "--duration", "7200"]));
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
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", bot1.path().to_str().unwrap(), "--secret", SECRET,
               "--action", "deploy", "--target", "prod", "--duration", "300"]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    // Try to activate as bot-2 — should fail
    let (ok, _, stderr) = run(standing()
        .args(["--db", db_path, "grant", "activate",
               "--id", &grant_id,
               "--identity", bot2.path().to_str().unwrap(), "--secret", SECRET]));
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

    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id_path, "--secret", SECRET,
               "--action", "deploy", "--target", "prod", "--duration", "300"]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    // Activate
    let (ok, _, _) = run(standing()
        .args(["--db", db_path, "grant", "activate",
               "--id", &grant_id, "--identity", id_path, "--secret", SECRET]));
    assert!(ok);

    // Use
    let (ok, _, _) = run(standing()
        .args(["--db", db_path, "grant", "use",
               "--id", &grant_id, "--identity", id_path, "--secret", SECRET]));
    assert!(ok);

    // Second use — should fail
    let (ok, _, stderr) = run(standing()
        .args(["--db", db_path, "grant", "use",
               "--id", &grant_id, "--identity", id_path, "--secret", SECRET]));
    assert!(!ok);
    assert!(stderr.contains("invalid transition"));
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

    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id_path, "--secret", SECRET,
               "--action", "deploy", "--target", "prod", "--duration", "300"]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    // Revoke as admin
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "revoke",
               "--id", &grant_id, "--identity", id_path, "--secret", SECRET,
               "--admin", "--reason", "security"]));
    assert!(ok);
    assert!(stdout.contains("revoked"));

    // Try to activate — should fail
    let (ok, _, stderr) = run(standing()
        .args(["--db", db_path, "grant", "activate",
               "--id", &grant_id, "--identity", id_path, "--secret", SECRET]));
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
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id_path, "--secret", SECRET,
               "--action", "deploy", "--target", "prod", "--duration", "1"]));
    assert!(ok);
    let grant_id = extract_grant_id(&stdout);

    // Wait for expiry
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Dry run
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "sweep", "--dry-run"]));
    assert!(ok);
    assert!(stdout.contains("would expire"));

    // Real sweep
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "sweep"]));
    assert!(ok);
    assert!(stdout.contains("expired"));
    assert!(stdout.contains(&grant_id));

    // Verify state
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "list", "--state", "expired"]));
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
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "list"]));
    assert!(ok);
    assert!(stdout.contains("no grants found"));

    // Create one
    let (ok, _, _) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id_path, "--secret", SECRET,
               "--action", "deploy", "--target", "prod", "--duration", "300"]));
    assert!(ok);

    // Now has one
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "list"]));
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
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id_path, "--secret", SECRET,
               "--action", "deploy", "--target", "prod", "--duration", "300"]));
    assert!(ok);
    assert!(stdout.contains("granted"));

    // Second request with SAME identity file (same jti) should be rejected
    let (ok, _, stderr) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id_path, "--secret", SECRET,
               "--action", "deploy", "--target", "staging", "--duration", "300"]));
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
    let (ok, _, _) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id1.path().to_str().unwrap(), "--secret", SECRET,
               "--action", "deploy", "--target", "prod", "--duration", "300"]));
    assert!(ok);

    // Second request with id2 (different jti) succeeds
    let (ok, stdout, _) = run(standing()
        .args(["--db", db_path, "grant", "request",
               "--identity", id2.path().to_str().unwrap(), "--secret", SECRET,
               "--action", "deploy", "--target", "staging", "--duration", "300"]));
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
fn resolver_list_modes_documents_all_four() {
    let (ok, stdout, _) = run(standing().args(["resolver", "list-modes"]));
    assert!(ok);
    for mode in ["deny_all", "local_only", "static_config", "store_grant"] {
        assert!(
            stdout.contains(mode),
            "resolver list-modes must mention {mode}: {stdout}"
        );
    }
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
