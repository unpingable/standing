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
