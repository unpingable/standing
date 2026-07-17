#!/usr/bin/env bash
# NQ-Gov-Wicket demo — the Phase 4b/6 binding path, end to end.
#
# LAB-BACKED COMPATIBILITY EVIDENCE, NOT LIVE TESTIMONY. This drives the real
# `standing` binary against a throwaway DB with synthetic identities. It
# demonstrates the surface a consumer (NQ binding flip / Wicket adapter) points
# at; it is NOT a claim that any real consumer is wired.
#
# Usage:  cargo build && ./examples/nq-gov-wicket-demo.sh
set -euo pipefail

BIN="${STANDING_BIN:-./target/debug/standing}"
DEMO_TMPDIR="$(mktemp -d)"
DB="$DEMO_TMPDIR/standing.db"
OP_ID="$DEMO_TMPDIR/operator.id.json"
SPEAKER_ID="$DEMO_TMPDIR/speaker.id.json"
SEC="demo-secret"

cleanup() {
  rm -f -- "$DB" "${DB}-wal" "${DB}-shm" "$OP_ID" "$SPEAKER_ID"
  rmdir -- "$DEMO_TMPDIR" 2>/dev/null || true
}
trap cleanup EXIT

say() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
run() { echo "\$ $*"; "$@"; }

expect_failure() {
  local label="$1"
  local expected="$2"
  shift 2

  echo "   -- $label --"
  local output
  if output="$("$@" 2>&1)"; then
    echo "UNEXPECTED: command succeeded: $label" >&2
    exit 1
  fi
  if ! grep -qi -- "$expected" <<<"$output"; then
    printf 'UNEXPECTED refusal for %s (wanted /%s/):\n%s\n' \
      "$label" "$expected" "$output" >&2
    exit 1
  fi
  printf '%s\n' "$output" | sed 's/^/   /'
}

say "0. synthetic identities (operator + speaker)"
"$BIN" --db "$DB" identity create --name operator --location laptop --secret "$SEC" > "$OP_ID"
"$BIN" --db "$DB" identity create --name speaker  --location host1  --secret "$SEC" > "$SPEAKER_ID"

say "1. genesis fail-closed: issuance is refused before a genesis exists"
expect_failure "issuance without genesis" "no genesis" \
  "$BIN" --db "$DB" assert grant \
    --identity "$SPEAKER_ID" --secret "$SEC" \
    --operator-identity "$OP_ID" --operator-secret "$SEC" \
    --claim-kind sqlite_wal_state --subject-scope 'labelwatch/*' --audience nq:main \
    --max-uses 3

say "2. install genesis (operator fiat, the citable root)"
run "$BIN" --db "$DB" genesis install --identity "$OP_ID" --secret "$SEC"

say "3. genesis operator opens a bounded lease for a distinct speaker (max-uses 3)"
GRANT_OUT="$("$BIN" --db "$DB" assert grant \
  --identity "$SPEAKER_ID" --secret "$SEC" \
  --operator-identity "$OP_ID" --operator-secret "$SEC" \
  --claim-kind sqlite_wal_state --subject-scope 'labelwatch/*' --audience nq:main \
  --duration 3600 --max-uses 3)"
printf '%s\n' "$GRANT_OUT"
GID="$(printf '%s\n' "$GRANT_OUT" | awk 'NR == 1 { print $NF }')"

say "4. consumer preflight (Wicket asks: do I need assert-standing, and is it available?)"
echo "   -- PREVIEW: authorizes nothing, consumes nothing --"
"$BIN" --db "$DB" assert resolve --principal wl:speaker:host1 --consumer nq:main \
  --claim-kind sqlite_wal_state --target labelwatch/foo --effect binding \
  --id "$GID" --identity "$SPEAKER_ID" --secret "$SEC" \
  --subject-id labelwatch/foo --jti demo-preview \
  --body-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --preview \
  | grep -E '"decision"|"authorizes_effect"|"decision_mode"'

say "5. consumer binds: the spend path authorizes and emits a receipt"
"$BIN" --db "$DB" assert resolve --principal wl:speaker:host1 --consumer nq:main \
  --claim-kind sqlite_wal_state --target labelwatch/foo --effect binding \
  --id "$GID" --identity "$SPEAKER_ID" --secret "$SEC" \
  --subject-id labelwatch/foo --jti demo-bind-1 \
  --body-digest bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  | grep -E '"decision"|"authorizes_effect"|"freshness"|"emitted_receipt_digest"'

say "6. NEGATIVE FIXTURES (the cages)"
expect_failure "replay (same jti)" "replay" \
  "$BIN" --db "$DB" assert prove --id "$GID" --identity "$SPEAKER_ID" --secret "$SEC" \
    --claim-kind sqlite_wal_state --subject-id labelwatch/foo --audience nq:main \
    --jti demo-bind-1 --body-digest bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
expect_failure "out-of-scope subject (non-consuming)" "subject" \
  "$BIN" --db "$DB" assert prove --id "$GID" --identity "$SPEAKER_ID" --secret "$SEC" \
    --claim-kind sqlite_wal_state --subject-id other/x --audience nq:main \
    --jti demo-oops --body-digest cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

say "7. incident mode: freeze the claim class, prove is denied, thaw restores"
run "$BIN" --db "$DB" policy freeze --handle demo-incident \
  --class-type claim_kind --class-value sqlite_wal_state \
  --reason "storage smoke" --identity "$OP_ID" --secret "$SEC"
expect_failure "prove under freeze" "frozen" \
  "$BIN" --db "$DB" assert prove --id "$GID" --identity "$SPEAKER_ID" --secret "$SEC" \
    --claim-kind sqlite_wal_state --subject-id labelwatch/foo --audience nq:main \
    --jti demo-frozen --body-digest dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
run "$BIN" --db "$DB" policy thaw --handle demo-incident \
  --identity "$OP_ID" --secret "$SEC"

say "8. budget exhaustion: the lease is spent, re-witness required"
"$BIN" --db "$DB" assert prove --id "$GID" --identity "$SPEAKER_ID" --secret "$SEC" \
  --claim-kind sqlite_wal_state --subject-id labelwatch/bar --audience nq:main --jti demo-bind-2 \
  --body-digest eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  2>&1 | sed 's/^/   /'
"$BIN" --db "$DB" assert prove --id "$GID" --identity "$SPEAKER_ID" --secret "$SEC" \
  --claim-kind sqlite_wal_state --subject-id labelwatch/baz --audience nq:main --jti demo-bind-3 \
  --body-digest ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  2>&1 | sed 's/^/   /'
expect_failure "fourth spend after max-uses=3" "exhausted" \
  "$BIN" --db "$DB" assert prove --id "$GID" --identity "$SPEAKER_ID" --secret "$SEC" \
    --claim-kind sqlite_wal_state --subject-id labelwatch/quux --audience nq:main \
    --jti demo-bind-4 --body-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

say "9. the receipt chain — requested -> issued(cites genesis) -> activated -> assertion_made*"
"$BIN" --db "$DB" query chain --id "$GID" | grep -iE 'requested|issued|activated|made|exhausted' | sed 's/^/   /'

say "demo complete (throwaway files are removed on exit)"
