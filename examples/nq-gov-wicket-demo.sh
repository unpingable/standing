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
DB="$(mktemp -u).db"
SEC="demo-secret"
trap 'rm -f "$DB" ./*.demo.id.json' EXIT

say() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
run() { echo "\$ $*"; "$@"; }

say "0. synthetic identities (operator + speaker)"
"$BIN" --db "$DB" identity create --name operator --location laptop --secret "$SEC" > operator.demo.id.json
"$BIN" --db "$DB" identity create --name speaker  --location host1  --secret "$SEC" > speaker.demo.id.json

say "1. genesis fail-closed: issuance is refused before a genesis exists"
if "$BIN" --db "$DB" assert grant --identity speaker.demo.id.json --secret "$SEC" \
      --claim-kind sqlite_wal_state --subject-scope 'labelwatch/*' --audience nq:main \
      --max-uses 3 2>/dev/null; then
  echo "UNEXPECTED: grant succeeded without genesis"; exit 1
else
  echo "refused (as designed): assertion issuance requires a settlement-witness"
fi

say "2. install genesis (operator fiat, the citable root)"
run "$BIN" --db "$DB" genesis install --identity operator.demo.id.json --secret "$SEC"

say "3. open a bounded assertion lease (max-uses 3)"
GRANT_OUT="$("$BIN" --db "$DB" assert grant --identity speaker.demo.id.json --secret "$SEC" \
  --claim-kind sqlite_wal_state --subject-scope 'labelwatch/*' --audience nq:main \
  --duration 3600 --max-uses 3)"
echo "$GRANT_OUT"
GID="$(echo "$GRANT_OUT" | head -1 | awk '{print $NF}')"

say "4. consumer preflight (Wicket asks: do I need assert-standing, and is it available?)"
echo "   -- PREVIEW: authorizes nothing, consumes nothing --"
"$BIN" --db "$DB" assert resolve --principal wl:speaker:host1 --consumer nq:main \
  --claim-kind sqlite_wal_state --target labelwatch/foo --effect binding \
  --id "$GID" --identity speaker.demo.id.json --secret "$SEC" \
  --subject-id labelwatch/foo --jti demo-preview --preview \
  | grep -E '"decision"|"authorizes_effect"|"decision_mode"'

say "5. consumer binds: the spend path authorizes and emits a receipt"
"$BIN" --db "$DB" assert resolve --principal wl:speaker:host1 --consumer nq:main \
  --claim-kind sqlite_wal_state --target labelwatch/foo --effect binding \
  --id "$GID" --identity speaker.demo.id.json --secret "$SEC" \
  --subject-id labelwatch/foo --jti demo-bind-1 \
  | grep -E '"decision"|"authorizes_effect"|"freshness"|"emitted_receipt_digest"'

say "6. NEGATIVE FIXTURES (the cages)"
echo "   -- replay (same jti) --"
"$BIN" --db "$DB" assert prove --id "$GID" --identity speaker.demo.id.json --secret "$SEC" \
  --claim-kind sqlite_wal_state --subject-id labelwatch/foo --audience nq:main --jti demo-bind-1 \
  2>&1 | sed 's/^/   /' || true
echo "   -- out-of-scope subject (non-consuming) --"
"$BIN" --db "$DB" assert prove --id "$GID" --identity speaker.demo.id.json --secret "$SEC" \
  --claim-kind sqlite_wal_state --subject-id other/x --audience nq:main --jti demo-oops \
  2>&1 | sed 's/^/   /' || true

say "7. incident mode: freeze the claim class, prove is denied, thaw restores"
run "$BIN" --db "$DB" policy freeze --handle demo-incident \
  --class-type claim_kind --class-value sqlite_wal_state \
  --reason "storage smoke" --identity operator.demo.id.json --secret "$SEC"
echo "   -- prove under freeze --"
"$BIN" --db "$DB" assert prove --id "$GID" --identity speaker.demo.id.json --secret "$SEC" \
  --claim-kind sqlite_wal_state --subject-id labelwatch/foo --audience nq:main --jti demo-frozen \
  2>&1 | sed 's/^/   /' || true
run "$BIN" --db "$DB" policy thaw --handle demo-incident \
  --identity operator.demo.id.json --secret "$SEC"

say "8. budget exhaustion: the lease is spent, re-witness required"
"$BIN" --db "$DB" assert prove --id "$GID" --identity speaker.demo.id.json --secret "$SEC" \
  --claim-kind sqlite_wal_state --subject-id labelwatch/bar --audience nq:main --jti demo-bind-2 \
  2>&1 | sed 's/^/   /' || true
"$BIN" --db "$DB" assert prove --id "$GID" --identity speaker.demo.id.json --secret "$SEC" \
  --claim-kind sqlite_wal_state --subject-id labelwatch/baz --audience nq:main --jti demo-bind-3 \
  2>&1 | sed 's/^/   /' || true

say "9. the receipt chain — requested -> issued(cites genesis) -> activated -> assertion_made*"
"$BIN" --db "$DB" query chain --id "$GID" | grep -iE 'requested|issued|activated|made|exhausted' | sed 's/^/   /'

say "demo complete (throwaway DB removed)"
