#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

sources=(
  crates/standing-continuity/src
  crates/standing-store/src/continuity.rs
)

if rg -n '(ag[_-]|docket|nightshift)::|use[[:space:]]+(ag[_-]|docket|nightshift)' "${sources[@]}"; then
  echo "continuity authority boundary imports a downstream authority/runtime owner" >&2
  exit 1
fi

if rg -n '(current_substrate|hostname|dns_name|ip_address|continuity_authorized[[:space:]]*:[[:space:]]*bool)' "${sources[@]}"; then
  echo "continuity authority boundary contains a forbidden inferred/mutable shortcut" >&2
  exit 1
fi

if rg -n '(issued_at|committed_at)[[:space:]]*(<|>|<=|>=)|(observed_at)[[:space:]]*(<|>|<=|>=)' "${sources[@]}"; then
  echo "continuity authority boundary attempts timestamp-only causal ordering" >&2
  exit 1
fi

rg -q 'enum ContinuityRelationV1' crates/standing-continuity/src/lib.rs
rg -q 'SubstrateIncarnation' crates/standing-continuity/src/lib.rs
rg -q 'transaction_with_behavior\(TransactionBehavior::Immediate\)' \
  crates/standing-store/src/continuity.rs
rg -q 'ContinuityAcquisitionCommitted' crates/standing-store/src/continuity.rs
rg -q 'Ed25519' docs/continuity-authority-carrier.md

echo "continuity authority boundary: PASS"
