#!/usr/bin/env bash
set -Eeuo pipefail

: "${GUARD_ADDRESS:?Set GUARD_ADDRESS}"
: "${VAULT_ADDRESS:?Set VAULT_ADDRESS}"
: "${SESSION_KEY:?Set SESSION_KEY}"
: "${EXPECTED_FORENSIC_HASH:?Set EXPECTED_FORENSIC_HASH}"
: "${FROM_BLOCK:?Set FROM_BLOCK to the GuardModule deployment block}"
: "${RPC_URL:=https://rpc-test.qday.info}"
: "${ACTION_LOG:=actions.jsonl}"
: "${TAMPERED_LOG:=actions.tampered.jsonl}"

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root/rust"

printf '%s\n' 'ACT F1A: export and verify the authentic on-chain event history'
cargo run --release -p aevumaegis-forensic-verifier -- export \
    --rpc-url "$RPC_URL" \
    --guard-address "$GUARD_ADDRESS" \
    --vault-address "$VAULT_ADDRESS" \
    --session-key "$SESSION_KEY" \
    --from-block "$FROM_BLOCK" \
    --output "$ACTION_LOG" \
    --expected-hash "$EXPECTED_FORENSIC_HASH"

printf '%s\n' 'ACT F1B: flip one byte in the first recorded action hash'
python3 - "$ACTION_LOG" "$TAMPERED_LOG" <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as handle:
    lines = handle.readlines()
if not lines:
    raise SystemExit("The authentic action log is empty")
record = json.loads(lines[0])
hash_value = record["action_hash"]
last_byte = hash_value[-2:]
record["action_hash"] = hash_value[:-2] + ("00" if last_byte != "00" else "01")
lines[0] = json.dumps(record, separators=(",", ":")) + "\n"
with open(destination, "w", encoding="utf-8") as handle:
    handle.writelines(lines)
PY

if cargo run --release -p aevumaegis-forensic-verifier -- verify \
    --log "$TAMPERED_LOG" \
    --expected-hash "$EXPECTED_FORENSIC_HASH"; then
    printf '%s\n' 'ERROR: tampered forensic log unexpectedly passed verification' >&2
    exit 1
fi

printf '%s\n' 'PASS: authentic log verified and tampered log rejected'
