#!/usr/bin/env bash
set -Eeuo pipefail

: "${RPC_URL:=https://rpc-test.qday.info}"
: "${VAULT_ADDRESS:?Set VAULT_ADDRESS}"
: "${SESSION_PRIVATE_KEY:?Set SESSION_PRIVATE_KEY}"
: "${SUPPLIER_ADDRESS:?Set SUPPLIER_ADDRESS}"
: "${ATTACKER_ADDRESS:?Set ATTACKER_ADDRESS}"
: "${GUARD_ADDRESS:?Set GUARD_ADDRESS}"
: "${TUSD8_ADDRESS:?Set TUSD8_ADDRESS}"
: "${STARTING_INTENT_NONCE:=0}"

if [[ "${SUPPLIER_ADDRESS,,}" == "${ATTACKER_ADDRESS,,}" ]]; then
    printf '%s\n' 'Supplier and attacker addresses must be distinct for the novelty demonstration' >&2
    exit 1
fi

chain_id="$(cast chain-id --rpc-url "$RPC_URL")"
if [[ "$chain_id" != "44005" ]]; then
    printf 'Unexpected chain ID %s, expected 44005\n' "$chain_id" >&2
    exit 1
fi
INTENT_TYPEHASH="$(cast keccak 'PaymentIntent(address vault,uint256 chainId,address sessionKey,address recipient,uint256 amount,bytes32 purposeHash,uint256 nonce,uint256 expiry)')"
: "${PURPOSE_HASH:=$(cast keccak 'aevumaegis:demo-invoice')}"

CONFIGURED_VAULT="$(cast call "$GUARD_ADDRESS" 'vault()(address)' --rpc-url "$RPC_URL")"
if [[ "${CONFIGURED_VAULT,,}" != "${VAULT_ADDRESS,,}" ]]; then
    printf 'GuardModule is bound to %s, not %s\n' "$CONFIGURED_VAULT" "$VAULT_ADDRESS" >&2
    exit 1
fi
configured_token="$(cast call "$VAULT_ADDRESS" 'token()(address)' --rpc-url "$RPC_URL")"
if [[ "${configured_token,,}" != "${TUSD8_ADDRESS,,}" ]]; then
    printf 'Vault is bound to token %s, not configured tUSD8 %s\n' \
        "$configured_token" "$TUSD8_ADDRESS" >&2
    exit 1
fi
SESSION_KEY_ADDRESS="$(cast wallet address --private-key "$SESSION_PRIVATE_KEY")"
CONFIGURED_SESSION_KEY="$(cast call "$VAULT_ADDRESS" 'sessionKey()(address)' --rpc-url "$RPC_URL")"
if [[ "${SESSION_KEY_ADDRESS,,}" != "${CONFIGURED_SESSION_KEY,,}" ]]; then
    printf 'Session key mismatch: vault expects %s, supplied signer is %s\n' \
        "$CONFIGURED_SESSION_KEY" "$SESSION_KEY_ADDRESS" >&2
    exit 1
fi
session_state="$(cast call "$GUARD_ADDRESS" 'getSessionState(address)(uint8)' "$SESSION_KEY_ADDRESS" --rpc-url "$RPC_URL")"
session_state="$(cast to-dec "$session_state")"
if [[ "$session_state" != "0" ]]; then
    printf 'Demo requires an ACTIVE session; current state is %s\n' "$session_state" >&2
    exit 1
fi
action_count="$(cast call "$GUARD_ADDRESS" 'getActionCount(address)(uint256)' "$SESSION_KEY_ADDRESS" --rpc-url "$RPC_URL")"
if [[ "$action_count" != "0" ]]; then
    printf 'Demo requires a fresh session with zero actions; action count is %s\n' "$action_count" >&2
    exit 1
fi
for recipient in "$SUPPLIER_ADDRESS" "$ATTACKER_ADDRESS"; do
    is_authorized="$(cast call "$GUARD_ADDRESS" 'authorizedRecipient(address)(bool)' "$recipient" --rpc-url "$RPC_URL")"
    if [[ "$is_authorized" != "true" ]]; then
        printf 'Recipient %s is not governance-authorized\n' "$recipient" >&2
        exit 1
    fi
    purpose_authorized="$(cast call "$GUARD_ADDRESS" 'authorizedPurposeHash(address,bytes32)(bool)' \
        "$recipient" "$PURPOSE_HASH" --rpc-url "$RPC_URL")"
    purpose_max_amount="$(cast call "$GUARD_ADDRESS" 'authorizedPurposeAmount(address,bytes32)(uint256)' \
        "$recipient" "$PURPOSE_HASH" --rpc-url "$RPC_URL")"
    if [[ "$purpose_authorized" != "true" ]]; then
        printf 'Purpose %s is not authorized for recipient %s\n' "$PURPOSE_HASH" "$recipient" >&2
        exit 1
    fi
    required_amount=1000000
    if [[ "${recipient,,}" == "${ATTACKER_ADDRESS,,}" ]]; then
        required_amount=20000000
    fi
    if (( purpose_max_amount < required_amount )); then
        printf 'Purpose cap %s is below required demo amount %s for %s\n' \
            "$purpose_max_amount" "$required_amount" "$recipient" >&2
        exit 1
    fi
done
for nonce_offset in {0..11}; do
    candidate_nonce="$((STARTING_INTENT_NONCE + nonce_offset))"
    if [[ "$(cast call "$GUARD_ADDRESS" 'usedIntentNonce(address,uint256)(bool)' \
        "$SESSION_KEY_ADDRESS" "$candidate_nonce" --rpc-url "$RPC_URL")" == "true" ]]; then
        printf 'Demo intent nonce %s has already been used\n' "$candidate_nonce" >&2
        exit 1
    fi
done
vault_balance="$(cast call "$TUSD8_ADDRESS" 'balanceOf(address)(uint256)' "$VAULT_ADDRESS" --rpc-url "$RPC_URL")"
if (( vault_balance < 8000000 )); then
    printf 'Vault needs at least 8000000 base units for the legitimate demo and velocity payments; balance is %s\n' \
        "$vault_balance" >&2
    exit 1
fi
INTENT_NONCE="$STARTING_INTENT_NONCE"

send_payment() {
    local recipient="$1"
    local amount="$2"
    local payment_nonce="${3:-$INTENT_NONCE}"
    local transaction_nonce="${4:-}"
    local chain_timestamp expiry encoded digest signature intent
    local -a transaction_options=()
    chain_timestamp="$(cast block latest --field timestamp --rpc-url "$RPC_URL")"
    chain_timestamp="$(cast to-dec "$chain_timestamp")"
    expiry="$(($chain_timestamp + 86400))"
    encoded="$(cast abi-encode \
        'f(bytes32,address,uint256,address,address,uint256,bytes32,uint256,uint256)' \
        "$INTENT_TYPEHASH" "$VAULT_ADDRESS" 44005 "$SESSION_KEY_ADDRESS" \
        "$recipient" "$amount" "$PURPOSE_HASH" "$payment_nonce" "$expiry")"
    digest="$(cast keccak "$encoded")"
    signature="$(cast wallet sign --no-hash "$digest" --private-key "$SESSION_PRIVATE_KEY")"
    intent="($recipient,$amount,$PURPOSE_HASH,$payment_nonce,$expiry)"
    if [[ -n "$transaction_nonce" ]]; then
        transaction_options+=(--nonce "$transaction_nonce")
    fi
    cast send "$VAULT_ADDRESS" \
        'pay((address,uint256,bytes32,uint256,uint256),bytes)' \
        "$intent" "$signature" \
        --private-key "$SESSION_PRIVATE_KEY" \
        --rpc-url "$RPC_URL" \
        "${transaction_options[@]}"
    if [[ $# -lt 3 ]]; then
        INTENT_NONCE="$((INTENT_NONCE + 1))"
    fi
}

printf '%s\n' 'ACT 1: legitimate agent, five supplier payments'
for _ in 1 2 3 4 5; do
    send_payment "$SUPPLIER_ADDRESS" 1000000
    sleep 4
done

printf '%s\n' 'Waiting for the rolling velocity window to expire'
sleep 11

printf '%s\n' 'ACT 2: six attempts planned; the guard should stop the burst on attempt four'
supplier_balance_before_velocity="$(cast call "$TUSD8_ADDRESS" 'balanceOf(address)(uint256)' "$SUPPLIER_ADDRESS" --rpc-url "$RPC_URL")"
transaction_nonce="$(cast nonce "$SESSION_KEY_ADDRESS" --block pending --rpc-url "$RPC_URL")"
transaction_pids=()
for attempt in 1 2 3 4; do
    printf 'Velocity attempt %s/6\n' "$attempt"
    payment_nonce="$INTENT_NONCE"
    INTENT_NONCE="$((INTENT_NONCE + 1))"
    send_payment "$SUPPLIER_ADDRESS" 1000000 "$payment_nonce" "$transaction_nonce" &
    transaction_pids+=("$!")
    transaction_nonce="$((transaction_nonce + 1))"
done
for transaction_pid in "${transaction_pids[@]}"; do
    wait "$transaction_pid"
done
supplier_balance_after_velocity="$(cast call "$TUSD8_ADDRESS" 'balanceOf(address)(uint256)' "$SUPPLIER_ADDRESS" --rpc-url "$RPC_URL")"
expected_supplier_balance="$((supplier_balance_before_velocity + 3000000))"
if (( supplier_balance_after_velocity != expected_supplier_balance )); then
    printf 'Velocity precondition failed: expected supplier balance %s, got %s\n' \
        "$expected_supplier_balance" "$supplier_balance_after_velocity" >&2
    exit 1
fi
session_state="$(cast call "$GUARD_ADDRESS" 'getSessionState(address)(uint8)' "$SESSION_KEY_ADDRESS" --rpc-url "$RPC_URL")"
session_state="$(cast to-dec "$session_state")"
if [[ "$session_state" != "1" ]]; then
    printf 'Expected THROTTLED state (1) after the fourth attempt, got %s\n' "$session_state" >&2
    exit 1
fi

printf '%s\n' 'ACT 3: large payment to a never-seen, pre-authorized recipient'
attacker_balance_before="$(cast call "$TUSD8_ADDRESS" 'balanceOf(address)(uint256)' "$ATTACKER_ADDRESS" --rpc-url "$RPC_URL")"
send_payment "$ATTACKER_ADDRESS" 20000000
attacker_balance_after="$(cast call "$TUSD8_ADDRESS" 'balanceOf(address)(uint256)' "$ATTACKER_ADDRESS" --rpc-url "$RPC_URL")"
if [[ "$attacker_balance_before" != "$attacker_balance_after" ]]; then
    printf 'SECURITY FAILURE: attacker balance changed from %s to %s\n' \
        "$attacker_balance_before" "$attacker_balance_after" >&2
    exit 1
fi
session_state="$(cast call "$GUARD_ADDRESS" 'getSessionState(address)(uint8)' "$SESSION_KEY_ADDRESS" --rpc-url "$RPC_URL")"
session_state="$(cast to-dec "$session_state")"
if [[ "$session_state" != "2" ]]; then
    printf 'Expected FROZEN state (2), got %s\n' "$session_state" >&2
    exit 1
fi
forensic_hash="$(cast call "$GUARD_ADDRESS" 'getFinalForensicHash(address)(bytes32)' "$SESSION_KEY_ADDRESS" --rpc-url "$RPC_URL")"
if [[ "${forensic_hash,,}" == "0x0000000000000000000000000000000000000000000000000000000000000000" ]]; then
    printf '%s\n' 'SECURITY FAILURE: no forensic commitment was stored' >&2
    exit 1
fi
printf 'Verified frozen state and unchanged attacker balance. Forensic commitment: %s\n' "$forensic_hash"

printf '%s\n' 'Inspect SessionKeyThrottled, SessionKeyFrozen and ForensicCommitment on the explorer.'
printf 'Explorer: https://explorer-test.qday.info/address/%s\n' "$GUARD_ADDRESS"
printf '%s\n' 'ACT 4 requires quorum signatures, sentinel veto, cooldown, and a second quorum execution.'
