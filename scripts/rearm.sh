#!/usr/bin/env bash
set -Eeuo pipefail

: "${RPC_URL:=https://rpc-test.qday.info}"
: "${GUARD_ADDRESS:?Set GUARD_ADDRESS}"
: "${VAULT_ADDRESS:?Set VAULT_ADDRESS}"
: "${OWNER_ONE_PRIVATE_KEY:=${DEPLOYER_PRIVATE_KEY:-}}"
: "${OWNER_ONE_PRIVATE_KEY:?Set OWNER_ONE_PRIVATE_KEY or DEPLOYER_PRIVATE_KEY}"
: "${OWNER_TWO_PRIVATE_KEY:?Set OWNER_TWO_PRIVATE_KEY}"
: "${SENTINEL_PRIVATE_KEY:?Set SENTINEL_PRIVATE_KEY}"
: "${NEW_SESSION_PRIVATE_KEY:?Set NEW_SESSION_PRIVATE_KEY}"
: "${SUPPLIER_ADDRESS:?Set SUPPLIER_ADDRESS}"
: "${PAYMENT_AMOUNT:=1000000}"
: "${COOLDOWN_SECONDS:=86400}"

chain_id="$(cast chain-id --rpc-url "$RPC_URL")"
if [[ "$chain_id" != "44005" ]]; then
    printf 'Unexpected chain ID %s, expected 44005\n' "$chain_id" >&2
    exit 1
fi

new_session_key="$(cast wallet address --private-key "$NEW_SESSION_PRIVATE_KEY")"
owner_one="$(cast wallet address --private-key "$OWNER_ONE_PRIVATE_KEY")"
owner_two="$(cast wallet address --private-key "$OWNER_TWO_PRIVATE_KEY")"
sentinel="$(cast wallet address --private-key "$SENTINEL_PRIVATE_KEY")"
printf 'Replacement session key: %s\n' "$new_session_key"
printf 'Quorum signers: %s, %s\n' "$owner_one" "$owner_two"
printf 'Sentinel: %s\n' "$sentinel"

unfreeze_digest() {
    local nonce="$1"
    local requested_at="$2"
    local encoded
    encoded="$(cast abi-encode \
        'f(address,uint256,string,uint256,uint256,address)' \
        "$GUARD_ADDRESS" 44005 AEVUMAEGIS_UNFREEZE "$nonce" "$requested_at" "$new_session_key")"
    cast keccak "$encoded"
}

sign_digest() {
    local digest="$1"
    local private_key="$2"
    cast wallet sign --no-hash "$digest" --private-key "$private_key"
}

submit_request() {
    local nonce="$1"
    local requested_at="$2"
    local digest signature_one signature_two
    digest="$(unfreeze_digest "$nonce" "$requested_at")"
    signature_one="$(sign_digest "$digest" "$OWNER_ONE_PRIVATE_KEY")"
    signature_two="$(sign_digest "$digest" "$OWNER_TWO_PRIVATE_KEY")"
    cast send "$GUARD_ADDRESS" \
        'requestUnfreeze(address,bytes[])' \
        "$new_session_key" "[$signature_one,$signature_two]" \
        --private-key "$OWNER_ONE_PRIVATE_KEY" \
        --rpc-url "$RPC_URL"
}

printf '%s\n' 'ACT 4A: owners request re-arm, sentinel vetoes the first request'
nonce="$(cast call "$GUARD_ADDRESS" 'governanceNonce()(uint256)' --rpc-url "$RPC_URL")"
requested_at="$(cast call "$GUARD_ADDRESS" 'unfreezeRequestedAt()(uint256)' --rpc-url "$RPC_URL")"
submit_request "$nonce" "$requested_at"
cast send "$GUARD_ADDRESS" 'vetoUnfreeze()' \
    --private-key "$SENTINEL_PRIVATE_KEY" --rpc-url "$RPC_URL"

printf '%s\n' 'ACT 4B: owners submit a fresh request after the veto'
nonce="$(cast call "$GUARD_ADDRESS" 'governanceNonce()(uint256)' --rpc-url "$RPC_URL")"
requested_at="$(cast call "$GUARD_ADDRESS" 'unfreezeRequestedAt()(uint256)' --rpc-url "$RPC_URL")"
submit_request "$nonce" "$requested_at"

printf 'Waiting %s seconds for the on-chain cooldown\n' "$COOLDOWN_SECONDS"
sleep "$COOLDOWN_SECONDS"
cast send "$GUARD_ADDRESS" 'executeUnfreeze()' \
    --private-key "$OWNER_ONE_PRIVATE_KEY" --rpc-url "$RPC_URL"

printf '%s\n' 'ACT 4C: the replacement session key makes a small payment'
cast send "$VAULT_ADDRESS" 'pay(address,uint256)' \
    "$SUPPLIER_ADDRESS" "$PAYMENT_AMOUNT" \
    --private-key "$NEW_SESSION_PRIVATE_KEY" \
    --rpc-url "$RPC_URL"
printf 'Inspect UnfreezeRequested, UnfreezeVetoed, UnfreezeExecuted and PaymentExecuted for %s\n' "$GUARD_ADDRESS"
