#!/usr/bin/env bash
set -Eeuo pipefail

: "${RPC_URL:=https://rpc-test.qday.info}"
: "${GUARD_ADDRESS:?Set GUARD_ADDRESS}"
: "${VAULT_ADDRESS:?Set VAULT_ADDRESS}"
: "${TUSD8_ADDRESS:?Set TUSD8_ADDRESS}"
: "${OWNER_ONE_PRIVATE_KEY:=${DEPLOYER_PRIVATE_KEY:-}}"
: "${OWNER_ONE_PRIVATE_KEY:?Set OWNER_ONE_PRIVATE_KEY or DEPLOYER_PRIVATE_KEY}"
: "${OWNER_TWO_PRIVATE_KEY:?Set OWNER_TWO_PRIVATE_KEY}"
: "${SENTINEL_PRIVATE_KEY:?Set SENTINEL_PRIVATE_KEY}"
: "${NEW_SESSION_PRIVATE_KEY:?Set NEW_SESSION_PRIVATE_KEY}"
: "${SUPPLIER_ADDRESS:?Set SUPPLIER_ADDRESS}"
: "${PAYMENT_AMOUNT:=1000000}"
: "${COOLDOWN_SECONDS:=}"
: "${STARTING_INTENT_NONCE:=0}"
: "${PURPOSE_HASH:=$(cast keccak 'aevumaegis:demo-invoice')}"

chain_id="$(cast chain-id --rpc-url "$RPC_URL")"
if [[ "$chain_id" != "44005" ]]; then
    printf 'Unexpected chain ID %s, expected 44005\n' "$chain_id" >&2
    exit 1
fi
onchain_cooldown="$(cast call "$GUARD_ADDRESS" 'unfreezeCooldown()(uint256)' --rpc-url "$RPC_URL")"
onchain_cooldown="$(cast to-dec "$onchain_cooldown")"
if [[ -n "$COOLDOWN_SECONDS" && "$COOLDOWN_SECONDS" != "$onchain_cooldown" ]]; then
    printf 'Configured cooldown %s does not match on-chain cooldown %s\n' \
        "$COOLDOWN_SECONDS" "$onchain_cooldown" >&2
    exit 1
fi
COOLDOWN_SECONDS="$onchain_cooldown"

new_session_key="$(cast wallet address --private-key "$NEW_SESSION_PRIVATE_KEY")"
owner_one="$(cast wallet address --private-key "$OWNER_ONE_PRIVATE_KEY")"
owner_two="$(cast wallet address --private-key "$OWNER_TWO_PRIVATE_KEY")"
sentinel="$(cast wallet address --private-key "$SENTINEL_PRIVATE_KEY")"
configured_vault="$(cast call "$GUARD_ADDRESS" 'vault()(address)' --rpc-url "$RPC_URL")"
configured_sentinel="$(cast call "$GUARD_ADDRESS" 'sentinel()(address)' --rpc-url "$RPC_URL")"
if [[ "${configured_vault,,}" != "${VAULT_ADDRESS,,}" ]]; then
    printf 'GuardModule is bound to %s, not %s\n' "$configured_vault" "$VAULT_ADDRESS" >&2
    exit 1
fi
if [[ "${configured_sentinel,,}" != "${sentinel,,}" ]]; then
    printf 'Sentinel mismatch: guard expects %s, supplied signer is %s\n' \
        "$configured_sentinel" "$sentinel" >&2
    exit 1
fi
if [[ "${owner_one,,}" == "${owner_two,,}" || "${owner_one,,}" == "${sentinel,,}" || "${owner_two,,}" == "${sentinel,,}" ]]; then
    printf '%s\n' 'Owner and sentinel keys must be distinct' >&2
    exit 1
fi
for signer_address in "$owner_one" "$owner_two"; do
    is_owner="$(cast call "$GUARD_ADDRESS" 'isOwner(address)(bool)' "$signer_address" --rpc-url "$RPC_URL")"
    if [[ "$is_owner" != "true" ]]; then
        printf 'Address %s is not a configured owner\n' "$signer_address" >&2
        exit 1
    fi
done
current_session_key="$(cast call "$VAULT_ADDRESS" 'sessionKey()(address)' --rpc-url "$RPC_URL")"
if [[ "${new_session_key,,}" == "${current_session_key,,}" ]]; then
    printf '%s\n' 'Replacement session key must differ from the frozen key' >&2
    exit 1
fi
if [[ "$(cast call "$GUARD_ADDRESS" 'usedSessionKeys(address)(bool)' "$new_session_key" --rpc-url "$RPC_URL")" == "true" ]]; then
    printf '%s\n' 'Replacement session key has already been used' >&2
    exit 1
fi
if [[ "$(cast call "$GUARD_ADDRESS" 'isOwner(address)(bool)' "$new_session_key" --rpc-url "$RPC_URL")" == "true" || "${new_session_key,,}" == "${sentinel,,}" ]]; then
    printf '%s\n' 'Replacement session key cannot be an owner or sentinel' >&2
    exit 1
fi
current_state="$(cast call "$GUARD_ADDRESS" 'getSessionState(address)(uint8)' "$current_session_key" --rpc-url "$RPC_URL")"
current_state="$(cast to-dec "$current_state")"
if [[ "$current_state" != "2" ]]; then
    printf 'Current session is not frozen; state is %s\n' "$current_state" >&2
    exit 1
fi
if [[ "$(cast call "$GUARD_ADDRESS" 'unfreezePending()(bool)' --rpc-url "$RPC_URL")" != "false" ]]; then
    printf '%s\n' 'An unfreeze request is already pending; inspect it before starting another re-arm sequence' >&2
    exit 1
fi
new_session_code="$(cast code "$new_session_key" --rpc-url "$RPC_URL")"
if [[ "$new_session_code" != "0x" ]]; then
    printf '%s\n' 'Replacement session key must be an EOA with no contract code' >&2
    exit 1
fi
if [[ "$(cast call "$GUARD_ADDRESS" 'authorizedRecipient(address)(bool)' "$SUPPLIER_ADDRESS" --rpc-url "$RPC_URL")" != "true" ]]; then
    printf 'Supplier %s is not governance-authorized\n' "$SUPPLIER_ADDRESS" >&2
    exit 1
fi
if [[ "$(cast call "$GUARD_ADDRESS" 'authorizedPurposeHash(address,bytes32)(bool)' \
    "$SUPPLIER_ADDRESS" "$PURPOSE_HASH" --rpc-url "$RPC_URL")" != "true" ]]; then
    printf 'Purpose %s is not authorized for supplier %s\n' "$PURPOSE_HASH" "$SUPPLIER_ADDRESS" >&2
    exit 1
fi
supplier_purpose_cap="$(cast call "$GUARD_ADDRESS" 'authorizedPurposeAmount(address,bytes32)(uint256)' \
    "$SUPPLIER_ADDRESS" "$PURPOSE_HASH" --rpc-url "$RPC_URL")"
if (( supplier_purpose_cap < PAYMENT_AMOUNT )); then
    printf 'Purpose cap %s is below re-arm payment amount %s\n' \
        "$supplier_purpose_cap" "$PAYMENT_AMOUNT" >&2
    exit 1
fi
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
if [[ "$(cast call "$GUARD_ADDRESS" 'unfreezePending()(bool)' --rpc-url "$RPC_URL")" != "false" ]]; then
    printf '%s\n' 'Sentinel veto did not clear the pending request' >&2
    exit 1
fi

printf '%s\n' 'ACT 4B: owners submit a fresh request after the veto'
nonce="$(cast call "$GUARD_ADDRESS" 'governanceNonce()(uint256)' --rpc-url "$RPC_URL")"
requested_at="$(cast call "$GUARD_ADDRESS" 'unfreezeRequestedAt()(uint256)' --rpc-url "$RPC_URL")"
submit_request "$nonce" "$requested_at"
if [[ "$(cast call "$GUARD_ADDRESS" 'unfreezePending()(bool)' --rpc-url "$RPC_URL")" != "true" ]]; then
    printf '%s\n' 'Second quorum request was not registered' >&2
    exit 1
fi

printf 'Waiting %s seconds for the on-chain cooldown\n' "$COOLDOWN_SECONDS"
sleep "$COOLDOWN_SECONDS"
cast send "$GUARD_ADDRESS" 'executeUnfreeze()' \
    --private-key "$OWNER_ONE_PRIVATE_KEY" --rpc-url "$RPC_URL"

printf '%s\n' 'ACT 4C: the replacement session key makes a signed-intent payment'
new_session_address="$new_session_key"
intent_typehash="$(cast keccak 'PaymentIntent(address vault,uint256 chainId,address sessionKey,address recipient,uint256 amount,bytes32 purposeHash,uint256 nonce,uint256 expiry)')"
purpose_hash="$PURPOSE_HASH"
chain_timestamp="$(cast block latest --field timestamp --rpc-url "$RPC_URL")"
chain_timestamp="$(cast to-dec "$chain_timestamp")"
expiry="$(($chain_timestamp + 86400))"
encoded="$(cast abi-encode \
    'f(bytes32,address,uint256,address,address,uint256,bytes32,uint256,uint256)' \
    "$intent_typehash" "$VAULT_ADDRESS" 44005 "$new_session_address" \
    "$SUPPLIER_ADDRESS" "$PAYMENT_AMOUNT" "$purpose_hash" "$STARTING_INTENT_NONCE" "$expiry")"
intent_digest="$(cast keccak "$encoded")"
intent_signature="$(cast wallet sign --no-hash "$intent_digest" --private-key "$NEW_SESSION_PRIVATE_KEY")"
intent="($SUPPLIER_ADDRESS,$PAYMENT_AMOUNT,$purpose_hash,$STARTING_INTENT_NONCE,$expiry)"
configured_session_key="$(cast call "$VAULT_ADDRESS" 'sessionKey()(address)' --rpc-url "$RPC_URL")"
if [[ "${configured_session_key,,}" != "${new_session_address,,}" ]]; then
    printf 'Session rotation mismatch: vault expects %s, requested %s\n' \
        "$configured_session_key" "$new_session_address" >&2
    exit 1
fi
old_session_state="$(cast call "$GUARD_ADDRESS" 'getSessionState(address)(uint8)' \
    "$current_session_key" --rpc-url "$RPC_URL")"
old_session_state="$(cast to-dec "$old_session_state")"
if [[ "$old_session_state" != "2" ]]; then
    printf 'Historical session state changed unexpectedly: %s\n' "$old_session_state" >&2
    exit 1
fi
supplier_balance_before="$(cast call "$TUSD8_ADDRESS" 'balanceOf(address)(uint256)' "$SUPPLIER_ADDRESS" --rpc-url "$RPC_URL")"
cast send "$VAULT_ADDRESS" \
    'pay((address,uint256,bytes32,uint256,uint256),bytes)' \
    "$intent" "$intent_signature" \
    --private-key "$NEW_SESSION_PRIVATE_KEY" \
    --rpc-url "$RPC_URL"
supplier_balance_after="$(cast call "$TUSD8_ADDRESS" 'balanceOf(address)(uint256)' "$SUPPLIER_ADDRESS" --rpc-url "$RPC_URL")"
if [[ "$supplier_balance_after" -le "$supplier_balance_before" ]]; then
    printf '%s\n' 'Replacement session payment did not transfer tokens' >&2
    exit 1
fi
new_session_state="$(cast call "$GUARD_ADDRESS" 'getSessionState(address)(uint8)' "$new_session_key" --rpc-url "$RPC_URL")"
new_session_state="$(cast to-dec "$new_session_state")"
if [[ "$new_session_state" != "0" ]]; then
    printf 'Replacement session did not remain ACTIVE; state is %s\n' "$new_session_state" >&2
    exit 1
fi
printf 'Re-armed session key %s and verified its first payment.\n' "$new_session_key"
printf 'Inspect UnfreezeRequested, UnfreezeVetoed, UnfreezeExecuted and PaymentExecuted for %s\n' "$GUARD_ADDRESS"
