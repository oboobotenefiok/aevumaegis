#!/usr/bin/env bash
set -Eeuo pipefail

: "${RPC_URL:=https://rpc-test.qday.info}"
: "${GUARD_ADDRESS:?Set GUARD_ADDRESS}"
: "${RECIPIENT_ADDRESS:?Set RECIPIENT_ADDRESS}"
: "${OWNER_ONE_PRIVATE_KEY:=${DEPLOYER_PRIVATE_KEY:-}}"
: "${OWNER_ONE_PRIVATE_KEY:?Set OWNER_ONE_PRIVATE_KEY or DEPLOYER_PRIVATE_KEY}"
: "${OWNER_TWO_PRIVATE_KEY:?Set OWNER_TWO_PRIVATE_KEY}"
: "${AUTHORIZED:=true}"
: "${PURPOSE_HASH:=$(cast keccak 'aevumaegis:demo-invoice')}"
: "${PURPOSE_MAX_AMOUNT:=1000000}"
if [[ "$AUTHORIZED" != "true" && "$AUTHORIZED" != "false" ]]; then
    printf '%s\n' 'AUTHORIZED must be true or false' >&2
    exit 1
fi
if [[ "$AUTHORIZED" == "false" ]]; then
    PURPOSE_MAX_AMOUNT=0
elif (( PURPOSE_MAX_AMOUNT <= 0 || PURPOSE_MAX_AMOUNT > 1000000000000000000 )); then
    printf '%s\n' 'PURPOSE_MAX_AMOUNT must be between 1 and 1e18 base units' >&2
    exit 1
fi

chain_id="$(cast chain-id --rpc-url "$RPC_URL")"
if [[ "$chain_id" != "44005" ]]; then
    printf 'Unexpected chain ID %s, expected 44005\n' "$chain_id" >&2
    exit 1
fi

owner_one="$(cast wallet address --private-key "$OWNER_ONE_PRIVATE_KEY")"
owner_two="$(cast wallet address --private-key "$OWNER_TWO_PRIVATE_KEY")"
if [[ "${owner_one,,}" == "${owner_two,,}" ]]; then
    printf '%s\n' 'Recipient authorization requires two distinct owner keys' >&2
    exit 1
fi
for signer_address in "$owner_one" "$owner_two"; do
    is_owner="$(cast call "$GUARD_ADDRESS" 'isOwner(address)(bool)' "$signer_address" --rpc-url "$RPC_URL")"
    if [[ "$is_owner" != "true" ]]; then
        printf 'Address %s is not a configured owner\n' "$signer_address" >&2
        exit 1
    fi
done

nonce="$(cast call "$GUARD_ADDRESS" 'governanceNonce()(uint256)' --rpc-url "$RPC_URL")"
encoded="$(cast abi-encode \
    'f(address,uint256,string,uint256,address,bool)' \
    "$GUARD_ADDRESS" 44005 AEVUMAEGIS_RECIPIENT "$nonce" "$RECIPIENT_ADDRESS" "$AUTHORIZED")"
digest="$(cast keccak "$encoded")"
signature_one="$(cast wallet sign --no-hash "$digest" --private-key "$OWNER_ONE_PRIVATE_KEY")"
signature_two="$(cast wallet sign --no-hash "$digest" --private-key "$OWNER_TWO_PRIVATE_KEY")"

cast send "$GUARD_ADDRESS" \
    'setRecipientAuthorization(address,bool,bytes[])' \
    "$RECIPIENT_ADDRESS" "$AUTHORIZED" "[$signature_one,$signature_two]" \
    --private-key "$OWNER_ONE_PRIVATE_KEY" \
    --rpc-url "$RPC_URL"
actual_authorization="$(cast call "$GUARD_ADDRESS" 'authorizedRecipient(address)(bool)' \
    "$RECIPIENT_ADDRESS" --rpc-url "$RPC_URL")"
if [[ "$actual_authorization" != "$AUTHORIZED" ]]; then
    printf 'Authorization postcondition failed: expected %s, got %s\n' \
        "$AUTHORIZED" "$actual_authorization" >&2
    exit 1
fi

purpose_nonce="$(cast call "$GUARD_ADDRESS" 'governanceNonce()(uint256)' --rpc-url "$RPC_URL")"
purpose_encoded="$(cast abi-encode \
    'f(address,uint256,string,uint256,address,bytes32,uint256,bool)' \
    "$GUARD_ADDRESS" 44005 AEVUMAEGIS_PURPOSE "$purpose_nonce" \
    "$RECIPIENT_ADDRESS" "$PURPOSE_HASH" "$PURPOSE_MAX_AMOUNT" "$AUTHORIZED")"
purpose_digest="$(cast keccak "$purpose_encoded")"
purpose_signature_one="$(cast wallet sign --no-hash "$purpose_digest" --private-key "$OWNER_ONE_PRIVATE_KEY")"
purpose_signature_two="$(cast wallet sign --no-hash "$purpose_digest" --private-key "$OWNER_TWO_PRIVATE_KEY")"
cast send "$GUARD_ADDRESS" \
    'setPurposeAuthorization(address,bytes32,uint256,bool,bytes[])' \
    "$RECIPIENT_ADDRESS" "$PURPOSE_HASH" "$PURPOSE_MAX_AMOUNT" "$AUTHORIZED" \
    "[$purpose_signature_one,$purpose_signature_two]" \
    --private-key "$OWNER_ONE_PRIVATE_KEY" \
    --rpc-url "$RPC_URL"
actual_purpose_authorization="$(cast call "$GUARD_ADDRESS" 'authorizedPurposeHash(address,bytes32)(bool)' \
    "$RECIPIENT_ADDRESS" "$PURPOSE_HASH" --rpc-url "$RPC_URL")"
actual_purpose_amount="$(cast call "$GUARD_ADDRESS" 'authorizedPurposeAmount(address,bytes32)(uint256)' \
    "$RECIPIENT_ADDRESS" "$PURPOSE_HASH" --rpc-url "$RPC_URL")"
expected_purpose_amount="$PURPOSE_MAX_AMOUNT"
if [[ "$AUTHORIZED" == "false" ]]; then
    expected_purpose_amount=0
fi
if [[ "$actual_purpose_authorization" != "$AUTHORIZED" || "$actual_purpose_amount" != "$expected_purpose_amount" ]]; then
    printf 'Purpose authorization postcondition failed: expected %s/%s, got %s/%s\n' \
        "$AUTHORIZED" "$expected_purpose_amount" "$actual_purpose_authorization" "$actual_purpose_amount" >&2
    exit 1
fi

printf 'Recipient %s and purpose %s authorization updated: %s, max amount %s\n' \
    "$RECIPIENT_ADDRESS" "$PURPOSE_HASH" "$AUTHORIZED" "$expected_purpose_amount"
