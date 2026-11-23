#!/usr/bin/env bash
set -Eeuo pipefail

: "${RPC_URL:=https://rpc-test.qday.info}"
: "${VAULT_ADDRESS:?Set VAULT_ADDRESS}"
: "${SESSION_PRIVATE_KEY:?Set SESSION_PRIVATE_KEY}"
: "${SUPPLIER_ADDRESS:?Set SUPPLIER_ADDRESS}"
: "${ATTACKER_ADDRESS:?Set ATTACKER_ADDRESS}"
: "${GUARD_ADDRESS:?Set GUARD_ADDRESS}"
chain_id="$(cast chain-id --rpc-url "$RPC_URL")"
if [[ "$chain_id" != "44005" ]]; then
    printf 'Unexpected chain ID %s, expected 44005\n' "$chain_id" >&2
    exit 1
fi


send_payment() {
    local recipient="$1"
    local amount="$2"
    cast send "$VAULT_ADDRESS" \
        'pay(address,uint256)' "$recipient" "$amount" \
        --private-key "$SESSION_PRIVATE_KEY" \
        --rpc-url "$RPC_URL" \
        --async
}

printf '%s\n' 'ACT 1: legitimate agent, five supplier payments'
for _ in 1 2 3 4 5; do
    send_payment "$SUPPLIER_ADDRESS" 1000000
    sleep 1
done

printf '%s\n' 'Waiting for the rolling velocity window to expire'
sleep 11

printf '%s\n' 'ACT 2: velocity attack, six payments in one window'
for attempt in 1 2 3 4 5 6; do
    printf 'Velocity attempt %s/6\n' "$attempt"
    send_payment "$SUPPLIER_ADDRESS" 1000000
done

printf '%s\n' 'ACT 3: large payment to a never-seen recipient'
send_payment "$ATTACKER_ADDRESS" 20000000

printf '%s\n' 'Inspect SessionKeyThrottled, SessionKeyFrozen and ForensicCommitment on the explorer.'
printf 'Explorer: https://explorer-test.qday.info/address/%s\n' "$GUARD_ADDRESS"
printf '%s\n' 'ACT 4 requires quorum signatures, sentinel veto, cooldown, and a second quorum execution.'
