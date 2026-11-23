# Aevumaegis

A governed, tamper-evident behavioral circuit breaker for AI-agent stablecoin payments on Aevum.

> The freeze is the kill switch. The hash chain is the black box that survives it.

## 1. Threat model

An autonomous agent receives a delegated session key so it can make routine stablecoin payments without asking a human to sign every transaction. If the agent host is compromised, an attacker can use that key to drain the wallet through otherwise valid ERC-20 transfers.

A spending cap alone is an incomplete control. A fixed cap can be too restrictive for a legitimate payment schedule and still permit a compromised key to make many smaller payments. Aevumaegis therefore puts behavioral enforcement in the same on-chain path that controls token movement.

The session key cannot call the token directly through the vault. Every payment passes through `GuardModule.evaluatePayment`. The vault transfers tUSD8 only when the guard returns `true`.

**Security boundary:** the guard and vault are on-chain. The Rust simulator and forensic verifier are operational tools, not trusted enforcement components.

## 2. Pitch

An agent payment rail with a learned behavioral immune system, a tamper-evident black box, a two-key governed re-arm, an adversarial test harness, and a post-quantum migration path, built for Aevum testnet with tUSD8.

## 3. Network configuration

The QDay documentation currently identifies the public Aevum testnet as follows:

| Setting | Value |
| --- | --- |
| Network | QDay Aevum testnet |
| Chain ID | `44005` (`0xABE5`) |
| RPC | `https://rpc-test.qday.info` |
| WebSocket RPC | `wss://rpc-test.qday.info` |
| Explorer | `https://explorer-test.qday.info` |
| Native gas token | `tQDAY` |
| Stablecoin | `tUSD8` |
| tUSD8 address | `0x456569838f1d43009A91ebA4263147Afd7233483` |
| tUSD8 decimals | `6` |

Official references:

- [QDay chain parameters](https://wiki.qday.info/Knowledge/reference/chains)
- [QDay token list](https://wiki.qday.info/Knowledge/reference/tokens)
- [QDay Builder Challenge](https://qday.io/builder-challenge)
- [QDay testnet faucet](https://wiki.qday.info/guide/start/faucet)

The official challenge page confirms that tUSD8 is already deployed and that both tQDAY and tUSD8 are available through the testnet faucet. **Do not deploy `MockTUSD8` unless QDay's published token availability changes.**

Aevum is documented as EVM-compatible. The project therefore uses Solidity for enforceable contract logic and Rust for the simulator and off-chain tools. No unverified Rust contract runtime is assumed.

## 4. Architecture

```text
Human owner(s)                         Sentinel
     |                                    |
     | M-of-N signatures                  | veto
     v                                    v
+-------------------+             +-------------------+
|    GuardModule    |<------------| Governed re-arm   |
|                   |             +-------------------+
| - behavior checks |
| - state machine   |
| - rolling hash    |
| - policy quorum   |
| - signature port  |
+---------^---------+
          |
          | evaluatePayment(sessionKey, signedIntent, signature)
          |
+---------+---------+
|     AgentVault    |---- ERC-20 transfer ----> Supplier
|                   |
| owner / session   |
| key / tUSD8       |
+---------^---------+
          |
          | signed transaction
          |
    Rust AgentSimulator

Forensic events -> JSONL action log -> Rust verifier -> committed hash comparison
```

`AgentVault` is the intentionally small vault fallback described in the project brief. It is used instead of introducing ERC-4337 account-abstraction dependencies into the first build. The session key cannot be rotated by an owner-only setter. Rotation is available only inside the M-of-N, cooldown-protected re-arm path. The compromised key's frozen forensic history remains stored, and previously used session keys cannot be reactivated.

## 5. State machine

- `ACTIVE -> THROTTLED`: velocity, novel-recipient, or cadence rule is crossed.
- `ACTIVE -> FROZEN`: anomaly z-score or cumulative drawdown rule is crossed.
- `THROTTLED -> FROZEN`: another policy violation occurs before the throttle expires. A compliant retry is denied and recorded but does not escalate.
- `THROTTLED -> ACTIVE`: the throttle window expires without another violation.
- `FROZEN -> fresh ACTIVE session`: M-of-N owner signatures request re-arm, the cooldown elapses, the sentinel does not veto, and the vault rotates to a never-used session key. The compromised key remains frozen.

The initial deployment policy is tuned for the four-act demonstration. It is not a production risk model.

### Important EVM execution detail

A transaction that reverts cannot preserve the state update and logs emitted earlier in that same transaction. The demo brief asks for both a reverted payment and a persistent `SessionKeyThrottled` / `SessionKeyFrozen` event. Those requirements conflict at the EVM level.

Aevumaegis resolves this correctly: `GuardModule` records the attempted action, updates the state, emits the incident events, and returns `false`. `AgentVault` then emits `PaymentBlocked` and does not transfer tokens. The transaction receipt succeeds, but the payment itself is denied. A later call while frozen is also denied. This preserves the forensic evidence and proves that funds did not move.

## 6. Features

### F1. Forensic Replay Bundle

Each valid session-key payment attempt appends:

```text
keccak256(abi.encode(previousHash, sessionKey, recipient, amount, timestamp, actionIndex, actionKind, intentHash))
```

The contract emits `ActionRecorded(index, actionHash, kind, intentHash)`. On freeze it stores the terminal hash and emits `ForensicCommitment(finalHash, actionCount, reasonCode)`.

Only authenticated session-key intents enter the action history. Invalid signatures, expired intents, reused nonces, and unauthorized recipients revert before authentication, so they cannot create a misleading session-key forensic action. The exporter joins `PaymentIntentAuthenticated`, `ActionRecorded`, and `PaymentDecision` logs from each `Vault.pay` transaction, then reads that transaction's block timestamp. The Rust verifier accepts JSON Lines records containing the complete intent and action preimage:

```json
{"index":1,"session_key":"0x...","recipient":"0x...","amount":"1000000","timestamp":1,"kind":0,"allowed":true,"action_hash":"0x...","intent_hash":"0x...","vault_address":"0x...","chain_id":44005,"purpose_hash":"0x...","nonce":"0","expiry":"86401"}
```

It recomputes every hash in order, checks each emitted action hash, and compares the final result with the on-chain commitment. Editing one field or one hash causes verification to fail.

### F2. Learned behavioral baselines

`GuardModule` tracks:

- EWMA transaction amount with period 8.
- EWMA variance and a z-score comparison against the prior baseline.
- Per-session distinct-recipient counts, first-seen recipient state, and a rolling-window fraction of newly observed counterparties, alongside the novelty amount threshold.
- An exact rolling velocity window backed by a bounded 64-entry timestamp queue. The deployment default allows three transactions per ten seconds. Governance can configure a threshold up to 63 transactions; entries expire individually at the exact window boundary.
- Six epoch-tagged four-hour cadence buckets covering a rolling 24-hour cycle; reused buckets reset rather than inheriting yesterday's count.
- Cumulative spend since the last governed reset.
- A quantized composite threat score: velocity contributes 2, novel-recipient behavior 2, anomaly 3, drawdown 3, and cadence deviation 1. The default velocity threshold is three transactions per ten seconds. The novelty-fraction threshold is 50%, the throttle threat-score threshold is 2, and the freeze threshold is 3. Any further policy violation while throttled escalates to freeze; a compliant retry is denied without escalation.

Amounts are stored in the token's smallest unit. For tUSD8, one token is `1_000_000` base units. The implementation deliberately caps tracked payment size at `1e18` base units so squared deviations fit the chosen fixed-width variance representation. Policy values are quantized integer values to bound gas and arithmetic. This is an explicit trade-off, not a claim of full statistical sophistication.

### F3. Two-key tripwire

The owner quorum is configured at deployment. Two of three owners are required by the default deployment plan to request unfreeze or change policy. The quorum digest binds the replacement session-key address, so the owners authorize the exact key that will receive authority. The sentinel can veto a pending unfreeze, which clears the request and increments the governance nonce. A new quorum request is then required. The cooldown is one day in the default deployment configuration.

The signature verifier is an interface. The ECDSA implementation is active now; the hybrid verifier deliberately fails closed until a QDay-supported PQ precompile or verifier is available. The exact migration assignment is `signatureVerifier = ISignatureVerifier(newVerifier);` inside `GuardModule.updateSignatureVerifier`. Switch only after QDay publishes the verifier/precompile interface and an audited implementation is available. The replacement must support both session-intent and owner-quorum verification.

### F4. Signed Spend Envelope

Every vault payment requires a session-key signature over a `PaymentIntent` containing the recipient, amount, purpose hash, nonce, and expiry. The digest additionally binds the vault address, chain ID, and active session key. This prevents cross-vault, cross-chain, cross-key, and cross-intent replay.

The guard rejects zero-value or expired intents, zero purpose hashes, unauthorized counterparties, unapproved purpose hashes, amounts above the approved purpose cap, reused nonces, and invalid signatures. Governance authorizes each recipient-purpose pair independently with M-of-N signatures and an explicit maximum amount. The purpose hash commits to an off-chain invoice or payment purpose, but the contract verifies the approved hash and amount cap rather than parsing the document. Recipient authorization epochs ensure that revoking and reauthorizing a counterparty does not restore stale purpose approvals. The nonce is consumed after authentication and before behavioral evaluation. Consequently, an authenticated payment blocked by the circuit breaker cannot be replayed after the session is re-armed.

The Rust simulator signs the same ABI-encoded digest locally. The forensic exporter reconstructs the digest from `PaymentIntentAuthenticated`, `ActionRecorded`, and `PaymentDecision` events and checks it before accepting the action chain.


### F5. Adversarial harness

The Foundry suite includes deterministic tests for legitimate payments, exact velocity-window rollover, 24-hour cadence bucket rollover, novelty, anomaly, drawdown, escalation to freeze, blocked-intent nonce consumption, low-s ECDSA enforcement, vault/guard binding, M-of-N re-arm, cooldown enforcement, and sentinel veto. Fuzzed payment amounts and an invariant handler compare payment decisions with token balance movement and the cumulative-spend ceiling. Run the invariant suite and coverage in Foundry before treating F5 as runtime-verified. Do not invent a counterexample.

### F6. Post-quantum forward path

`GuardModule` depends on `ISignatureVerifier`, not directly on ECDSA. `EcdsaVerifier` is the live adapter. `HybridVerifier` is a fail-closed placeholder with an explicit `awaiting PQ precompile` error. Once QDay publishes the supported ML-DSA / hybrid verification interface, deploy the compatible verifier and use the governed `updateSignatureVerifier` function.


## 7. Behavioral signals and authorization checks

| Check | Purpose | Current behavior |
| --- | --- | --- |
| Velocity | Detect burst draining | Default: more than 3 transactions in 10 seconds triggers throttle; a further violation while throttled freezes |
| Anomaly | Detect unusual payment size | Freeze when the z-score exceeds policy |
| Novelty | Detect first-time counterparties and bursts of new counterparties | Track distinct recipients and throttle when the rolling novelty fraction or large-recipient threshold is crossed |
| Drawdown | Detect cumulative slow bleed | Freeze when spend exceeds the configured ceiling |
| Cadence | Detect activity in an unobserved time bucket | Throttle after the configured warm-up count |
| Signed intent | Bind vault, chain, session key, recipient, amount, purpose, nonce, and expiry | Mandatory signature plus M-of-N recipient-purpose authorization and a maximum amount cap |

## 8. Build and test

GitHub Actions runs mandatory Clippy, Rust tests, shell syntax checks, Foundry compilation, the Foundry unit/fuzz/invariant suite, and a coverage summary on pushes and pull requests. The workflow is in `.github/workflows/ci.yml`.

Prerequisites:

- Foundry (`forge`, `cast`, `anvil`)
- Rust toolchain and Clippy
- Access to Aevum testnet RPC

From `contracts/`:

```bash
forge build
forge test -vvv
forge test --fuzz-runs 10000
forge coverage
```

From `rust/`:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

The source package has not been compiled or tested in this execution environment. No Foundry coverage percentage or Foundry-generated counterexample is claimed. Record those outputs after running the commands above; do not substitute static review for runtime evidence.

## 9. Deploy

Copy `.env.example` to `.env` and fill it locally. Never commit `.env` or disclose private keys.

```bash
cd contracts
set -a
source ../.env
set +a
forge script script/Deploy.s.sol:DeployAevumaegis \
  --rpc-url "$RPC_URL" \
  --broadcast \
  --private-key "$DEPLOYER_PRIVATE_KEY"
```

The deploy script refuses to run unless `block.chainid == 44005`. It deploys the ECDSA verifier, vault, and guard, then configures the vault. The deployer is owner one; `OWNER_TWO`, `OWNER_THREE`, `SENTINEL`, `SESSION_KEY`, and `TUSD8_ADDRESS` must be supplied.

Before the first payment, return to the project root, authorize the supplier and attacker counterparties with the M-of-N governance helper, then fund the vault. Use integer base units. For example, `1 tUSD8 = 1000000`.

```bash
cd ..
# Run once for each counterparty that the agent is allowed to pay.
RECIPIENT_ADDRESS="$SUPPLIER_ADDRESS" PURPOSE_HASH="$PURPOSE_HASH" PURPOSE_MAX_AMOUNT=1000000 ./scripts/authorize-recipient.sh
RECIPIENT_ADDRESS="$ATTACKER_ADDRESS" PURPOSE_HASH="$PURPOSE_HASH" PURPOSE_MAX_AMOUNT=20000000 ./scripts/authorize-recipient.sh

# Approve the vault and deposit tUSD8 from the vault owner.
cast send "$TUSD8_ADDRESS" 'approve(address,uint256)' "$VAULT_ADDRESS" 500000000 \
  --private-key "$DEPLOYER_PRIVATE_KEY" --rpc-url "$RPC_URL"
cast send "$VAULT_ADDRESS" 'deposit(uint256)' 500000000 \
  --private-key "$DEPLOYER_PRIVATE_KEY" --rpc-url "$RPC_URL"
```

## 10. Terminal demonstration

The Rust simulator is in `rust/agent-simulator`:

```bash
cargo run --release -p aevumaegis-agent-simulator -- \
  --vault "$VAULT_ADDRESS" \
  --session-private-key "$SESSION_PRIVATE_KEY" \
  --supplier "$SUPPLIER_ADDRESS" \
  --attacker "$ATTACKER_ADDRESS" \
  --mode demo
```

The demo sends five ordinary payments spaced four seconds apart, waits for the velocity window to expire, then submits four of six planned rapid attempts. The fourth attempt trips the three-per-ten-second threshold and the compromised client stops. It then attempts a large payment to a novel recipient while throttled. That final attempt should freeze the session key with `NOVEL_RECIPIENT_LARGE_AMOUNT`. The shell demo additionally checks the THROTTLED and FROZEN transitions, confirms a nonzero forensic commitment, and verifies that the attacker's tUSD8 balance did not increase.

The shell alternative is `scripts/demo.sh`. It demonstrates acts 1 through 3. The compromised client is planned for six rapid payments but stops after the fourth attempt trips THROTTLED, preserving act 3 as a distinct escalation. Act 4 is automated by `scripts/rearm.sh`: it signs the first request with two owner keys, submits the request, sends a sentinel veto, creates a fresh quorum request using the incremented governance nonce, waits for the configured cooldown, executes the re-arm, and sends one payment with the replacement session key. The script derives the replacement address from `NEW_SESSION_PRIVATE_KEY`; all keys are read from the local environment and must never be committed.

Run act 4 only after act 3 has frozen the currently active session key:

```bash
set -a
source .env
set +a
./scripts/rearm.sh
```

The default cooldown is 86,400 seconds. For a local Foundry test deployment, set `COOLDOWN_SECONDS` to the cooldown configured in that deployment. The public testnet deployment uses the one-day policy.

The expected act-3 evidence is the `SessionKeyFrozen` event with the `REASON_NOVEL_RECIPIENT_LARGE_AMOUNT` code, followed by `ForensicCommitment`. Reason codes are `bytes32` hashes of their documented labels, so the explorer displays the hash; compare it with the public constant getter. The blocked call is mined to preserve evidence, but the drain transfer must not appear as a successful tUSD8 transfer.

## 11. Forensic export and verification

The Rust forensic tool now has two commands. `export` reads the GuardModule event stream directly from Aevum, joins each `PaymentIntentAuthenticated` with its corresponding `ActionRecorded` and `PaymentDecision` in transaction log order, resolves the block timestamp, writes JSONL, and verifies the resulting chain before publishing the file. It checks the RPC chain ID, validates the guard-to-vault binding, compares the supplied hash, frozen state, action count, and rolling hash with `getSessionStats(sessionKey)`, detects a changing chain head, and uses bounded `eth_getLogs` block chunks.

```bash
export SESSION_KEY_ADDRESS="$(cast wallet address --private-key "$SESSION_PRIVATE_KEY")"
export EXPECTED_FORENSIC_HASH="$(cast call "$GUARD_ADDRESS" 'getFinalForensicHash(address)(bytes32)' "$SESSION_KEY_ADDRESS" --rpc-url "$RPC_URL")"
cd rust
cargo run --release -p aevumaegis-forensic-verifier -- export \
  --guard-address "$GUARD_ADDRESS" \
  --vault-address "$VAULT_ADDRESS" \
  --session-key "$SESSION_KEY_ADDRESS" \
  --from-block "$FROM_BLOCK" \
  --output actions.jsonl \
  --expected-hash "$EXPECTED_FORENSIC_HASH"
```

The `--from-block` value must include the first action for that session key because verification starts from a zero hash. The export must end at the latest block because the tool also reads `getSessionStats(sessionKey)` and checks the frozen state, current action count, rolling hash, and `finalForensicHash`. It detects a changing chain head and asks you to retry rather than mixing two snapshots. Each session key has an independent chain. After governed re-arm, export the replacement key as a separate log, using the deployment start block or the first block containing its actions. The tool filters by the `PaymentDecision.sessionKey` field, so actions from other keys do not enter the selected chain.

The exporter pairs events by transaction hash and log order, so it also handles a transaction containing more than one vault payment. It rejects missing event pairs, duplicate action indices, inconsistent event ordering, an unexpected chain ID, and a final commitment mismatch. It uses block timestamps returned with logs when available and fetches the block header otherwise. Output is written only after the complete log has passed verification.

To verify an existing log without contacting RPC:

```bash
cargo run --release -p aevumaegis-forensic-verifier -- verify \
  --log actions.jsonl \
  --expected-hash 0x<forensic-commitment-hash>
```

The verifier recomputes the hash from the prior hash and action fields, checks each emitted action hash and the `allowed` decision against the action kind, then compares the final result to the on-chain `ForensicCommitment`. A modified field or hash must fail verification.

For the complete F1 proof, set `GUARD_ADDRESS`, `SESSION_PRIVATE_KEY`, `FROM_BLOCK`, and `RPC_URL` in `.env`, derive `SESSION_KEY_ADDRESS` as shown above, set `EXPECTED_FORENSIC_HASH`, then run the tamper demonstration from the project root:

```bash
./scripts/forensic-demo.sh
```

It exports and verifies the authentic event history, flips one byte in the first action hash, and requires the tampered file to fail verification. The script treats an unexpected PASS as a failure.

## 12. Honest limitations and next work

- Session-key rotation is restricted to the M-of-N re-arm path. Each replacement key must be fresh and unused; the old key's frozen history remains intact.
- Behavioral features are gas-bounded approximations. The six cadence buckets are coarse, the 64-entry velocity queue has a deliberate 63-transaction policy ceiling, and the variance model is not a substitute for a mature fraud model. Cadence buckets are epoch-tagged so a prior day's activity cannot masquerade as current activity.
- `HybridVerifier` is a stub, not a post-quantum implementation.
- Foundry and Rust tests have been authored but still require execution in a configured toolchain. No deployment or explorer verification is claimed yet.
- The Rust JSONL event exporter is implemented but awaits a live Aevum RPC run. It validates the GuardModule-to-vault binding, joins authenticated-intent, action, and decision events, resolves timestamps, exports one session-key chain at a time, and verifies the output before writing it. The act-4 owner-signing, sentinel-veto, cooldown, session-key rotation, and post-rearm payment workflow is provided by `scripts/rearm.sh`.

## 13. Submission

Challenge: [Aevum Builder Challenge #1](https://qday.io/builder-challenge)

Submission deadline in the supplied project brief: **11 December 2026**. Verify the live DoraHacks submission page before submitting, and include deployed contract addresses, explorer links, test output, coverage, and the adversarial counterexample/fix.
