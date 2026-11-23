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
          | evaluatePayment(sessionKey, recipient, amount)
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
- `THROTTLED -> FROZEN`: another policy violation occurs before the throttle expires.
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
keccak256(abi.encode(previousHash, sessionKey, recipient, amount, timestamp, actionIndex, actionKind))
```

The contract emits `ActionRecorded(index, actionHash, kind)`. On freeze it stores the terminal hash and emits `ForensicCommitment(finalHash, actionCount, reasonCode)`.

The exporter joins `ActionRecorded` and `PaymentDecision` logs from each `Vault.pay` transaction, then reads that transaction's block timestamp. The Rust verifier accepts JSON Lines records with these fields:

```json
{"index":1,"session_key":"0x...","recipient":"0x...","amount":"1000000","timestamp":1,"kind":0,"action_hash":"0x..."}
```

It recomputes every hash in order, checks each emitted action hash, and compares the final result with the on-chain commitment. Editing one field or one hash causes verification to fail.

### F2. Learned behavioral baselines

`GuardModule` tracks:

- EWMA transaction amount with period 8.
- EWMA variance and a z-score comparison against the prior baseline.
- First-seen recipient state and a novelty amount threshold.
- Rolling transaction count and time window.
- Six coarse four-hour cadence buckets.
- Cumulative spend since the last governed reset.
- A quantized composite threat score: velocity contributes 2, novel-recipient behavior 2, anomaly 3, drawdown 3, and cadence deviation 1. The default throttle threshold is 2 and freeze threshold is 3. Any further payment attempt while throttled escalates to freeze.

Amounts are stored in the token's smallest unit. For tUSD8, one token is `1_000_000` base units. The implementation deliberately caps tracked payment size at `1e18` base units so squared deviations fit the chosen fixed-width variance representation. Policy values are quantized integer values to bound gas and arithmetic. This is an explicit trade-off, not a claim of full statistical sophistication.

### F3. Two-key tripwire

The owner quorum is configured at deployment. Two of three owners are required by the default deployment plan to request unfreeze or change policy. The quorum digest binds the replacement session-key address, so the owners authorize the exact key that will receive authority. The sentinel can veto a pending unfreeze, which clears the request and increments the governance nonce. A new quorum request is then required. The cooldown is one day in the default deployment configuration.

The signature verifier is an interface. The ECDSA implementation is active now; the hybrid verifier deliberately fails closed until a QDay-supported PQ precompile or verifier is available. A quorum-governed `updateSignatureVerifier` function provides the migration seam.

### F5. Adversarial harness

The Foundry suite includes deterministic tests for legitimate payments, velocity throttling, escalation to freeze, forensic hash progression, M-of-N re-arm, cooldown enforcement, sentinel veto, and a fuzzed blocked-transfer property.

The invariant suite and coverage report are not yet complete. A real counterexample and fix must be captured from Foundry before the project claims the F5 acceptance criteria are met. Do not invent a counterexample.

### F6. Post-quantum forward path

`GuardModule` depends on `ISignatureVerifier`, not directly on ECDSA. `EcdsaVerifier` is the live adapter. `HybridVerifier` is a fail-closed placeholder with an explicit `awaiting PQ precompile` error. Once QDay publishes the supported ML-DSA / hybrid verification interface, deploy the compatible verifier and use the governed `updateSignatureVerifier` function.

### F4. Spend Envelope

Deferred. Signed payment intents, invoice/purpose binding, nonce replay protection, expiry, and recipient allowlisting are stretch work. F1, F2, F3, F5, and F6 take priority.

## 7. Six policy checks

| Check | Purpose | Current behavior |
| --- | --- | --- |
| Velocity | Detect burst draining | Throttle when the rolling count exceeds policy |
| Anomaly | Detect unusual payment size | Freeze when the z-score exceeds policy |
| Novelty | Detect first-time counterparties | Throttle above the novelty threshold; freeze if repeated while throttled |
| Drawdown | Detect cumulative slow bleed | Freeze when spend exceeds the configured ceiling |
| Cadence | Detect activity in an unobserved time bucket | Throttle after the configured warm-up count |
| Intent | Bind payments to invoices and purpose | Deferred with F4 |

## 8. Build and test

GitHub Actions runs Rust formatting, mandatory Clippy, Rust tests, Solidity formatting, Foundry compilation, and the Foundry unit/fuzz/invariant suite on pushes and pull requests. The workflow is in `.github/workflows/ci.yml`.

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

Before the first payment, the vault owner must approve the vault to spend tUSD8 and deposit a demo balance. Use integer base units. For example, `1 tUSD8 = 1000000`.

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

The demo sends five ordinary payments, waits for the velocity window to expire, sends six rapid payments, then attempts a large payment to a novel recipient. The final attempt should freeze the session key with `NOVEL_RECIPIENT_LARGE_AMOUNT`.

The shell alternative is `scripts/demo.sh`. It demonstrates acts 1 through 3. Act 4 is now automated by `scripts/rearm.sh`: it signs the first request with two owner keys, submits the request, sends a sentinel veto, creates a fresh quorum request using the incremented governance nonce, waits for the configured cooldown, executes the re-arm, and sends one payment with the replacement session key. The script derives the replacement address from `NEW_SESSION_PRIVATE_KEY`; all keys are read from the local environment and must never be committed.

Run act 4 only after act 3 has frozen the currently active session key:

```bash
set -a
source .env
set +a
./scripts/rearm.sh
```

The default cooldown is 86,400 seconds. For a local Foundry test deployment, set `COOLDOWN_SECONDS` to the cooldown configured in that deployment. The public testnet deployment uses the one-day policy.

The expected act-3 evidence is the `SessionKeyFrozen` event with the `REASON_NOVEL_RECIPIENT_LARGE_AMOUNT` code, followed by `ForensicCommitment`. Reason codes are `bytes32` hashes of their documented labels, so the explorer displays the hash; compare it with the public constant getter. The blocked call is mined to preserve evidence, but the drain transfer must not appear as a successful tUSD8 transfer.

## 11. Forensic verification

Build and run:

```bash
cargo run --release -p aevumaegis-forensic-verifier -- \
  --log actions.jsonl \
  --expected-hash 0x<forensic-commitment-hash>
```

The log exporter must preserve the order and exact fields emitted by `ActionRecorded`. The verifier does not trust a locally supplied `action_hash`: it recomputes the hash from the prior hash and action fields, checks each recorded hash, then compares the last hash to the on-chain `ForensicCommitment`.

## 12. Honest limitations and next work

- Session-key rotation is restricted to the M-of-N re-arm path. Each replacement key must be fresh and unused; the old key's frozen history remains intact.
- Behavioral features are gas-bounded approximations. The six cadence buckets are coarse, and the variance model is not a substitute for a mature fraud model.
- `HybridVerifier` is a stub, not a post-quantum implementation.
- F4 is deferred.
- Foundry and Rust tests have been authored but still require execution in a configured toolchain. No deployment or explorer verification is claimed yet.
- A JSONL exporter from explorer/RPC event logs remains to be completed. The act-4 owner-signing, sentinel-veto, cooldown, session-key rotation, and post-rearm payment workflow is provided by `scripts/rearm.sh`.

## 13. Submission

Challenge: [Aevum Builder Challenge #1](https://qday.io/builder-challenge)

Submission deadline in the supplied project brief: **11 December 2026**. Verify the live DoraHacks submission page before submitting, and include deployed contract addresses, explorer links, test output, coverage, and the adversarial counterexample/fix.
