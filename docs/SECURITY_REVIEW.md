# Aevumaegis security review

## Scope

This review covers the Solidity vault and guard, ECDSA verification, governed session rotation, signed-intent digest construction, the Rust/Alloy simulator and forensic exporter, and the bash deployment/demo workflows.

It is a source review, not an audit or a substitute for compilation, fuzzing, invariant execution, or testnet operation.

## Correctness issues found and addressed

1. **Tumbling velocity window:** the original start-time counter reset the entire count at one boundary. It is now a bounded 64-entry per-session circular timestamp queue. Entries expire individually at the configured window boundary. Policy thresholds are capped at 63 so the queue can always retain enough history to detect the next breach.
2. **Stale cadence buckets:** modulo bucket counters could carry yesterday's activity into today's matching bucket. Each bucket now stores its absolute four-hour epoch and resets when reused.
3. **Missing novelty fraction:** a first-seen mapping alone did not measure bursts of new counterparties. The guard now tracks distinct observed recipients and records first-observation flags in the rolling velocity queue. After warm-up, the rolling novelty fraction is checked against a governance-controlled WAD threshold.
4. **Vault/guard mismatch:** vault configuration now verifies that the configured guard is a contract bound to that exact vault. The forensic exporter independently checks the same binding.
5. **Invalid signer configuration:** constructor and rotation checks reject contract addresses where ECDSA EOAs are required. The verifier and token addresses must contain contract code.
6. **Purpose authorization lifecycle:** purpose hashes and maximum amounts are quorum-authorized per recipient. Recipient authorization epochs ensure revoking and reauthorizing a recipient does not silently restore stale purpose approvals. Payments above the approved purpose cap are rejected before nonce consumption.
7. **Forensic export scope:** the exporter now checks session-key and vault consistency, duplicate nonces, monotonic timestamps, intent field validity, action count, on-chain final commitment, and chain-head stability during export.
8. **Host clock dependence:** simulator and shell intent expiries now use the latest Aevum block timestamp.
9. **Concurrent demo nonce reuse:** velocity transactions now receive explicit sequential transaction nonces and explicit distinct intent nonces before being submitted concurrently.
10. **False-positive demo claims:** the shell demo now checks that the session actually reached FROZEN, that a forensic commitment exists, and that the attacker's token balance did not increase.
11. **Invariant accounting:** the Foundry invariant handler now compares both recipient and vault token balances, tracks total successful spend, and checks the on-chain drawdown ceiling.
12. **Throttle escalation:** a compliant attempt during the throttle period was incorrectly treated as a further violation. The guard now records and denies that attempt without freezing; only a new velocity, novelty, cadence, anomaly, or drawdown violation escalates. A regression test covers the distinction.
13. **Demo threshold mismatch:** the deployment default now allows three transactions per ten-second window, matching the fourth-attempt throttle scenario. The compromised client stops after that first denial so the novel-recipient drain remains a separate THROTTLED-to-FROZEN act.

## Invariants intended to hold

- Only the active session key can call `AgentVault.pay`.
- Every payment requires an authorized recipient, an approved purpose hash and maximum amount for that recipient, and a valid, unexpired, non-replayed session-key intent.
- An authenticated behavioral denial returns `false`, records evidence, and does not transfer tokens. A compliant attempt during an active throttle remains denied without escalating; a further policy violation escalates to FROZEN.
- Invalid or unauthenticated intents revert before they are recorded. This includes unapproved recipient-purpose pairs. This is intentional: an unauthenticated caller must not be able to write arbitrary actions into a session key's forensic history.
- A FROZEN session cannot transfer tokens.
- Cumulative successful spend cannot exceed the configured drawdown limit.
- A session key can only be rotated by the guard after quorum approval and cooldown, and only to a fresh EOA.
- A sentinel veto invalidates the pending re-arm request and requires a new quorum request.
- The forensic exporter only accepts a complete per-session action sequence whose recomputed chain matches the current on-chain commitment and action count.

## Residual risks and unverified work

- `HybridVerifier` is deliberately non-operational and reverts. No post-quantum signature verification is implemented.
- Behavioral thresholds are demonstration defaults. The EWMA and cadence model are heuristics, not a production fraud classifier.
- The velocity queue has bounded storage and a maximum configured threshold of 63. That bound is explicit and should be revisited only with a redesigned data structure.
- A denied behavioral payment is mined with a successful transaction receipt so state and events persist. It is not an EVM revert. Invalid signatures, expired intents, replayed nonces, unauthorized recipients, unapproved recipient-purpose pairs, and amounts above an approved purpose cap do revert.
- Invalid or unauthenticated intents do not enter the forensic action chain because their transactions revert.
- Foundry coverage and a Foundry-generated counterexample/fix have not yet been captured.
- Rust compilation, mandatory Clippy, Foundry compilation, unit/fuzz/invariant execution, live deployment, and explorer verification remain unverified in this environment.
- The current deployment assumes the official tUSD8 contract and standard ERC-20 boolean return behavior.

## Required verification before release

Run the commands in the root README and retain their output. In particular, require `cargo clippy --workspace --all-targets --all-features -- -D warnings`, the complete Foundry fuzz/invariant suite, and `forge coverage` to pass before describing the build as verified. Then deploy to Aevum, run all four demo acts, export the frozen session's forensic log, and demonstrate that a one-byte tamper fails verification.
