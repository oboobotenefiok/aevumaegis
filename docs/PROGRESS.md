# Build progress

## Implemented in the initial scaffold

- Solidity `AgentVault` with guarded tUSD8 payments, non-reentrant token operations, and guard-only session-key rotation.
- Solidity `GuardModule` with ACTIVE / THROTTLED / FROZEN states, EWMA amount and variance, z-score checks, distinct-recipient counts, rolling novelty fraction, epoch-tagged cadence buckets, a 64-entry exact rolling velocity queue, drawdown, composite threat score, forensic hash chain, and M-of-N policy / re-arm governance.
- M-of-N recipient and per-recipient purpose-hash authorization with an approved maximum amount. Recipient authorization epochs prevent stale invoice-purpose approvals from becoming active after a revoke/reauthorize cycle.
- ECDSA signature adapter and fail-closed hybrid verifier placeholder.
- Foundry unit tests for EWMA, cadence, velocity, novelty, anomaly, drawdown, freeze escalation, forensic hash progression, quorum, sentinel veto, cooldown, session-key rotation, purpose authorization quorum, purpose amount caps, and recipient reauthorization epochs.
- Foundry invariant handler fuzzing payment amount, recipient, and elapsed time; deterministic regression tests cover exact velocity-window rollover, 24-hour cadence bucket rollover, blocked-intent nonce consumption, and high-s ECDSA rejection.
- Rust + Alloy session-key payment simulator.
- Rust + Alloy ABI-based forensic verifier with valid, tampered action hash, tampered intent field, empty-log, decision-consistency, duplicate nonce, mixed-session, mixed-vault, and malformed-intent checks.
- Rust + Alloy live event exporter: reads Aevum GuardModule logs in bounded block chunks, pairs PaymentIntentAuthenticated, ActionRecorded, and PaymentDecision events by transaction and log order, resolves block timestamps, filters per session key, validates the GuardModule-to-vault binding, compares the exported action count, rolling hash, frozen state, and final hash with on-chain session stats, detects a changing chain head, recomputes the signed intent digest and action chain, and verifies before writing JSONL.
- Demo scripts use Aevum block timestamps for intent expiry, explicit pending transaction nonces for concurrent velocity submissions, and on-chain checks for the THROTTLED/FROZEN states, forensic commitment, and unchanged attacker balance. The default deployment policy allows three payments per ten-second window; the compromised client stops after the fourth attempt trips throttle so the drain act can separately trigger freeze.
- Constructor validation rejects token addresses without code, non-contract verifier addresses, contract-based ECDSA signers, and guards bound to a different vault.
- Consistent Aevumaegis naming across Solidity contracts, tests, Rust crates and binaries, deployment command, and documentation.
- Act 4 re-arm script: quorum request, sentinel veto, nonce refresh, second quorum request, cooldown wait, session-key rotation, and a post-rearm payment.
- Explicit fail-closed test for the hybrid signature-verifier placeholder.
- F4 signed payment intents enforced on every vault payment: session-key ECDSA digest verification, vault/chain binding, purpose hash, expiry, per-session-key nonce replay protection, and M-of-N governed recipient/purpose authorization with a per-purpose amount cap.
- Alloy simulator signs each payment intent locally; shell demo and re-arm scripts encode and sign the same intent digest.
- Governance recipient authorization helper and F4 intent rejection tests for replay, expiry, unauthorized recipients, and invalid signatures.
- GitHub Actions workflow for Rust Clippy/tests, shell syntax checks, Solidity build, Foundry unit/fuzz/invariant tests, and coverage summary.
- Deployment script, demo script, README, architecture decisions, and contribution guide.

## Verified external configuration

- Aevum testnet chain ID: `44005`.
- RPC: `https://rpc-test.qday.info`.
- Explorer: `https://explorer-test.qday.info`.
- tUSD8: `0x456569838f1d43009A91ebA4263147Afd7233483`, 6 decimals.
- QDay's current builder challenge page confirms the deployed test token and testnet faucet availability. No mock token is part of the default path.

## Remaining work

1. Run `forge fmt`, `forge build`, `forge test`, fuzzing, invariant tests, and coverage in a Foundry-enabled environment.
2. Run `cargo fmt`, mandatory Clippy, and Rust workspace tests in a Rust-enabled environment.
3. Run the exporter against a deployed GuardModule and capture authentic plus tampered-log PASS/FAIL evidence.
4. Deploy to Aevum, verify source on the explorer, and execute the complete four-act demo.
5. Capture any actual Foundry counterexample and its regression fix. Do not fabricate one.
6. Confirm token authorization, vault funding, transaction ordering, and all governance operations on the live testnet.

## Local toolchain status for this handoff

The execution container does not have `rustc`, `cargo`, `forge`, `solc`, or `cast`. Earlier apt and compiler retrieval attempts timed out. `bash -n`, JSON/TOML parsing, project identity checks, excluded-artifact checks, and basic Solidity delimiter checks passed. No compilation, unit test, invariant test, or deployment success is claimed.

## Current completion estimate

**95%** of the planned non-stretch project scope is implemented in source. This is an implementation estimate, not a test-pass percentage. Runtime validation, live deployment, explorer verification, coverage evidence, and a Foundry-generated counterexample with its regression fix remain outstanding.
