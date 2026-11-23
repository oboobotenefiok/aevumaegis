# Build progress

## Implemented in the initial scaffold

- Solidity `AgentVault` with guarded tUSD8 payments, non-reentrant token operations, and guard-only session-key rotation.
- Solidity `GuardModule` with ACTIVE / THROTTLED / FROZEN states, EWMA amount and variance, z-score checks, recipient novelty, cadence buckets, velocity, drawdown, composite threat score, forensic hash chain, and M-of-N policy / re-arm governance.
- ECDSA signature adapter and fail-closed hybrid verifier placeholder.
- Foundry unit tests for EWMA, cadence, velocity, novelty, anomaly, drawdown, freeze escalation, forensic hash progression, quorum, sentinel veto, cooldown, and session-key rotation.
- Foundry invariant handler fuzzing payment amount, recipient, and elapsed time.
- Rust + Alloy session-key payment simulator.
- Rust + Alloy ABI-based forensic hash verifier with valid, tampered, and empty-log tests.
- Consistent Aevumaegis naming across Solidity contracts, tests, Rust crates and binaries, deployment command, and documentation.
- Act 4 re-arm script: quorum request, sentinel veto, nonce refresh, second quorum request, cooldown wait, session-key rotation, and a post-rearm payment.
- Explicit fail-closed test for the hybrid signature-verifier placeholder.
- GitHub Actions workflow for Rust formatting, Clippy, Rust tests, Solidity formatting, Foundry build, and Foundry tests.
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
3. Add the JSONL event exporter that joins `ActionRecorded` and `PaymentDecision` logs and resolves block timestamps.
4. Deploy to Aevum, verify source on the explorer, and execute the complete four-act demo.
5. Capture an actual Foundry counterexample and its regression fix. Do not fabricate one.
6. Decide whether F4 signed payment intents can be added without delaying the core submission.

## Local toolchain status for this handoff

The execution container does not have `rustc`, `cargo`, `forge`, `solc`, or `cast`. Earlier apt and compiler retrieval attempts timed out. `bash -n`, JSON/TOML parsing, project identity checks, excluded-artifact checks, and basic Solidity delimiter checks passed. No compilation, unit test, invariant test, or deployment success is claimed.
