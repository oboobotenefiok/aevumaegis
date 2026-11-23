# Architecture decisions

## ADR-001: Solidity is the enforcement runtime

Aevum is documented as EVM-compatible. Aevumaegis keeps the security decision in Solidity and does not assume an unconfirmed Rust contract runtime. Rust is used for off-chain tooling.

## ADR-002: Start with a vault, not ERC-4337

The supplied project brief explicitly allows a vault fallback when account-abstraction tooling adds friction. The vault is smaller, easier to audit, and sufficient to demonstrate the payment policy. It holds tUSD8 and makes the guard check part of every session-key transfer.

## ADR-003: Preserve incident evidence instead of reverting blocked payment calls

A reverted EVM transaction rolls back emitted logs and storage writes. Because the forensic state transition must persist, blocked payments return `false` and do not transfer tokens. This is an intentional protocol-level clarification of the supplied demo's conflicting expectation.

## ADR-004: Session-key rotation is part of governed re-arm

An owner-only session-key setter would let one owner replace a frozen key with a fresh key whose behavioral statistics are empty. Rotation is therefore callable only by GuardModule after M-of-N signatures and the cooldown. Previously used keys are rejected, and the old key's frozen forensic history remains intact.

## ADR-005: Use the deployed test stablecoin

QDay's official token list and builder challenge page publish the Aevum tUSD8 address and six decimals. No mock token is included in the default deployment path.

## ADR-006: Require signed intent envelopes for every payment

The vault exposes no raw recipient/amount payment method. Every payment must present a session-key signature bound to the vault, chain ID, session key, recipient, amount, purpose hash, nonce, and expiry. Counterparties are controlled by the same M-of-N governance quorum used for policy changes. Nonces are consumed after signature and envelope validation, including when the behavioral circuit breaker denies the transfer, so a blocked intent cannot be replayed. The forensic action hash commits to the intent digest, and the exporter emits enough authenticated event data for independent digest reconstruction.

## ADR-007: Cadence buckets are epoch-tagged

A modulo ring of six bucket counters is not sufficient by itself: without an epoch tag, activity from 24 hours earlier can be mistaken for activity in the current bucket. Each bucket therefore stores the absolute four-hour epoch that last wrote it and resets its count when reused. Velocity windows also reset at the exact configured boundary.


## ADR-008: Use a bounded timestamp queue for true rolling velocity

A single `windowStartedAt` counter implements a tumbling window, not a rolling window. The guard now maintains a 64-entry per-session-key circular timestamp queue, expires entries individually at the exact `windowSeconds` boundary, and limits the configurable threshold to 63 so the queue always retains enough history to detect the next breach. The queue also records authenticated behavior-blocked attempts, while invalid or unauthenticated intents remain transaction reverts and do not enter the action history.


## ADR-009: Measure novelty as both first-use and rolling fraction

A first-seen mapping catches a large payment to a new counterparty but does not detect a burst of many small payments to different new counterparties. Aevumaegis now counts distinct observed counterparties per session and tags the bounded velocity queue with first-observation flags. The rolling novelty fraction is compared with a governance-tunable WAD threshold after the behavioral warm-up period. The separate `seenRecipient` map remains success-based so a blocked large first payment still escalates if retried while throttled.


## ADR-010: Intent expiry uses chain time

The simulator and shell scripts derive intent expiry from the latest Aevum block timestamp rather than the host device clock. This avoids rejecting otherwise valid intents when a Termux device clock is skewed and keeps all authorization time decisions in the chain's time domain.


## ADR-011: Purpose hashes are authorized per recipient and epoch

A signed payment intent includes a purpose hash that commits to an off-chain invoice or payment purpose. The contract does not parse or fetch the off-chain document. Governance authorizes each recipient-purpose pair independently and supplies a maximum amount for that pair. Each recipient authorization change advances its epoch, so revoking and later reauthorizing a recipient cannot silently restore old purpose approvals. The off-chain system must canonicalize invoice data consistently before hashing it.
