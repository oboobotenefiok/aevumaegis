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
