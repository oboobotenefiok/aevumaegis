# Contributing

Aevumaegis is an open-source security prototype. Contributions should preserve the threat model and keep all payment enforcement on-chain.

## Before submitting a change

1. Read the threat model and architecture decisions in `README.md` and `docs/DECISIONS.md`.
2. Keep Solidity interfaces narrow and validate every state transition with Foundry tests.
3. Never add a path that lets the session key transfer tokens without calling `GuardModule`.
4. Keep Rust code idiomatic, avoid panics in production paths, and document non-obvious ABI assumptions.
5. Add a regression test for every security-relevant fix.

## Verification

```bash
cd contracts
forge fmt --check
forge build
forge test -vvv
forge test --fuzz-runs 10000
forge coverage

cd ../rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Do not commit `.env`, private keys, `Cargo.lock`, build output, or vendored dependencies.

Rust implementation guidance: [The Rust Programming Language](https://doc.rust-lang.org/book/) and [bruh](https://github.com/oboobotenefiok/bruh).
