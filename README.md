# Nox Confidential Safe Treasury Module

A Gnosis Safe module implementing a confidential treasury ledger: the Safe
deposits into an encrypted internal balance, and payouts move an encrypted
amount to a recipient's encrypted balance via Nox's `transfer` primitive.
The amount moved — and even whether a payout succeeded — stays encrypted
on-chain; only accounts explicitly granted access can decrypt it off-chain
via the Nox JS SDK.

## Revision history (why this looks different from the first draft)

The original scaffold guessed Nox worked like an async request/callback
oracle (submit encrypted data, wait for a TEE callback with a result).
The real docs (docs.noxprotocol.io) show something different and simpler:
Nox is a **Solidity library** you call directly - `Nox.add`, `Nox.transfer`,
`Nox.allow`, etc. - operating on encrypted types (`euint256`, `ebool`)
inline in your function. The off-chain TEE computation happens
asynchronously after your transaction, but the handle referencing the
result is computed deterministically on-chain and returned immediately, so
your Solidity logic reads as synchronous. This version reflects that.

## What's private, and what isn't

Nox hides **amounts and balances**, not addresses. A payout recipient is a
plaintext address (same as any confidential-token design - see the Token
Operations reference on docs.noxprotocol.io). What's hidden here is how
much moved and what the resulting balances are - not who received
something. Even the `success`/`failure` outcome of a transfer is encrypted
by default (the docs explain this explicitly: exposing plaintext
success/failure would create a "binary oracle" leaking balance info).

## Why this fits the WTF Hackathon Nox brief
- Integrates cleanly: deploys as a standard Safe module - no fork or
  modification of Safe itself.
- Real privacy, not just encryption theater: amount and balance state
  are genuinely hidden on-chain; access is opt-in and explicit via
  Nox.allow / addViewer.
- Deployable pattern: confidential treasury payouts (DAO payroll,
  grants, contributor payments) is a real product need.

## Structure
```
src/
  ISafe.sol             minimal Safe interface (swap for official
                         safe-contracts import when you have network)
  NoxPayoutModule.sol    the module: fund() + requestPayout() + balanceOf()
script/
  Deploy.s.sol           deployment script (no Nox address needed - it's
                         a linked library, not a separate deployed contract)
test/
  NoxPayoutModule.t.sol  access-control tests (see note below on scope)
  mocks/MockSafe.sol     simulates Safe's execTransactionFromModule
package.json             pulls the real Nox Solidity library via npm
```

## Known gap: encrypted-value round-trip testing

Encrypted inputs (externalEuint256 + proof) are normally produced
client-side by the Nox JS SDK's encryptInput, which signs an EIP-712
proof - not something fabricable from plain Foundry/Solidity. Current
tests cover access control only. Before the demo, either:
- write a Foundry FFI test shelling out to a small Node script using the
  JS SDK to generate a real encrypted input, or
- check the "Hello World" / "Networks" docs pages for whether Nox ships
  its own local test harness/mock for this.

## Also still open
- [ ] Whether a withdraw path (recipient claims their confidential
      balance out to real ETH via the Safe) is in scope for the demo -
      not implemented yet; would need either a public-decryption step
      (Nox.allowPublicDecryption) or an off-chain-proof claim flow.
- [ ] Confirm which chain/testnet the hackathon wants submissions on

## Getting this running in Termux
```
npm install
forge install foundry-rs/forge-std
forge build
forge test -vvv
```
