# Nox Confidential Safe Treasury Ledger

A Gnosis Safe module implementing a confidential **internal accounting
ledger**: the Safe deposits into an encrypted balance it holds within this
contract, and payouts move an encrypted amount from that balance to a
recipient's encrypted balance via Nox's `transfer` primitive. The amount
moved — and even whether a payout succeeded — stays encrypted on-chain;
only accounts explicitly granted access can decrypt it off-chain via the
Nox JS SDK.

**Important scope note:** this module does **not** move real ETH or
tokens. `fund()` and `requestPayout()` only update encrypted numbers in
this contract's own storage (`_balances`) — there is no `payable`, no
`.call{value:...}`, no ERC-20 transfer anywhere in the code. What's
proven here is a genuine confidential accounting primitive (think:
private payroll bookkeeping, or a settlement layer that nets out before
a final real transfer) — not yet a complete payment rail. A real payout
of funds would require adding a `withdraw()` path that moves actual
assets out via `execTransactionFromModule` once a balance is decrypted;
see "Also still open" below.

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
- [ ] **No real asset movement yet.** `fund()`/`requestPayout()` only
      update encrypted balances in this contract's own storage. Adding a
      `withdraw()` function (recipient decrypts their balance, submits
      proof, contract calls `execTransactionFromModule` to send real
      ETH/tokens via the Safe) would close the loop into an actual
      payment system. Not implemented — would need either a
      public-decryption step (`Nox.allowPublicDecryption`) or an
      off-chain-proof claim flow to let the contract verify the claimed
      amount without just trusting the caller.
- [ ] Confirm which chain/testnet the hackathon wants submissions on

## Getting this running in Termux
```
npm install
forge install foundry-rs/forge-std
forge build
forge test -vvv
```

## How judges can test this live

Deployed on **Ethereum Sepolia**:
- Module: `0x9B83Efc08bECB7b73b5A892aaeEE68956Ce84746`
- Demo Safe (1-of-1): `0x6b2895225Ccc174FFda8c8346E602698C7e43c66`

**Easiest — the hosted front-end:**
https://obednc-glitch.github.io/nox-confidential-treasury/
Connect a wallet, encrypt an amount client-side, copy the handle/proof
into Safe's Transaction Builder to call `fund`/`requestPayout`, then
connect as the recipient in Step 3 to decrypt and confirm the exact
amount landed in their ledger entry.

**Option A — Etherscan (if verified):**
Go to the module address above on sepolia.etherscan.io, use the
"Read/Write Contract" tabs directly.

**Option B — Safe UI + scripts directly:**
1. Go to app.safe.global, open the Safe address above (or connect your own
   Safe and enable this module via Settings > Modules > paste the module
   address)
2. Clone this repo, `npm install`, then generate an encrypted amount:
   `MODULE_ADDRESS=0x9B83... SAFE_ADDRESS=<your Safe> node scripts/encrypt.js 500`
3. In Safe's Transaction Builder app, call `fund(bytes32,bytes)` or
   `requestPayout(address,bytes32,bytes)` on the module with the printed
   handle/proof
4. Decrypt any balance you're authorized to see:
   `MODULE_ADDRESS=0x9B83... node scripts/decrypt.js <address>`

**What to look for:** the on-chain transaction data and event logs never
show a plaintext amount — only an authorized decrypt (step 4 above)
reveals the real number. Note this confirms the *encrypted ledger entry*
updated correctly — it does not move real Sepolia ETH (see scope note
at the top of this README).
