// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Nox, euint256, ebool, externalEuint256} from "@iexec-nox/nox-protocol-contracts/contracts/Nox.sol";
import {ISafe} from "./ISafe.sol";

/// @title NoxPayoutModule
/// @notice A Gnosis Safe module implementing a confidential treasury ledger.
/// The Safe deposits into an encrypted internal balance; payouts move an
/// encrypted amount from the Safe's balance to a recipient's encrypted
/// balance via Nox.transfer. The amount moved, and even whether the
/// transfer succeeded, stay encrypted on-chain — only accounts explicitly
/// granted access (via Nox.allow / addViewer) can ever decrypt them.
///
/// SCOPE NOTE: Nox hides amounts/balances, not addresses — the recipient
/// of a payout is a plaintext address (same as any confidential-token
/// design; see the Token Operations reference). What's private here is
/// how much moved and what the resulting balances are, not who received
/// something.
///
/// This does not modify Safe itself — it's enabled as a standard module.
contract NoxPayoutModule {
    ISafe public immutable safe;

    /// @dev Confidential balance ledger. The Safe's own treasury balance
    /// lives under `_balances[address(safe)]`; every payout recipient
    /// gets their own encrypted entry here too.
    mapping(address => euint256) private _balances;

    /// @notice Emitted on deposit/payout. Deliberately carries no amount
    /// and no success/failure signal — both stay encrypted per Nox's
    /// all-or-nothing semantics (see Token Operations docs: exposing
    /// success/failure in plaintext would create a binary oracle on
    /// balance state).
    event ConfidentialDeposit(address indexed account);
    event ConfidentialPayout(address indexed from, address indexed to);

    error NotSafeOwnerFlow();

    constructor(address _safe) {
        safe = ISafe(_safe);
    }

    modifier onlySafe() {
        if (msg.sender != address(safe)) revert NotSafeOwnerFlow();
        _;
    }

    /// @notice Fund the Safe's confidential treasury balance. Called by
    /// the Safe (via normal Safe-owner-approved transaction) with an
    /// amount encrypted client-side using the JS SDK.
    function fund(externalEuint256 encryptedAmount, bytes calldata proof) external onlySafe {
        euint256 amount = Nox.fromExternal(encryptedAmount, proof);
        euint256 treasury = _balances[address(safe)];

        if (!Nox.isInitialized(treasury)) {
            treasury = Nox.toEuint256(0);
            Nox.allowThis(treasury);
        }

        euint256 newTreasury = Nox.add(treasury, amount);
        Nox.allowThis(newTreasury);
        _balances[address(safe)] = newTreasury;

        emit ConfidentialDeposit(address(safe));
    }

    /// @notice Pay a recipient confidentially out of the Safe's treasury
    /// balance. The amount is encrypted client-side before this call;
    /// this contract never sees it in plaintext. Follows Nox's
    /// all-or-nothing semantics: if the treasury balance is insufficient,
    /// nothing changes and the encrypted `success` handle reflects that
    /// — no plaintext revert, no plaintext success flag.
    ///
    /// @param recipient Plaintext address — see SCOPE NOTE above on what
    /// Nox does and doesn't hide.
    function requestPayout(
        address recipient,
        externalEuint256 encryptedAmount,
        bytes calldata proof
    ) external onlySafe {
        euint256 amount = Nox.fromExternal(encryptedAmount, proof);
        euint256 treasury = _balances[address(safe)];
        euint256 recipientBalance = _balances[recipient];

        if (!Nox.isInitialized(recipientBalance)) {
            recipientBalance = Nox.toEuint256(0);
        }

        (ebool ok, euint256 newTreasury, euint256 newRecipientBalance) =
            Nox.transfer(treasury, recipientBalance, amount);

        // Keep the contract able to reuse both handles in future calls.
        Nox.allowThis(ok);
        Nox.allowThis(newTreasury);
        Nox.allowThis(newRecipientBalance);

        // Let the recipient decrypt their own new balance off-chain via
        // the JS SDK. Does NOT let them decrypt `ok` or the treasury
        // balance — narrowest access that still lets them see what
        // they received.
        Nox.addViewer(newRecipientBalance, recipient);

        // Let the Safe (i.e. its owners, off-chain via the JS SDK) see
        // both the outcome and its own updated treasury balance, for
        // bookkeeping/audit purposes.
        Nox.addViewer(ok, address(safe));
        Nox.addViewer(newTreasury, address(safe));

        _balances[address(safe)] = newTreasury;
        _balances[recipient] = newRecipientBalance;

        emit ConfidentialPayout(address(safe), recipient);
    }

    /// @notice Returns the caller's own encrypted balance handle. Actual
    /// decryption happens off-chain via the JS SDK by whoever holds
    /// viewer/admin access to this handle (see Nox Access Control docs).
    function balanceOf(address account) external view returns (euint256) {
        return _balances[account];
    }
}
