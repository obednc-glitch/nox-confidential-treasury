// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal slice of the Gnosis Safe interface this module needs.
/// Swap for the official `safe-contracts` package import
/// (`forge install safe-global/safe-contracts`) once you have network
/// access — kept local here so this scaffold compiles standalone.
interface ISafe {
    enum Operation {
        Call,
        DelegateCall
    }

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation
    ) external returns (bool success);

    function isModuleEnabled(address module) external view returns (bool);
}
