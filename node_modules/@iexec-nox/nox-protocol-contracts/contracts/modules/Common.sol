// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.35;

import {INoxCompute} from "../interfaces/INoxCompute.sol";

/**
 * @title Common
 * @notice Shared base for all modules. Defines the ERC7201 storage layout,
 * the storage accessor, and virtual declarations for cross-module functions.
 */
abstract contract Common is INoxCompute {
    // TODO: remove `slither-disable-next-line` once Slither supports the `erc7201` builtin (added in solc 0.8.35).
    // slither-disable-next-line uninitialized-state
    bytes32 private constant NOX_COMPUTE_STORAGE_LOCATION = bytes32(
        erc7201("nox.storage.NoxCompute")
    );

    /// @custom:storage-location erc7201:nox.storage.NoxCompute
    struct NoxComputeStorage {
        // An admin of a handle can:
        //  - use it as a computation input
        //  - decrypt its associated data off-chain
        //  - make it publicly decryptable
        //  - add other admins and viewers
        mapping(bytes32 handleId => mapping(address => bool)) admins;
        // A viewer of a handle can only decrypt its associated data off-chain.
        //TODO: Make viewer expirable
        mapping(bytes32 handleId => mapping(address => bool)) viewers;
        // Handles that are publicly decryptable
        mapping(bytes32 handle => bool) isPubliclyDecryptable;
        bytes kmsPublicKey;
        address gateway;
        uint256 proofExpirationDuration;
        // Counter used to guarantee handle uniqueness when all operands are public handles
        uint256 uniqueSeedCounter;
    }

    function _getNoxComputeStorage() internal pure returns (NoxComputeStorage storage $) {
        bytes32 slot = NOX_COMPUTE_STORAGE_LOCATION;
        assembly {
            $.slot := slot
        }
    }

    // ----- Functions used cross-modules -----

    // Implemented by ACL, called by Compute.
    function _allowTransient(bytes32 handle, address account) internal virtual;

    // Implemented by ACL, called by Compute.
    function _validateAllowedForAll(
        address account,
        bytes32[] memory handles
    ) internal view virtual;
}
