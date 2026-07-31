// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.35;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {Admin} from "./modules/Admin.sol";
import {ACL} from "./modules/ACL.sol";
import {Compute} from "./modules/Compute.sol";

/**
 * @title NoxCompute
 * @notice The entry point contract for the Nox TEE compute protocol.
 * It's role includes:
 * - Managing the access control list (ACL) for encrypted handles
 * - Validating handle proofs issued by a trusted gateway
 * - Wrapping plaintext values into public handles
 * - Triggering off-chain TEE computations through event emissions
 */
contract NoxCompute is Admin, ACL, Compute {
    /**
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() EIP712("NoxCompute", "1") {
        _disableInitializers();
    }

    /**
     * Initializes the proxy contract state for a fresh deployment.
     * @param admin Address granted `DEFAULT_ADMIN_ROLE`.
     * @param upgrader Address granted `UPGRADER_ROLE`.
     * @param kmsPublicKey KMS public key for ECIES encryption.
     * @param gateway Gateway wallet address.
     */
    function initialize(
        address admin,
        address upgrader,
        bytes calldata kmsPublicKey,
        address gateway
    ) public initializer {
        // v0.1.0
        require(kmsPublicKey.length != 0, InvalidEmptyBytes());
        require(gateway != address(0), InvalidZeroAddress());
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        $.proofExpirationDuration = 1 hours;
        $.kmsPublicKey = kmsPublicKey;
        $.gateway = gateway;
        // v0.2.0
        _emitZeroHandleSeeds();
        // v0.2.3
        _initAccessControl(admin, upgrader);
    }

    /**
     * @notice Initializer of 0.2.0 upgrade for already deployed proxies.
     * @notice Emits zero handle seeds for existing proxies.
     * @dev The same logic is also called in `initialize()` for fresh deployments.
     * @dev The call to this function does not need to be protected because it does
     * not do any critical operations.
     */
    function initializeV2() public reinitializer(2) {
        _emitZeroHandleSeeds();
    }

    /**
     * @notice Initializer of 0.2.3 upgrade for already deployed proxies.
     * @notice Migrates the contract from `OwnableUpgradeable` to `AccessControlUpgradeable`:
     * initializes AccessControl, grants the two roles, and clears the legacy Ownable storage slot.
     * @param admin Address granted `DEFAULT_ADMIN_ROLE`.
     * @param upgrader Address granted `UPGRADER_ROLE`.
     */
    function initializeV3(address admin, address upgrader) public reinitializer(3) {
        _initAccessControl(admin, upgrader);
        // Clear the slot where `OwnableUpgradeable` stored the previous `_owner`
        // (ERC-7201 location for `openzeppelin.storage.Ownable`).
        // TODO: remove `slither-disable-next-line` once Slither supports the `erc7201`
        // builtin (added in solc 0.8.35).
        // slither-disable-next-line uninitialized-state
        bytes32 slot = bytes32(erc7201("openzeppelin.storage.Ownable"));
        assembly {
            sstore(slot, 0)
        }
    }
}
