// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.35;

import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Common} from "./Common.sol";

/**
 * @title Admin
 * @notice Role-based admin layer for NoxCompute.
 * @dev Two roles drive privileged actions:
 *      - DEFAULT_ADMIN_ROLE: grants/revokes other roles.
 *      - UPGRADER_ROLE: authorizes UUPS upgrades AND updates infrastructure config
 *        (KMS public key, gateway address, proof expiration duration).
 */
abstract contract Admin is Common, AccessControlUpgradeable, UUPSUpgradeable {
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /**
     * Sets the KMS public key used for ECIES encryption.
     * Only callable by an UPGRADER_ROLE holder.
     * @param newKmsPublicKey Compressed SEC1 secp256k1 public key (33 bytes)
     */
    function setKmsPublicKey(
        bytes calldata newKmsPublicKey
    ) external override onlyRole(UPGRADER_ROLE) {
        require(newKmsPublicKey.length != 0, InvalidEmptyBytes());
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        $.kmsPublicKey = newKmsPublicKey;
        emit KmsPublicKeyUpdated(newKmsPublicKey);
    }

    /**
     * Sets Gateway wallet address.
     * Only callable by an UPGRADER_ROLE holder.
     * @param gatewayAddress New Gateway wallet address
     */
    function setGateway(address gatewayAddress) external override onlyRole(UPGRADER_ROLE) {
        require(gatewayAddress != address(0), InvalidZeroAddress());
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        $.gateway = gatewayAddress;
        emit GatewayUpdated(gatewayAddress);
    }

    /**
     * Sets the proof expiration duration.
     * Only callable by an UPGRADER_ROLE holder.
     * @param newDuration New expiration duration in seconds
     */
    function setProofExpirationDuration(
        uint256 newDuration
    ) external override onlyRole(UPGRADER_ROLE) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        $.proofExpirationDuration = newDuration;
        emit ProofExpirationDurationUpdated(newDuration);
    }

    /**
     * Returns the KMS public key used for ECIES encryption.
     */
    function kmsPublicKey() external view override returns (bytes memory) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        return $.kmsPublicKey;
    }

    /**
     * Returns the Gateway wallet address.
     */
    function gateway() external view override returns (address) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        return $.gateway;
    }

    /**
     * Returns the proof expiration duration in seconds.
     */
    function proofExpirationDuration() external view override returns (uint256) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        return $.proofExpirationDuration;
    }

    /**
     * Authorizes contract upgrades only by an UPGRADER_ROLE holder.
     */
    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal override onlyRole(UPGRADER_ROLE) {}

    /**
     * @dev Initializes AccessControl and grants the defined roles.
     */
    function _initAccessControl(address admin, address upgrader) internal {
        require(admin != address(0), InvalidZeroAddress());
        require(upgrader != address(0), InvalidZeroAddress());
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, upgrader);
    }
}
