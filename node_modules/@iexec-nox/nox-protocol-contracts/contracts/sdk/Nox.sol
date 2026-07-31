// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {HandleUtils} from "../utils/HandleUtils.sol";
import {TEEType, TypeUtils} from "../utils/TypeUtils.sol";
import {INoxCompute} from "../interfaces/INoxCompute.sol";
import "encrypted-types/EncryptedTypes.sol";

/**
 * @title Nox
 * @notice Library providing convenient functions for TEE confidential computations.
 */
library Nox {
    // ============ Errors ============

    error MalformedDecryptedData(bytes data);

    // ============ Address resolution ============

    /**
     * @dev Returns the NoxCompute contract address for the current chain.
     * Supports:
     * - Hardhat local development chain (31337)
     * - Arbitrum Sepolia (421614)
     * - Ethereum Sepolia (11155111)
     */
    function noxComputeContract() internal view returns (address) {
        // Hardhat local development chain
        if (block.chainid == 31337) {
            return 0x75C6AF4430cc474b1bb9b8540b7E46D6f8e1C685;
        }
        // Arbitrum Sepolia
        if (block.chainid == 421614) {
            return 0xd464B198f06756a1d00be223634b85E0a731c229;
        }
        // Ethereum Sepolia
        if (block.chainid == 11155111) {
            return 0x24Ef36Ec5b626D7DCD09a98F3083c2758F0F77bF;
        }
        revert("Nox: Unsupported chain");
    }

    // =========== Handle initialization checks ============

    /**
     * @dev Checks if an encrypted boolean handle is initialized.
     * This is a basic check and does not guarantee that the handle
     * is valid or recognized by the ACL.
     * @param handle encrypted boolean handle
     */
    function isInitialized(ebool handle) internal pure returns (bool) {
        return ebool.unwrap(handle) != 0;
    }

    /**
     * @dev Checks if an encrypted uint16 handle is initialized.
     * This is a basic check and does not guarantee that the handle
     * is valid or recognized by the ACL.
     * @param handle encrypted uint16 handle
     */
    function isInitialized(euint16 handle) internal pure returns (bool) {
        return euint16.unwrap(handle) != 0;
    }

    /**
     * @dev Checks if an encrypted uint256 handle is initialized.
     * This is a basic check and does not guarantee that the handle
     * is valid or recognized by the ACL.
     * @param handle encrypted uint256 handle
     */
    function isInitialized(euint256 handle) internal pure returns (bool) {
        return euint256.unwrap(handle) != 0;
    }

    /**
     * @dev Checks if an encrypted int16 handle is initialized.
     * This is a basic check and does not guarantee that the handle
     * is valid or recognized by the ACL.
     * @param handle encrypted int16 handle
     */
    function isInitialized(eint16 handle) internal pure returns (bool) {
        return eint16.unwrap(handle) != 0;
    }

    /**
     * @dev Checks if an encrypted int256 handle is initialized.
     * This is a basic check and does not guarantee that the handle
     * is valid or recognized by the ACL.
     * @param handle encrypted int256 handle
     */
    function isInitialized(eint256 handle) internal pure returns (bool) {
        return eint256.unwrap(handle) != 0;
    }

    // ============ Trivial Encryption Functions ============

    /**
     * @dev Converts a plaintext boolean to an encrypted boolean.
     */
    function toEbool(bool value) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().wrapAsPublicHandle(
                    bytes32(uint256(value ? 1 : 0)),
                    TEEType.Bool
                )
            );
    }

    /**
     * @dev Convert a plaintext value to an encrypted euint16 integer.
     */
    function toEuint16(uint16 value) internal returns (euint16) {
        return
            euint16.wrap(
                _noxComputeContract().wrapAsPublicHandle(bytes32(uint256(value)), TEEType.Uint16)
            );
    }

    /**
     * @dev Convert a plaintext value to an encrypted euint256 integer.
     */
    function toEuint256(uint256 value) internal returns (euint256) {
        return
            euint256.wrap(
                _noxComputeContract().wrapAsPublicHandle(bytes32(value), TEEType.Uint256)
            );
    }

    /**
     * @dev Convert a plaintext value to an encrypted eint16 integer.
     */
    function toEint16(int16 value) internal returns (eint16) {
        return
            eint16.wrap(
                _noxComputeContract().wrapAsPublicHandle(
                    bytes32(uint256(uint16(value))),
                    TEEType.Int16
                )
            );
    }

    /**
     * @dev Convert a plaintext value to an encrypted eint256 integer.
     */
    function toEint256(int256 value) internal returns (eint256) {
        return
            eint256.wrap(
                _noxComputeContract().wrapAsPublicHandle(bytes32(uint256(value)), TEEType.Int256)
            );
    }

    // ============ Handle validation ============

    function fromExternal(
        externalEbool externalHandle,
        bytes calldata handleProof
    ) internal returns (ebool) {
        bytes32 handle = externalEbool.unwrap(externalHandle);
        _noxComputeContract().validateInputProof(handle, msg.sender, handleProof, TEEType.Bool);
        return ebool.wrap(handle);
    }

    function fromExternal(
        externalEuint16 externalHandle,
        bytes calldata handleProof
    ) internal returns (euint16) {
        bytes32 handle = externalEuint16.unwrap(externalHandle);
        _noxComputeContract().validateInputProof(handle, msg.sender, handleProof, TEEType.Uint16);
        return euint16.wrap(handle);
    }

    function fromExternal(
        externalEuint256 externalHandle,
        bytes calldata handleProof
    ) internal returns (euint256) {
        bytes32 handle = externalEuint256.unwrap(externalHandle);
        _noxComputeContract().validateInputProof(handle, msg.sender, handleProof, TEEType.Uint256);
        return euint256.wrap(handle);
    }

    function fromExternal(
        externalEint16 externalHandle,
        bytes calldata handleProof
    ) internal returns (eint16) {
        bytes32 handle = externalEint16.unwrap(externalHandle);
        _noxComputeContract().validateInputProof(handle, msg.sender, handleProof, TEEType.Int16);
        return eint16.wrap(handle);
    }

    function fromExternal(
        externalEint256 externalHandle,
        bytes calldata handleProof
    ) internal returns (eint256) {
        bytes32 handle = externalEint256.unwrap(externalHandle);
        _noxComputeContract().validateInputProof(handle, msg.sender, handleProof, TEEType.Int256);
        return eint256.wrap(handle);
    }

    // ============ Arithmetic primitives ============

    function add(euint16 a, euint16 b) internal returns (euint16) {
        return
            euint16.wrap(
                _noxComputeContract().add(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function add(euint256 a, euint256 b) internal returns (euint256) {
        return
            euint256.wrap(
                _noxComputeContract().add(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function add(eint16 a, eint16 b) internal returns (eint16) {
        return
            eint16.wrap(
                _noxComputeContract().add(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function add(eint256 a, eint256 b) internal returns (eint256) {
        return
            eint256.wrap(
                _noxComputeContract().add(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    function sub(euint16 a, euint16 b) internal returns (euint16) {
        return
            euint16.wrap(
                _noxComputeContract().sub(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function sub(euint256 a, euint256 b) internal returns (euint256) {
        return
            euint256.wrap(
                _noxComputeContract().sub(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function sub(eint16 a, eint16 b) internal returns (eint16) {
        return
            eint16.wrap(
                _noxComputeContract().sub(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function sub(eint256 a, eint256 b) internal returns (eint256) {
        return
            eint256.wrap(
                _noxComputeContract().sub(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    function mul(euint16 a, euint16 b) internal returns (euint16) {
        return
            euint16.wrap(
                _noxComputeContract().mul(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function mul(euint256 a, euint256 b) internal returns (euint256) {
        return
            euint256.wrap(
                _noxComputeContract().mul(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function mul(eint16 a, eint16 b) internal returns (eint16) {
        return
            eint16.wrap(
                _noxComputeContract().mul(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function mul(eint256 a, eint256 b) internal returns (eint256) {
        return
            eint256.wrap(
                _noxComputeContract().mul(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    function div(euint16 a, euint16 b) internal returns (euint16) {
        return
            euint16.wrap(
                _noxComputeContract().div(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function div(euint256 a, euint256 b) internal returns (euint256) {
        return
            euint256.wrap(
                _noxComputeContract().div(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function div(eint16 a, eint16 b) internal returns (eint16) {
        return
            eint16.wrap(
                _noxComputeContract().div(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function div(eint256 a, eint256 b) internal returns (eint256) {
        return
            eint256.wrap(
                _noxComputeContract().div(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    function safeAdd(euint16 a, euint16 b) internal returns (ebool, euint16) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeAdd(
            _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
            _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
        );
        return (ebool.wrap(success), euint16.wrap(result));
    }

    function safeAdd(euint256 a, euint256 b) internal returns (ebool, euint256) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeAdd(
            _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
            _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
        );
        return (ebool.wrap(success), euint256.wrap(result));
    }

    function safeAdd(eint16 a, eint16 b) internal returns (ebool, eint16) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeAdd(
            _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
            _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
        );
        return (ebool.wrap(success), eint16.wrap(result));
    }

    function safeAdd(eint256 a, eint256 b) internal returns (ebool, eint256) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeAdd(
            _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
            _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
        );
        return (ebool.wrap(success), eint256.wrap(result));
    }

    function safeSub(euint16 a, euint16 b) internal returns (ebool, euint16) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeSub(
            _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
            _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
        );
        return (ebool.wrap(success), euint16.wrap(result));
    }

    function safeSub(euint256 a, euint256 b) internal returns (ebool, euint256) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeSub(
            _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
            _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
        );
        return (ebool.wrap(success), euint256.wrap(result));
    }

    function safeSub(eint16 a, eint16 b) internal returns (ebool, eint16) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeSub(
            _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
            _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
        );
        return (ebool.wrap(success), eint16.wrap(result));
    }

    function safeSub(eint256 a, eint256 b) internal returns (ebool, eint256) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeSub(
            _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
            _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
        );
        return (ebool.wrap(success), eint256.wrap(result));
    }

    function safeMul(euint16 a, euint16 b) internal returns (ebool, euint16) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeMul(
            _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
            _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
        );
        return (ebool.wrap(success), euint16.wrap(result));
    }

    function safeMul(euint256 a, euint256 b) internal returns (ebool, euint256) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeMul(
            _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
            _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
        );
        return (ebool.wrap(success), euint256.wrap(result));
    }

    function safeMul(eint16 a, eint16 b) internal returns (ebool, eint16) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeMul(
            _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
            _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
        );
        return (ebool.wrap(success), eint16.wrap(result));
    }

    function safeMul(eint256 a, eint256 b) internal returns (ebool, eint256) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeMul(
            _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
            _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
        );
        return (ebool.wrap(success), eint256.wrap(result));
    }

    function safeDiv(euint16 a, euint16 b) internal returns (ebool, euint16) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeDiv(
            _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
            _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
        );
        return (ebool.wrap(success), euint16.wrap(result));
    }

    function safeDiv(euint256 a, euint256 b) internal returns (ebool, euint256) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeDiv(
            _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
            _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
        );
        return (ebool.wrap(success), euint256.wrap(result));
    }

    function safeDiv(eint16 a, eint16 b) internal returns (ebool, eint16) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeDiv(
            _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
            _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
        );
        return (ebool.wrap(success), eint16.wrap(result));
    }

    function safeDiv(eint256 a, eint256 b) internal returns (ebool, eint256) {
        (bytes32 success, bytes32 result) = _noxComputeContract().safeDiv(
            _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
            _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
        );
        return (ebool.wrap(success), eint256.wrap(result));
    }

    function select(ebool condition, euint16 ifTrue, euint16 ifFalse) internal returns (euint16) {
        return
            euint16.wrap(
                _noxComputeContract().select(
                    _resolveUndefinedHandle(ebool.unwrap(condition), TEEType.Bool),
                    _resolveUndefinedHandle(euint16.unwrap(ifTrue), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(ifFalse), TEEType.Uint16)
                )
            );
    }

    function select(
        ebool condition,
        euint256 ifTrue,
        euint256 ifFalse
    ) internal returns (euint256) {
        return
            euint256.wrap(
                _noxComputeContract().select(
                    _resolveUndefinedHandle(ebool.unwrap(condition), TEEType.Bool),
                    _resolveUndefinedHandle(euint256.unwrap(ifTrue), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(ifFalse), TEEType.Uint256)
                )
            );
    }

    function select(ebool condition, eint16 ifTrue, eint16 ifFalse) internal returns (eint16) {
        return
            eint16.wrap(
                _noxComputeContract().select(
                    _resolveUndefinedHandle(ebool.unwrap(condition), TEEType.Bool),
                    _resolveUndefinedHandle(eint16.unwrap(ifTrue), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(ifFalse), TEEType.Int16)
                )
            );
    }

    function select(ebool condition, eint256 ifTrue, eint256 ifFalse) internal returns (eint256) {
        return
            eint256.wrap(
                _noxComputeContract().select(
                    _resolveUndefinedHandle(ebool.unwrap(condition), TEEType.Bool),
                    _resolveUndefinedHandle(eint256.unwrap(ifTrue), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(ifFalse), TEEType.Int256)
                )
            );
    }

    function eq(euint16 a, euint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().eq(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function eq(euint256 a, euint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().eq(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function eq(eint16 a, eint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().eq(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function eq(eint256 a, eint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().eq(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    function ne(euint16 a, euint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().ne(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function ne(euint256 a, euint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().ne(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function ne(eint16 a, eint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().ne(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function ne(eint256 a, eint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().ne(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    function lt(euint16 a, euint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().lt(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function lt(euint256 a, euint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().lt(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function lt(eint16 a, eint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().lt(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function lt(eint256 a, eint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().lt(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    function le(euint16 a, euint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().le(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function le(euint256 a, euint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().le(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function le(eint16 a, eint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().le(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function le(eint256 a, eint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().le(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    function gt(euint16 a, euint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().gt(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function gt(euint256 a, euint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().gt(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function gt(eint16 a, eint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().gt(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function gt(eint256 a, eint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().gt(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    function ge(euint16 a, euint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().ge(
                    _resolveUndefinedHandle(euint16.unwrap(a), TEEType.Uint16),
                    _resolveUndefinedHandle(euint16.unwrap(b), TEEType.Uint16)
                )
            );
    }

    function ge(euint256 a, euint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().ge(
                    _resolveUndefinedHandle(euint256.unwrap(a), TEEType.Uint256),
                    _resolveUndefinedHandle(euint256.unwrap(b), TEEType.Uint256)
                )
            );
    }

    function ge(eint16 a, eint16 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().ge(
                    _resolveUndefinedHandle(eint16.unwrap(a), TEEType.Int16),
                    _resolveUndefinedHandle(eint16.unwrap(b), TEEType.Int16)
                )
            );
    }

    function ge(eint256 a, eint256 b) internal returns (ebool) {
        return
            ebool.wrap(
                _noxComputeContract().ge(
                    _resolveUndefinedHandle(eint256.unwrap(a), TEEType.Int256),
                    _resolveUndefinedHandle(eint256.unwrap(b), TEEType.Int256)
                )
            );
    }

    // ============ ADVANCED FUNCTIONS ============

    /**
     * @dev Atomically transfers `amount` from `balanceFrom` to `balanceTo`.
     * Returns the new balances and whether the transfer was successful.
     * The transfer will fail if `balanceFrom < amount`.
     */
    function transfer(
        euint256 balanceFrom,
        euint256 balanceTo,
        euint256 amount
    ) internal returns (ebool success, euint256 newBalanceFrom, euint256 newBalanceTo) {
        (bytes32 _success, bytes32 _newBalanceFrom, bytes32 _newBalanceTo) = _noxComputeContract()
            .transfer(
                _resolveUndefinedHandle(euint256.unwrap(balanceFrom), TEEType.Uint256),
                _resolveUndefinedHandle(euint256.unwrap(balanceTo), TEEType.Uint256),
                _resolveUndefinedHandle(euint256.unwrap(amount), TEEType.Uint256)
            );
        success = ebool.wrap(_success);
        newBalanceFrom = euint256.wrap(_newBalanceFrom);
        newBalanceTo = euint256.wrap(_newBalanceTo);
    }

    /**
     * @dev Atomically mints `amount` to `balanceTo` and increases `totalSupply` by `amount`.
     * Returns the new balance, new total supply, and whether the mint was successful.
     * The mint will fail if `totalSupply + amount` overflows.
     */
    function mint(
        euint256 balanceTo,
        euint256 amount,
        euint256 totalSupply
    ) internal returns (ebool success, euint256 newBalanceTo, euint256 newTotalSupply) {
        (bytes32 _success, bytes32 _newBalanceTo, bytes32 _newTotalSupply) = _noxComputeContract()
            .mint(
                _resolveUndefinedHandle(euint256.unwrap(balanceTo), TEEType.Uint256),
                _resolveUndefinedHandle(euint256.unwrap(amount), TEEType.Uint256),
                _resolveUndefinedHandle(euint256.unwrap(totalSupply), TEEType.Uint256)
            );
        success = ebool.wrap(_success);
        newBalanceTo = euint256.wrap(_newBalanceTo);
        newTotalSupply = euint256.wrap(_newTotalSupply);
    }

    /**
     * @dev Atomically burns `amount` from `balanceFrom` and decreases `totalSupply` by `amount`.
     * Returns the new balance, new total supply, and whether the burn was successful.
     * The burn will fail if `balanceFrom < amount`.
     */
    function burn(
        euint256 balanceFrom,
        euint256 amount,
        euint256 totalSupply
    ) internal returns (ebool success, euint256 newBalanceFrom, euint256 newTotalSupply) {
        (bytes32 _success, bytes32 _newBalanceFrom, bytes32 _newTotalSupply) = _noxComputeContract()
            .burn(
                _resolveUndefinedHandle(euint256.unwrap(balanceFrom), TEEType.Uint256),
                _resolveUndefinedHandle(euint256.unwrap(amount), TEEType.Uint256),
                _resolveUndefinedHandle(euint256.unwrap(totalSupply), TEEType.Uint256)
            );
        success = ebool.wrap(_success);
        newBalanceFrom = euint256.wrap(_newBalanceFrom);
        newTotalSupply = euint256.wrap(_newTotalSupply);
    }

    // ============ PERMISSION MANAGEMENT ============

    /**
     * @dev Allows the use of value for the address account.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allow(ebool value, address account) internal {
        _allowIfNotPublic(ebool.unwrap(value), account);
    }

    /**
     * @dev Allows the use of value for the address account.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allow(euint16 value, address account) internal {
        _allowIfNotPublic(euint16.unwrap(value), account);
    }

    /**
     * @dev Allows the use of value for the address account.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allow(euint256 value, address account) internal {
        _allowIfNotPublic(euint256.unwrap(value), account);
    }

    /**
     * @dev Allows the use of value for the address account.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allow(eint16 value, address account) internal {
        _allowIfNotPublic(eint16.unwrap(value), account);
    }

    /**
     * @dev Allows the use of value for the address account.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allow(eint256 value, address account) internal {
        _allowIfNotPublic(eint256.unwrap(value), account);
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowThis(ebool value) internal {
        _allowIfNotPublic(ebool.unwrap(value), address(this));
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowThis(euint16 value) internal {
        _allowIfNotPublic(euint16.unwrap(value), address(this));
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowThis(euint256 value) internal {
        _allowIfNotPublic(euint256.unwrap(value), address(this));
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowThis(eint16 value) internal {
        _allowIfNotPublic(eint16.unwrap(value), address(this));
    }

    /**
     * @dev Allows the use of value for this address (address(this)).
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowThis(eint256 value) internal {
        _allowIfNotPublic(eint256.unwrap(value), address(this));
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowTransient(ebool value, address account) internal {
        _allowTransientIfNotPublic(ebool.unwrap(value), account);
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowTransient(euint16 value, address account) internal {
        _allowTransientIfNotPublic(euint16.unwrap(value), account);
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowTransient(euint256 value, address account) internal {
        _allowTransientIfNotPublic(euint256.unwrap(value), account);
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowTransient(eint16 value, address account) internal {
        _allowTransientIfNotPublic(eint16.unwrap(value), account);
    }

    /**
     * @dev Allows the use of value by address account for this transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function allowTransient(eint256 value, address account) internal {
        _allowTransientIfNotPublic(eint256.unwrap(value), account);
    }

    /**
     * @dev Revokes transient access to value for address account within the current transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function disallowTransient(ebool value, address account) internal {
        _disallowTransientIfNotPublic(ebool.unwrap(value), account);
    }

    /**
     * @dev Revokes transient access to value for address account within the current transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function disallowTransient(euint16 value, address account) internal {
        _disallowTransientIfNotPublic(euint16.unwrap(value), account);
    }

    /**
     * @dev Revokes transient access to value for address account within the current transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function disallowTransient(euint256 value, address account) internal {
        _disallowTransientIfNotPublic(euint256.unwrap(value), account);
    }

    /**
     * @dev Revokes transient access to value for address account within the current transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function disallowTransient(eint16 value, address account) internal {
        _disallowTransientIfNotPublic(eint16.unwrap(value), account);
    }

    /**
     * @dev Revokes transient access to value for address account within the current transaction.
     * Silently skips public handles (they are already accessible by everyone).
     */
    function disallowTransient(eint256 value, address account) internal {
        _disallowTransientIfNotPublic(eint256.unwrap(value), account);
    }

    /**
     * @dev Checks if the handle is allowed for the account.
     */
    function isAllowed(ebool handle, address account) internal view returns (bool) {
        return _noxComputeContract().isAllowed(ebool.unwrap(handle), account);
    }

    /**
     * @dev Checks if the handle is allowed for the account.
     */
    function isAllowed(euint16 handle, address account) internal view returns (bool) {
        return _noxComputeContract().isAllowed(euint16.unwrap(handle), account);
    }

    /**
     * @dev Checks if the handle is allowed for the account.
     */
    function isAllowed(euint256 handle, address account) internal view returns (bool) {
        return _noxComputeContract().isAllowed(euint256.unwrap(handle), account);
    }

    /**
     * @dev Checks if the handle is allowed for the account.
     */
    function isAllowed(eint16 handle, address account) internal view returns (bool) {
        return _noxComputeContract().isAllowed(eint16.unwrap(handle), account);
    }

    /**
     * @dev Checks if the handle is allowed for the account.
     */
    function isAllowed(eint256 handle, address account) internal view returns (bool) {
        return _noxComputeContract().isAllowed(eint256.unwrap(handle), account);
    }

    // ============ VIEWER MANAGEMENT ============

    /**
     * @dev Adds a viewer for an ebool handle.
     */
    function addViewer(ebool value, address viewer) internal {
        _noxComputeContract().addViewer(ebool.unwrap(value), viewer);
    }

    /**
     * @dev Adds a viewer for an euint16 handle.
     */
    function addViewer(euint16 value, address viewer) internal {
        _noxComputeContract().addViewer(euint16.unwrap(value), viewer);
    }

    /**
     * @dev Adds a viewer for an euint256 handle.
     */
    function addViewer(euint256 value, address viewer) internal {
        _noxComputeContract().addViewer(euint256.unwrap(value), viewer);
    }

    /**
     * @dev Adds a viewer for an eint16 handle.
     */
    function addViewer(eint16 value, address viewer) internal {
        _noxComputeContract().addViewer(eint16.unwrap(value), viewer);
    }

    /**
     * @dev Adds a viewer for an eint256 handle.
     */
    function addViewer(eint256 value, address viewer) internal {
        _noxComputeContract().addViewer(eint256.unwrap(value), viewer);
    }

    /**
     * @dev Checks if the viewer can view the handle.
     */
    function isViewer(ebool handle, address viewer) internal view returns (bool) {
        return _noxComputeContract().isViewer(ebool.unwrap(handle), viewer);
    }

    /**
     * @dev Checks if the viewer can view the handle.
     */
    function isViewer(euint16 handle, address viewer) internal view returns (bool) {
        return _noxComputeContract().isViewer(euint16.unwrap(handle), viewer);
    }

    /**
     * @dev Checks if the viewer can view the handle.
     */
    function isViewer(euint256 handle, address viewer) internal view returns (bool) {
        return _noxComputeContract().isViewer(euint256.unwrap(handle), viewer);
    }

    /**
     * @dev Checks if the viewer can view the handle.
     */
    function isViewer(eint16 handle, address viewer) internal view returns (bool) {
        return _noxComputeContract().isViewer(eint16.unwrap(handle), viewer);
    }

    /**
     * @dev Checks if the viewer can view the handle.
     */
    function isViewer(eint256 handle, address viewer) internal view returns (bool) {
        return _noxComputeContract().isViewer(eint256.unwrap(handle), viewer);
    }

    // ============ PUBLIC DECRYPTION ============

    /**
     * @dev Marks an ebool handle as publicly decryptable.
     */
    function allowPublicDecryption(ebool value) internal {
        _noxComputeContract().allowPublicDecryption(ebool.unwrap(value));
    }

    /**
     * @dev Marks an euint16 handle as publicly decryptable.
     */
    function allowPublicDecryption(euint16 value) internal {
        _noxComputeContract().allowPublicDecryption(euint16.unwrap(value));
    }

    /**
     * @dev Marks an euint256 handle as publicly decryptable.
     */
    function allowPublicDecryption(euint256 value) internal {
        _noxComputeContract().allowPublicDecryption(euint256.unwrap(value));
    }

    /**
     * @dev Marks an eint16 handle as publicly decryptable.
     */
    function allowPublicDecryption(eint16 value) internal {
        _noxComputeContract().allowPublicDecryption(eint16.unwrap(value));
    }

    /**
     * @dev Marks an eint256 handle as publicly decryptable.
     */
    function allowPublicDecryption(eint256 value) internal {
        _noxComputeContract().allowPublicDecryption(eint256.unwrap(value));
    }

    /**
     * @dev Checks if the handle is publicly decryptable.
     */
    function isPubliclyDecryptable(ebool handle) internal view returns (bool) {
        return _noxComputeContract().isPubliclyDecryptable(ebool.unwrap(handle));
    }

    /**
     * @dev Checks if the handle is publicly decryptable.
     */
    function isPubliclyDecryptable(euint16 handle) internal view returns (bool) {
        return _noxComputeContract().isPubliclyDecryptable(euint16.unwrap(handle));
    }

    /**
     * @dev Checks if the handle is publicly decryptable.
     */
    function isPubliclyDecryptable(euint256 handle) internal view returns (bool) {
        return _noxComputeContract().isPubliclyDecryptable(euint256.unwrap(handle));
    }

    /**
     * @dev Checks if the handle is publicly decryptable.
     */
    function isPubliclyDecryptable(eint16 handle) internal view returns (bool) {
        return _noxComputeContract().isPubliclyDecryptable(eint16.unwrap(handle));
    }

    /**
     * @dev Checks if the handle is publicly decryptable.
     */
    function isPubliclyDecryptable(eint256 handle) internal view returns (bool) {
        return _noxComputeContract().isPubliclyDecryptable(eint256.unwrap(handle));
    }

    // ============ Public decryption proof verification ============

    /**
     * @dev Verifies a decryption proof and returns the decrypted boolean value.
     */
    function publicDecrypt(
        ebool handle,
        bytes calldata decryptionProof
    ) internal view returns (bool plaintextValue) {
        bytes memory result = _noxComputeContract().validateDecryptionProof(
            ebool.unwrap(handle),
            decryptionProof
        );
        require(result.length == 1, MalformedDecryptedData(result));
        require(result[0] == 0x00 || result[0] == 0x01, MalformedDecryptedData(result));
        return result[0] != 0x00;
    }

    /**
     * @dev Verifies a decryption proof and returns the decrypted uint16 value.
     */
    function publicDecrypt(
        euint16 handle,
        bytes calldata decryptionProof
    ) internal view returns (uint16 plaintextValue) {
        bytes memory result = _noxComputeContract().validateDecryptionProof(
            euint16.unwrap(handle),
            decryptionProof
        );
        require(result.length == 2, MalformedDecryptedData(result));
        return uint16(bytes2(result));
    }

    /**
     * @dev Verifies a decryption proof and returns the decrypted uint256 value.
     */
    function publicDecrypt(
        euint256 handle,
        bytes calldata decryptionProof
    ) internal view returns (uint256 plaintextValue) {
        bytes memory result = _noxComputeContract().validateDecryptionProof(
            euint256.unwrap(handle),
            decryptionProof
        );
        require(result.length == 32, MalformedDecryptedData(result));
        return uint256(bytes32(result));
    }

    /**
     * @dev Verifies a decryption proof and returns the decrypted int16 value.
     */
    function publicDecrypt(
        eint16 handle,
        bytes calldata decryptionProof
    ) internal view returns (int16 plaintextValue) {
        bytes memory result = _noxComputeContract().validateDecryptionProof(
            eint16.unwrap(handle),
            decryptionProof
        );
        require(result.length == 2, MalformedDecryptedData(result));
        return int16(uint16(bytes2(result)));
    }

    /**
     * @dev Verifies a decryption proof and returns the decrypted int256 value.
     */
    function publicDecrypt(
        eint256 handle,
        bytes calldata decryptionProof
    ) internal view returns (int256 plaintextValue) {
        bytes memory result = _noxComputeContract().validateDecryptionProof(
            eint256.unwrap(handle),
            decryptionProof
        );
        require(result.length == 32, MalformedDecryptedData(result));
        return int256(uint256(bytes32(result)));
    }

    // ============ Private helpers ============

    function _noxComputeContract() private view returns (INoxCompute) {
        return INoxCompute(noxComputeContract());
    }

    /**
     * @dev Resolves an undefined (bytes32(0)) handle to the typed zero handle for the given type.
     * If the handle is already non-zero, returns it unchanged.
     */
    function _resolveUndefinedHandle(
        bytes32 handle,
        TEEType teeType
    ) private view returns (bytes32) {
        return handle == bytes32(0) ? HandleUtils.zeroHandle(teeType) : handle;
    }

    /**
     * @dev Calls allow on NoxCompute, silently skipping public handles.
     * Public handles are already accessible by everyone and don't need ACL.
     */
    function _allowIfNotPublic(bytes32 handle, address account) private {
        if (!HandleUtils.isPublicHandle(handle)) {
            _noxComputeContract().allow(handle, account);
        }
    }

    /**
     * @dev Calls allowTransient on NoxCompute, silently skipping public handles.
     * Public handles are already accessible by everyone and don't need ACL.
     */
    function _allowTransientIfNotPublic(bytes32 handle, address account) private {
        if (!HandleUtils.isPublicHandle(handle)) {
            _noxComputeContract().allowTransient(handle, account);
        }
    }

    /**
     * @dev Calls disallowTransient on NoxCompute, silently skipping public handles.
     * Public handles are already accessible by everyone and don't need ACL.
     */
    function _disallowTransientIfNotPublic(bytes32 handle, address account) private {
        if (!HandleUtils.isPublicHandle(handle)) {
            _noxComputeContract().disallowTransient(handle, account);
        }
    }
}
