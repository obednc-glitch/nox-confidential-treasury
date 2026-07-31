// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.35;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {HandleUtils} from "../utils/HandleUtils.sol";
import {TEEType, TypeUtils} from "../utils/TypeUtils.sol";
import {INoxCompute} from "../interfaces/INoxCompute.sol";
import {Common} from "./Common.sol";

/**
 * @title Compute
 * @notice TEE compute operations: handle wrapping, EIP712 proof validation,
 * arithmetic, comparisons, optimized transfer/mint/burn.
 *
 * @dev Using non-upgradeable EIP712 is safe here as it has no storage and the config is saved
 * in immutable variables, which is sufficient since we don't use multiple proxies with the
 * same implementation.
 */
abstract contract Compute is Common, EIP712 {
    using TypeUtils for bytes32;

    uint8 private constant HANDLE_VERSION = 0;

    bytes32 public constant HANDLE_PROOF_TYPEHASH = keccak256(
        "HandleProof(bytes32 handle,address owner,address app,uint256 createdAt)"
    );
    bytes32 public constant DECRYPTION_PROOF_TYPEHASH = keccak256(
        "DecryptionProof(bytes32 handle,bytes decryptedResult)"
    );

    /// @inheritdoc INoxCompute
    function wrapAsPublicHandle(
        bytes32 value,
        TEEType teeType
    ) external override returns (bytes32 result) {
        bytes32[] memory operands = new bytes32[](1);
        operands[0] = value;
        // Deterministic handle: same (value, type) always produces the same handle
        // Generate a public handle (outputIndex=0, uniqueSeed=0, attrs=0x00)
        result = _generateHandle(
            Operator.WrapAsPublicHandle,
            operands,
            teeType,
            0,
            0,
            bytes1(0x00)
        );
        _allowTransient(result, msg.sender);
        emit WrapAsPublicHandle(msg.sender, value, teeType, result);
    }

    /// @inheritdoc INoxCompute
    function validateInputProof(
        bytes32 handle,
        address owner,
        bytes calldata proof,
        TEEType teeType
    ) external override {
        bytes4 chainIdInHandle = bytes4(handle << (1 * 8));
        require(
            chainIdInHandle == bytes4(uint32(block.chainid)),
            InvalidProof(proof, "Handle chain id mismatch")
        );
        require(TypeUtils.typeOf(handle) == teeType, InvalidProof(proof, "Handle type mismatch"));
        require(proof.length == 137, InvalidProof(proof, "Invalid proof length"));
        address ownerInProof;
        address appInProof;
        uint256 createdAt;
        assembly {
            ownerInProof := shr(96, calldataload(proof.offset))
            appInProof := shr(96, calldataload(add(proof.offset, 20)))
            createdAt := calldataload(add(proof.offset, 40))
        }
        bytes calldata signature = proof[72:137];
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        require(
            block.timestamp <= createdAt + $.proofExpirationDuration,
            InvalidProof(proof, "Proof expired")
        );
        require(appInProof == msg.sender, InvalidProof(proof, "App mismatch"));
        require(ownerInProof == owner, InvalidProof(proof, "Owner mismatch"));
        bytes32 eip712MessageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(HANDLE_PROOF_TYPEHASH, handle, ownerInProof, appInProof, createdAt)
            )
        );
        require(
            ECDSA.recover(eip712MessageHash, signature) == $.gateway,
            InvalidProof(proof, "Invalid signature")
        );
        // Give caller contract transient access to the handle.
        _allowTransient(handle, msg.sender);
    }

    /// @inheritdoc INoxCompute
    function validateDecryptionProof(
        bytes32 handle,
        bytes calldata decryptionProof
    ) external view override returns (bytes memory) {
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        require(decryptionProof.length >= 65, InvalidProof(decryptionProof, "Proof too short"));
        bytes calldata decryptedResult = decryptionProof[65:];
        bytes32 eip712MessageHash = _hashTypedDataV4(
            keccak256(abi.encode(DECRYPTION_PROOF_TYPEHASH, handle, keccak256(decryptedResult)))
        );
        require(
            ECDSA.recoverCalldata(eip712MessageHash, decryptionProof[:65]) == $.gateway,
            InvalidProof(decryptionProof, "Invalid signature")
        );
        return decryptedResult;
    }

    /// @inheritdoc INoxCompute
    function add(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Add,
            operands,
            operands[0].typeOf(), // Result type
            1,
            false
        );
        result = results[0];
        emit Add(msg.sender, leftHandOperand, rightHandOperand, result);
    }

    /// @inheritdoc INoxCompute
    function sub(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Sub,
            operands,
            operands[0].typeOf(), // Result type
            1,
            false
        );
        result = results[0];
        emit Sub(msg.sender, leftHandOperand, rightHandOperand, result);
    }

    /// @inheritdoc INoxCompute
    function div(
        bytes32 numerator,
        bytes32 denominator
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(numerator, denominator);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = numerator;
        operands[1] = denominator;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Div,
            operands,
            operands[0].typeOf(), // Result type
            1,
            false
        );
        result = results[0];
        emit Div(msg.sender, numerator, denominator, result);
    }

    /// @inheritdoc INoxCompute
    function mul(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Mul,
            operands,
            operands[0].typeOf(), // Result type
            1,
            false
        );
        result = results[0];
        emit Mul(msg.sender, leftHandOperand, rightHandOperand, result);
    }

    /// @inheritdoc INoxCompute
    function safeAdd(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 success, bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        bytes32[] memory results;
        (success, results) = _executeOperation(
            Operator.SafeAdd,
            operands,
            operands[0].typeOf(), // Result type
            1,
            true
        );
        result = results[0];
        emit SafeAdd(msg.sender, leftHandOperand, rightHandOperand, success, result);
    }

    /// @inheritdoc INoxCompute
    function safeSub(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 success, bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        bytes32[] memory results;
        (success, results) = _executeOperation(
            Operator.SafeSub,
            operands,
            operands[0].typeOf(), // Result type
            1,
            true
        );
        result = results[0];
        emit SafeSub(msg.sender, leftHandOperand, rightHandOperand, success, result);
    }

    /// @inheritdoc INoxCompute
    function safeMul(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 success, bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        bytes32[] memory results;
        (success, results) = _executeOperation(
            Operator.SafeMul,
            operands,
            operands[0].typeOf(), // Result type
            1,
            true
        );
        result = results[0];
        emit SafeMul(msg.sender, leftHandOperand, rightHandOperand, success, result);
    }

    /// @inheritdoc INoxCompute
    function safeDiv(
        bytes32 numerator,
        bytes32 denominator
    ) external override returns (bytes32 success, bytes32 result) {
        TypeUtils.validateOperationTypes(numerator, denominator);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = numerator;
        operands[1] = denominator;
        bytes32[] memory results;
        (success, results) = _executeOperation(
            Operator.SafeDiv,
            operands,
            operands[0].typeOf(), // Result type
            1,
            true
        );
        result = results[0];
        emit SafeDiv(msg.sender, numerator, denominator, success, result);
    }

    /// @inheritdoc INoxCompute
    function eq(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Eq,
            operands,
            TEEType.Bool, // Result type
            1,
            false
        );
        result = results[0];
        emit Eq(msg.sender, leftHandOperand, rightHandOperand, result);
    }

    /// @inheritdoc INoxCompute
    function ne(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Ne,
            operands,
            TEEType.Bool, // Result type
            1,
            false
        );
        result = results[0];
        emit Ne(msg.sender, leftHandOperand, rightHandOperand, result);
    }

    /// @inheritdoc INoxCompute
    function lt(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Lt,
            operands,
            TEEType.Bool, // Result type
            1,
            false
        );
        result = results[0];
        emit Lt(msg.sender, leftHandOperand, rightHandOperand, result);
    }

    /// @inheritdoc INoxCompute
    function le(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Le,
            operands,
            TEEType.Bool, // Result type
            1,
            false
        );
        result = results[0];
        emit Le(msg.sender, leftHandOperand, rightHandOperand, result);
    }

    /// @inheritdoc INoxCompute
    function gt(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Gt,
            operands,
            TEEType.Bool, // Result type
            1,
            false
        );
        result = results[0];
        emit Gt(msg.sender, leftHandOperand, rightHandOperand, result);
    }

    /// @inheritdoc INoxCompute
    function ge(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external override returns (bytes32 result) {
        TypeUtils.validateOperationTypes(leftHandOperand, rightHandOperand);
        bytes32[] memory operands = new bytes32[](2);
        operands[0] = leftHandOperand;
        operands[1] = rightHandOperand;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Ge,
            operands,
            TEEType.Bool, // Result type
            1,
            false
        );
        result = results[0];
        emit Ge(msg.sender, leftHandOperand, rightHandOperand, result);
    }

    /// @inheritdoc INoxCompute
    function select(
        bytes32 condition,
        bytes32 ifTrue,
        bytes32 ifFalse
    ) external override returns (bytes32 result) {
        TypeUtils.requireType(condition, TEEType.Bool);
        TypeUtils.validateOperationTypes(ifTrue, ifFalse);
        bytes32[] memory operands = new bytes32[](3);
        operands[0] = condition;
        operands[1] = ifTrue;
        operands[2] = ifFalse;
        (, bytes32[] memory results) = _executeOperation(
            Operator.Select,
            operands,
            operands[1].typeOf(), // Result type
            1,
            false
        );
        result = results[0];
        emit Select(msg.sender, condition, ifTrue, ifFalse, result);
    }

    /// @inheritdoc INoxCompute
    function transfer(
        bytes32 balanceFrom,
        bytes32 balanceTo,
        bytes32 amount
    ) external override returns (bytes32 success, bytes32 newBalanceFrom, bytes32 newBalanceTo) {
        TypeUtils.validateOperationTypes(balanceFrom, balanceTo, amount);
        bytes32[] memory operands = new bytes32[](3);
        operands[0] = balanceFrom;
        operands[1] = balanceTo;
        operands[2] = amount;
        bytes32[] memory results;
        (success, results) = _executeOperation(
            Operator.Transfer,
            operands,
            operands[0].typeOf(), // Result type
            2,
            true
        );
        newBalanceFrom = results[0];
        newBalanceTo = results[1];
        emit Transfer(
            msg.sender,
            balanceFrom,
            balanceTo,
            amount,
            success,
            newBalanceFrom,
            newBalanceTo
        );
    }

    /// @inheritdoc INoxCompute
    function mint(
        bytes32 balanceTo,
        bytes32 amount,
        bytes32 totalSupply
    ) external override returns (bytes32 success, bytes32 newBalanceTo, bytes32 newTotalSupply) {
        TypeUtils.validateOperationTypes(balanceTo, amount, totalSupply);
        bytes32[] memory operands = new bytes32[](3);
        operands[0] = balanceTo;
        operands[1] = amount;
        operands[2] = totalSupply;
        bytes32[] memory results;
        (success, results) = _executeOperation(
            Operator.Mint,
            operands,
            operands[0].typeOf(), // Result type
            2,
            true
        );
        newBalanceTo = results[0];
        newTotalSupply = results[1];
        emit Mint(
            msg.sender,
            balanceTo,
            amount,
            totalSupply,
            success,
            newBalanceTo,
            newTotalSupply
        );
    }

    /// @inheritdoc INoxCompute
    function burn(
        bytes32 balanceFrom,
        bytes32 amount,
        bytes32 totalSupply
    ) external override returns (bytes32 success, bytes32 newBalanceFrom, bytes32 newTotalSupply) {
        TypeUtils.validateOperationTypes(balanceFrom, amount, totalSupply);
        bytes32[] memory operands = new bytes32[](3);
        operands[0] = balanceFrom;
        operands[1] = amount;
        operands[2] = totalSupply;
        bytes32[] memory results;
        (success, results) = _executeOperation(
            Operator.Burn,
            operands,
            operands[0].typeOf(), // Result type
            2,
            true
        );
        newBalanceFrom = results[0];
        newTotalSupply = results[1];
        emit Burn(
            msg.sender,
            balanceFrom,
            amount,
            totalSupply,
            success,
            newBalanceFrom,
            newTotalSupply
        );
    }

    /**
     * Processes a compute operation on encrypted handles with arithmetic types.
     * - Validates ACL for all input handles
     * - Generates result handles
     * - Grants transient access to msg.sender
     * Note: Caller functions are responsible for type validation.
     * @param operator The operator to apply
     * @param operands Array of operand handles
     * @param resultType TEE type for result handles
     * @param resultCount Number of result handles to generate
     * @param withSuccess Whether to generate a Bool success handle
     * @return success The Bool success handle (bytes32(0) if withSuccess is false)
     * @return results Array of result handles
     */
    // TODO rename to _processOperation.
    function _executeOperation(
        Operator operator,
        bytes32[] memory operands,
        TEEType resultType,
        uint8 resultCount,
        bool withSuccess
    ) private returns (bytes32 success, bytes32[] memory results) {
        _requireDefinedHandles(operands);
        _validateAllowedForAll(msg.sender, operands);
        // The same seed can be used for all result handles because
        // they differ by outputIndex.
        uint256 uniqueSeed = _generateHandleUniqueSeed(operands);
        results = new bytes32[](resultCount);
        for (uint8 i = 0; i < resultCount; i++) {
            results[i] = _generateHandle(
                operator,
                operands,
                resultType,
                i,
                uniqueSeed,
                HandleUtils.ATTR_IS_UNIQUE_HANDLE
            );
            _allowTransient(results[i], msg.sender);
        }
        if (withSuccess) {
            success = _generateHandle(
                operator,
                operands,
                TEEType.Bool,
                resultCount,
                uniqueSeed,
                HandleUtils.ATTR_IS_UNIQUE_HANDLE
            );
            _allowTransient(success, msg.sender);
        }
    }

    /**
     * Reverts if any operand is bytes32(0) (undefined handle).
     */
    function _requireDefinedHandles(bytes32[] memory operands) private pure {
        for (uint256 i = 0; i < operands.length; i++) {
            require(operands[i] != bytes32(0), UndefinedHandle());
        }
    }

    /**
     * Generates a complete handle from an operator and its operands.
     *
     * Pre-handle format:
     *   keccak256(abi.encode(
     *       operator,        // Operator identifier (e.g., Add, Sub, WrapAsPublicHandle)
     *       operands,        // Array of operand handles (or plaintext value)
     *       address(this),   // NoxCompute contract address
     *       uniqueSeed,        // Uniqueness seed (0 or counter value)
     *       outputIndex      // For operations that return multiple outputs
     *   ))
     *
     * Handle format (32 bytes):
     *   [0]    : Handle version
     *   [1-4]  : Chain ID (4 bytes, uint32)
     *   [5]    : TEE type
     *   [6]    : Attributes (bit 0 = isUniqueHandle)
     *   [7-31] : Truncated pre-handle hash (25 bytes)
     *
     * @param operator The operator to apply
     * @param operands Array of operand handles
     * @param handleType The TEE type to encode in the handle
     * @param outputIndex Index for operations returning multiple outputs
     * @param uniqueSeed Uniqueness seed (0 for wrapAsPublicHandle and unique operands)
     * @param attrs Attributes byte (0x00 for public handle, 0x01 for confidential)
     * @return result The complete handle with metadata appended
     */
    function _generateHandle(
        Operator operator,
        bytes32[] memory operands,
        TEEType handleType,
        uint8 outputIndex,
        uint256 uniqueSeed,
        bytes1 attrs
    ) private view returns (bytes32 result) {
        result = keccak256(abi.encode(operator, operands, address(this), uniqueSeed, outputIndex));
        // Shift hash to bytes 7-31 (truncate to 25 bytes), leaving bytes 0-6 free for metadata.
        result = result >> (7 * 8);
        result = result | bytes32(bytes1(uint8(HANDLE_VERSION)));
        result = result | (bytes32(bytes4(uint32(block.chainid))) >> (1 * 8));
        result = result | (bytes32(bytes1(uint8(handleType))) >> (5 * 8));
        result = result | (bytes32(attrs) >> (6 * 8));
    }

    /**
     * Determines the uniqueness seed for a confidential operation.
     * If at least one operand has isUniqueHandle=1, returns 0 (no storage access needed).
     * If all operands are public handles, increments a storage counter to guarantee uniqueness.
     * @param operands Array of operand handles
     * @return The uniqueness seed
     */
    function _generateHandleUniqueSeed(bytes32[] memory operands) private returns (uint256) {
        for (uint256 i = 0; i < operands.length; i++) {
            if (!HandleUtils.isPublicHandle(operands[i])) {
                return 0;
            }
        }
        // All operands are public handles: need storage counter for uniqueness
        NoxComputeStorage storage $ = _getNoxComputeStorage();
        return ++$.uniqueSeedCounter;
    }

    /**
     * Emits events to seed the zero handles for all supported types. This allows off-chain
     * services to recognize the zero handle for each type without needing to hardcode them.
     */
    function _emitZeroHandleSeeds() internal {
        TEEType[] memory types = TypeUtils.allCurrentlySupportedTypes();
        for (uint i = 0; i < types.length; i++) {
            emit WrapAsPublicHandle(
                address(this),
                bytes32(0),
                types[i],
                HandleUtils.zeroHandle(types[i])
            );
        }
    }
}
