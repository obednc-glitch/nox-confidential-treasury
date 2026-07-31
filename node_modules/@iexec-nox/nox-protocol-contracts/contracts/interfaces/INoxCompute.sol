// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

import {TEEType} from "../utils/TypeUtils.sol";

/**
 * @title INoxCompute
 * @notice Interface for the Nox compute contract powered by TEE.
 */
interface INoxCompute {
    // ------------- General errors -------------
    /// Error thrown when account address is zero
    error InvalidZeroAddress();
    /// Error thrown when bytes parameter is empty
    error InvalidEmptyBytes();

    // ------------- ACL errors -------------
    /// Error thrown when sender doesn't have access to the handle
    error UnauthorizedSender(address sender);
    /// Error thrown when an account is not allowed to use a handle
    error NotAllowed(bytes32 handle, address account);
    /// Error thrown when a handle is not publicly decryptable
    error NotPubliclyDecryptable(bytes32 handle);
    /// Error thrown when attempting an ACL mutation on a public handle
    error PublicHandleACLForbidden();

    // ------------- Compute errors -------------
    /// Error thrown when the input proof is invalid
    error InvalidProof(bytes proof, string reason);
    /// Error thrown when an operand is bytes32(0), indicating an undefined handle
    error UndefinedHandle();

    // ------------- ACL events -------------
    /// Emitted when admin role is granted
    event Allowed(address indexed sender, address indexed account, bytes32 indexed handle);
    /// Emitted when viewer role is granted
    event ViewerAdded(address indexed sender, address indexed viewer, bytes32 indexed handle);
    /// Emitted when a handle is marked as publicly decryptable
    event MarkedAsPubliclyDecryptable(address indexed sender, bytes32 indexed handle);

    // ------------- Protocol config events -------------
    event KmsPublicKeyUpdated(bytes newKmsPublicKey);
    event GatewayUpdated(address indexed newGateway);
    event ProofExpirationDurationUpdated(uint256 newDuration);

    // ------------- Compute events -------------
    event WrapAsPublicHandle(
        address indexed caller,
        bytes32 plaintext,
        TEEType toType,
        bytes32 result
    );
    event Add(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event Sub(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event Div(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event Mul(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event Eq(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event Ne(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event Lt(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event Le(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event Gt(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event Ge(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 result
    );
    event SafeAdd(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 success,
        bytes32 result
    );
    event SafeSub(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 success,
        bytes32 result
    );
    event SafeMul(
        address indexed caller,
        bytes32 leftHandOperand,
        bytes32 rightHandOperand,
        bytes32 success,
        bytes32 result
    );
    event SafeDiv(
        address indexed caller,
        bytes32 numerator,
        bytes32 denominator,
        bytes32 success,
        bytes32 result
    );
    event Select(
        address indexed caller,
        bytes32 condition,
        bytes32 ifTrue,
        bytes32 ifFalse,
        bytes32 result
    );
    event Transfer(
        address indexed caller,
        bytes32 balanceFrom,
        bytes32 balanceTo,
        bytes32 amount,
        bytes32 success,
        bytes32 newBalanceFrom,
        bytes32 newBalanceTo
    );
    event Mint(
        address indexed caller,
        bytes32 balanceTo,
        bytes32 amount,
        bytes32 totalSupply,
        bytes32 success,
        bytes32 newBalanceTo,
        bytes32 newTotalSupply
    );
    event Burn(
        address indexed caller,
        bytes32 balanceFrom,
        bytes32 amount,
        bytes32 totalSupply,
        bytes32 success,
        bytes32 newBalanceFrom,
        bytes32 newTotalSupply
    );

    enum Operator {
        WrapAsPublicHandle,
        Add,
        Sub,
        Mul,
        Div,
        SafeAdd,
        SafeSub,
        SafeMul,
        SafeDiv,
        Select,
        Eq,
        Ne,
        Lt,
        Le,
        Gt,
        Ge,
        Transfer,
        Mint,
        Burn
    }

    // ------------- ACL functions -------------

    /**
     * Grant admin role to another address for a specific handle
     * @dev Caller must have access (transient OR persistent) to the handle
     * @param handle The handle identifier
     * @param account The address to grant admin role
     */
    function allow(bytes32 handle, address account) external;

    /**
     * Allows the use of `handle` by address `account` for this transaction.
     * @param handle Handle.
     * @param account Address of the account.
     */
    function allowTransient(bytes32 handle, address account) external;

    /**
     * Revokes transient access to `handle` for address `account` within the current transaction.
     * @param handle Handle.
     * @param account Address of the account.
     */
    function disallowTransient(bytes32 handle, address account) external;

    /**
     * Returns whether the account is allowed to use the `handle`, either due to
     * allowTransient() or allow().
     * @param handle Handle.
     * @param account Address of the account.
     * @return Whether the account can access the handle (persistent or transient).
     */
    function isAllowed(bytes32 handle, address account) external view returns (bool);

    /**
     * Checks whether the account is allowed to use all provided handles.
     * Reverts with NotAllowed if any handle is not allowed.
     * @param account Address of the account.
     * @param handles Array of handles to check.
     */
    function validateAllowedForAll(address account, bytes32[] calldata handles) external view;

    /**
     * Adds a viewer for a specific handle
     * @dev Only an admin can add a viewer. The viewer address cannot be address(0).
     * @param handle The handle identifier
     * @param viewer The address to grant viewer role
     */
    function addViewer(bytes32 handle, address viewer) external;

    /**
     * Returns whether the account can view the handle.
     * @dev Returns true if any of the following conditions are met:
     *      - The handle is publicly decryptable
     *      - The account was added as a viewer via `addViewer`
     *      - The account has persistent access (is allowed) on the handle
     * @param handle Handle.
     * @param viewer Address of the viewer.
     * @return Whether the account can view the handle.
     */
    function isViewer(bytes32 handle, address viewer) external view returns (bool);

    /**
     * Mark a handle as publicly decryptable.
     * @dev The caller must be allowed to use the handle.
     *      If not, the function reverts.
     * @param handle Handle to mark as publicly decryptable.
     */
    function allowPublicDecryption(bytes32 handle) external;

    /**
     * Checks whether a handle is publicly decryptable.
     * @param handle Handle.
     * @return Whether the handle is publicly decryptable.
     */
    function isPubliclyDecryptable(bytes32 handle) external view returns (bool);

    // ------------- Compute functions -------------

    /**
     * @notice Wraps a plaintext value into a deterministic public handle.
     * The resulting handle has bit 0 of the attributes byte (byte 30) unset,
     * meaning it can be non unique, it carries no ACL and is accessible by everyone.
     * The same value and type always produce the same handle.
     * @param value The plaintext value
     * @param teeType The type of the handle
     * @return The public handle
     */
    function wrapAsPublicHandle(bytes32 value, TEEType teeType) external returns (bytes32);

    /**
     * Validates that a handle provided by a user is:
     *   - of expected type
     *   - not expired
     *   - issued for the correct app (caller)
     *   - issued for the correct owner
     *   - issued by the configured gateway (signed by the gateway wallet)
     * or reverts otherwise.
     *
     * Handle format:
     *  1 byte    4 bytes      1 byte  1 byte      25 bytes
     *   [0]     [1------4]     [5]     [6]     [7-----------31]
     * Version    ChainId       Type    Attrs      Pre-handle
     *
     * Proof format:
     *  20 bytes       20 bytes        32 bytes            65 bytes
     * [0-----19]    [20-----39]    [40--------71]    [72------------136]
     *   Owner           App           CreatedAt       EIP-712 signature
     *
     * @param handle handle id
     * @param owner The address of the handle owner
     * @param proof Proof data
     */
    function validateInputProof(
        bytes32 handle,
        address owner,
        bytes calldata proof,
        TEEType teeType
    ) external;

    /**
     * Validates the decryption proof issued by the gateway for a given handle.
     * The proof must be signed by the configured gateway.
     *
     * The proof uses a compact serialization: `signature (65 bytes) || decryptedResult (N bytes)`.
     * The signature is placed first (fixed size) so that `decryptedResult` can be variable-length,
     * supporting all current and future types that may exceed 32 bytes (e.g. encrypted strings).
     *
     * @param handle Handle to decrypt
     * @param decryptionProof Compact proof: `signature (65 bytes) || decryptedResult (N bytes)`
     * @return decryptedResult The decrypted value extracted from the proof if the proof is valid,
     * or reverts otherwise
     */
    function validateDecryptionProof(
        bytes32 handle,
        bytes calldata decryptionProof
    ) external view returns (bytes memory);

    /**
     * @notice Performs an addition between two encrypted values without overflow check.
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return result Result handle
     */
    function add(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 result);

    /**
     * @notice Performs a subtraction between two encrypted values without underflow check.
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return result Result handle
     */
    function sub(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 result);

    /**
     * @notice Performs a multiplication between two encrypted values without overflow check.
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return result Result handle
     */
    function mul(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 result);

    /**
     * @notice Performs a division between two encrypted values without safety checks.
     * In the case of a division by zero, the result will be as follows:
     *  - For unsigned integers uintN: encrypted MAX_UintN (i.e., 2^N - 1)
     *  - For signed integers intN: encrypted MAX_IntN (i.e., 2^(N-1) - 1)
     * @param numerator Value to be divided
     * @param denominator Value to divide by
     * @return result Result handle
     */
    function div(bytes32 numerator, bytes32 denominator) external returns (bytes32 result);

    /**
     * @notice Performs an addition between two encrypted values with overflow check.
     * If the operation succeeds, the value of the success handle will be an encrypted
     * `true` and the result handle's value will be the encrypted sum.
     * If the operation fails (e.g., due to overflow), the success handle will contain
     * an encrypted `false` and the result handle will contain an encrypted `0`.
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return success Whether the operation was successful
     * @return result Result handle
     */
    function safeAdd(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 success, bytes32 result);

    /**
     * @notice Performs a subtraction between two encrypted values with underflow check.
     * If the operation succeeds, the value of the success handle will be an encrypted
     * `true` and the result handle's value will be the encrypted difference.
     * If the operation fails (e.g., due to underflow), the success handle will contain
     * an encrypted `false` and the result handle will contain an encrypted `0`.
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return success Whether the operation was successful
     * @return result Result handle
     */
    function safeSub(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 success, bytes32 result);

    /**
     * @notice Performs a multiplication between two encrypted values with overflow check.
     * If the operation succeeds, the value of the success handle will be an encrypted
     * `true` and the result handle's value will be the encrypted product.
     * If the operation fails (e.g., due to overflow), the success handle will contain
     * an encrypted `false` and the result handle will contain an encrypted `0`.
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return success Whether the operation was successful
     * @return result Result handle
     */
    function safeMul(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 success, bytes32 result);

    /**
     * @notice Performs a division between two encrypted values with division-by-zero check.
     * If the operation succeeds, the value of the success handle will be an encrypted
     * `true` and the result handle's value will be the encrypted quotient.
     * If the operation fails (e.g., due to division by zero), the success handle will contain
     * an encrypted `false` and the result handle will contain an encrypted `0`.
     * @param numerator Value to be divided
     * @param denominator Value to divide by
     * @return success Whether the operation was successful
     * @return result Result handle
     */
    function safeDiv(
        bytes32 numerator,
        bytes32 denominator
    ) external returns (bytes32 success, bytes32 result);

    /**
     * @notice Selects between two encrypted values based on a condition
     * @param condition Condition handle
     * @param ifTrue Value handle if condition is true
     * @param ifFalse Value handle if condition is false
     * @return result Selected value handle
     */
    function select(bytes32 condition, bytes32 ifTrue, bytes32 ifFalse) external returns (bytes32);

    /**
     * @notice Checks equality between two encrypted values
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return result Bool handle indicating equality
     */
    function eq(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 result);

    /**
     * @notice Checks inequality between two encrypted values
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return result Bool handle indicating inequality
     */
    function ne(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 result);

    /**
     * @notice Checks if left operand is less than right operand
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return result Bool handle indicating less than
     */
    function lt(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 result);

    /**
     * @notice Checks if left operand is less than or equal to right operand
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return result Bool handle indicating less than or equal
     */
    function le(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 result);

    /**
     * @notice Checks if left operand is greater than right operand
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return result Bool handle indicating greater than
     */
    function gt(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 result);

    /**
     * @notice Checks if left operand is greater than or equal to right operand
     * @param leftHandOperand Left-hand side operand handle
     * @param rightHandOperand Right-hand side operand handle
     * @return result Bool handle indicating greater than or equal
     */
    function ge(
        bytes32 leftHandOperand,
        bytes32 rightHandOperand
    ) external returns (bytes32 result);

    /**
     * @notice Computes a confidential transfer between two balances.
     * The transfer will succeed if the sender has sufficient balance and fail otherwise.
     * If the transfer fails, the success handle will contain an encrypted `false`, the
     * newBalanceFrom and newBalanceTo handles will contain the same values as the input
     * balanceFrom and balanceTo handles.
     * @param balanceFrom Sender's current balance handle
     * @param balanceTo Recipient's current balance handle
     * @param amount Amount handle to transfer
     * @return success Bool handle indicating if the transfer succeeded
     * @return newBalanceFrom Sender's new balance handle
     * @return newBalanceTo Recipient's new balance handle
     */
    function transfer(
        bytes32 balanceFrom,
        bytes32 balanceTo,
        bytes32 amount
    ) external returns (bytes32 success, bytes32 newBalanceFrom, bytes32 newBalanceTo);

    /**
     * @notice Computes a confidential mint operation.
     * If the minting operation fails (e.g., due to overflow), the success handle will
     * contain an encrypted `false` and the newBalanceTo and newTotalSupply handles will
     * contain the same values as the input balanceTo and totalSupply handles.
     * @param balanceTo Recipient's current balance handle
     * @param amount Amount handle to mint
     * @param totalSupply Current total supply handle
     * @return success Bool handle indicating if the mint succeeded
     * @return newBalanceTo Recipient's new balance handle
     * @return newTotalSupply New total supply handle
     */
    function mint(
        bytes32 balanceTo,
        bytes32 amount,
        bytes32 totalSupply
    ) external returns (bytes32 success, bytes32 newBalanceTo, bytes32 newTotalSupply);

    /**
     * @notice Computes a confidential burn operation.
     * If the burn operation fails (e.g., due to underflow), the success handle will
     * contain an encrypted `false` and the newBalanceFrom and newTotalSupply handles will
     * contain the same values as the input balanceFrom and totalSupply handles.
     * @param balanceFrom Sender's current balance handle
     * @param amount Amount handle to burn
     * @param totalSupply Current total supply handle
     * @return success Bool handle indicating if the burn succeeded
     * @return newBalanceFrom Sender's new balance handle
     * @return newTotalSupply New total supply handle
     */
    function burn(
        bytes32 balanceFrom,
        bytes32 amount,
        bytes32 totalSupply
    ) external returns (bytes32 success, bytes32 newBalanceFrom, bytes32 newTotalSupply);

    // ------------- Config getters -------------

    function kmsPublicKey() external view returns (bytes memory);
    function gateway() external view returns (address);
    function proofExpirationDuration() external view returns (uint256);

    // ------------- Admin functions -------------

    /**
     * @notice Sets the KMS public key used for ECIES encryption.
     * @param newKmsPublicKey The compressed SEC1 secp256k1 public key (33 bytes)
     */
    function setKmsPublicKey(bytes calldata newKmsPublicKey) external;

    /**
     * @notice Sets the gateway address in the contract's config.
     * @param gatewayAddress The address of the gateway
     */
    function setGateway(address gatewayAddress) external;

    /**
     * @notice Sets the proof expiration duration.
     * @param newDuration The new expiration duration in seconds
     */
    function setProofExpirationDuration(uint256 newDuration) external;
}
