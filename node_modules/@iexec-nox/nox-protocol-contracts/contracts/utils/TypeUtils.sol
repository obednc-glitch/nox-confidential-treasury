// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

/**
 * @notice Enum values MUST NOT be reordered or removed once deployed.
 * New types should only be appended at the end to maintain backward compatibility.
 */
enum TEEType {
    // ============ Special Types (0-3) ============
    Bool, // 0
    Address, // 1
    Bytes, // 2 (dynamic)
    String, // 3
    // ============ Unsigned Integer Types (4-35) ============
    Uint8, // 4
    Uint16, // 5
    Uint24, // 6
    Uint32, // 7
    Uint40, // 8
    Uint48, // 9
    Uint56, // 10
    Uint64, // 11
    Uint72, // 12
    Uint80, // 13
    Uint88, // 14
    Uint96, // 15
    Uint104, // 16
    Uint112, // 17
    Uint120, // 18
    Uint128, // 19
    Uint136, // 20
    Uint144, // 21
    Uint152, // 22
    Uint160, // 23
    Uint168, // 24
    Uint176, // 25
    Uint184, // 26
    Uint192, // 27
    Uint200, // 28
    Uint208, // 29
    Uint216, // 30
    Uint224, // 31
    Uint232, // 32
    Uint240, // 33
    Uint248, // 34
    Uint256, // 35
    // ============ Signed Integer Types (36-67) ============
    Int8, // 36
    Int16, // 37
    Int24, // 38
    Int32, // 39
    Int40, // 40
    Int48, // 41
    Int56, // 42
    Int64, // 43
    Int72, // 44
    Int80, // 45
    Int88, // 46
    Int96, // 47
    Int104, // 48
    Int112, // 49
    Int120, // 50
    Int128, // 51
    Int136, // 52
    Int144, // 53
    Int152, // 54
    Int160, // 55
    Int168, // 56
    Int176, // 57
    Int184, // 58
    Int192, // 59
    Int200, // 60
    Int208, // 61
    Int216, // 62
    Int224, // 63
    Int232, // 64
    Int240, // 65
    Int248, // 66
    Int256, // 67
    // ============ Fixed-size Bytes Types (68-99) ============
    Bytes1, // 68
    Bytes2, // 69
    Bytes3, // 70
    Bytes4, // 71
    Bytes5, // 72
    Bytes6, // 73
    Bytes7, // 74
    Bytes8, // 75
    Bytes9, // 76
    Bytes10, // 77
    Bytes11, // 78
    Bytes12, // 79
    Bytes13, // 80
    Bytes14, // 81
    Bytes15, // 82
    Bytes16, // 83
    Bytes17, // 84
    Bytes18, // 85
    Bytes19, // 86
    Bytes20, // 87
    Bytes21, // 88
    Bytes22, // 89
    Bytes23, // 90
    Bytes24, // 91
    Bytes25, // 92
    Bytes26, // 93
    Bytes27, // 94
    Bytes28, // 95
    Bytes29, // 96
    Bytes30, // 97
    Bytes31, // 98
    Bytes32 // 99
}

error NonArithmeticType();
error UnsupportedArithmeticType();
error IncompatibleTypes();

library TypeUtils {
    /**
     * Returns the list of all currently supported TEE types.
     * @dev Update this list when new types are supported.
     */
    function allCurrentlySupportedTypes() internal pure returns (TEEType[] memory types) {
        types = new TEEType[](5);
        types[0] = TEEType.Bool;
        types[1] = TEEType.Uint16;
        types[2] = TEEType.Uint256;
        types[3] = TEEType.Int16;
        types[4] = TEEType.Int256;
    }

    /**
     * @notice Extracts the TEE type from a handle.
     * The type is stored at byte position 5 in the handle.
     * @param handle The handle to extract the type from
     * @return The TEEType encoded in the handle
     */
    function typeOf(bytes32 handle) internal pure returns (TEEType) {
        return TEEType(uint8(handle[5]));
    }

    /**
     * @notice Validates that a TEE type is supported for arithmetic operations.
     * Only the following arithmetic types are supported:
     *  - uint16
     *  - uint256
     *  - int16
     *  - int256
     * @param teeType The TEE type to validate
     * @dev Reverts with NonArithmeticType when the type is not an arithmetic type.
     * @dev Reverts with UnsupportedArithmeticType when the type is not supported.
     */
    function validateArithmeticType(TEEType teeType) internal pure {
        uint8 t = uint8(teeType);
        require(t >= uint8(TEEType.Uint8) && t <= uint8(TEEType.Int256), NonArithmeticType());
        bool supportedType =
            teeType == TEEType.Uint16 ||
                teeType == TEEType.Uint256 ||
                teeType == TEEType.Int16 ||
                teeType == TEEType.Int256;
        require(supportedType, UnsupportedArithmeticType());
    }

    /**
     * Reverts if handle's TEEType doesn't match the expected type.
     */
    function requireType(bytes32 handle, TEEType expected) internal pure {
        require(typeOf(handle) == expected, IncompatibleTypes());
    }

    /**
     * Validates that first and second have the same supported arithmetic type.
     */
    function validateOperationTypes(bytes32 first, bytes32 second) internal pure {
        validateArithmeticType(typeOf(first));
        requireType(second, typeOf(first));
    }

    /**
     * Validates that first, second, and third have the same supported arithmetic type.
     */
    function validateOperationTypes(bytes32 first, bytes32 second, bytes32 third) internal pure {
        validateOperationTypes(first, second);
        requireType(third, typeOf(first));
    }
}
