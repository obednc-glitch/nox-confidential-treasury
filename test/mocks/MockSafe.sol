// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISafe} from "../../src/ISafe.sol";

/// @notice Minimal Safe stand-in — just enough to prove the module's
/// execTransactionFromModule call reaches the Safe with the right args.
/// Swap for the real safe-contracts Safe.sol in integration testing.
contract MockSafe is ISafe {
    address public lastTo;
    uint256 public lastValue;
    bytes public lastData;
    bool public executed;

    mapping(address => bool) public modules;

    function enableModule(address module) external {
        modules[module] = true;
    }

    function isModuleEnabled(address module) external view override returns (bool) {
        return modules[module];
    }

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Operation /* operation */
    ) external override returns (bool success) {
        require(modules[msg.sender], "module not enabled");
        lastTo = to;
        lastValue = value;
        lastData = data;
        executed = true;
        return true;
    }

    // Lets the test simulate the Safe itself calling requestConfidentialPayout,
    // matching how a real Safe owner tx would route through the Safe.
    function callAsModule(address target, bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok, "call failed");
    }
}
