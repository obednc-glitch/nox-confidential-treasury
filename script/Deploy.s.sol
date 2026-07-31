// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {NoxPayoutModule} from "../src/NoxPayoutModule.sol";

/// Usage:
///   forge script script/Deploy.s.sol \
///     --rpc-url testnet \
///     --private-key $DEPLOYER_KEY \
///     --broadcast
///
/// Requires SAFE_ADDRESS env var set before running. Nox is a linked
/// Solidity library (not a separately deployed contract you point at),
/// so there's no NOX_ADDRESS to configure here.
///
/// After deploy, enable the module on your Safe (via the Safe UI or a
/// direct enableModule tx) — deployment alone does not attach it.
contract Deploy is Script {
    function run() external returns (NoxPayoutModule module) {
        address safeAddress = vm.envAddress("SAFE_ADDRESS");

        vm.startBroadcast();
        module = new NoxPayoutModule(safeAddress);
        vm.stopBroadcast();
    }
}
