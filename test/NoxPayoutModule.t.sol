// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NoxPayoutModule} from "../src/NoxPayoutModule.sol";
import {MockSafe} from "./mocks/MockSafe.sol";
import {externalEuint256} from "@iexec-nox/nox-protocol-contracts/contracts/Nox.sol";

/// NOTE ON TEST COVERAGE: encrypted inputs (externalEuint256 + proof) are
/// normally produced client-side via the Nox JS SDK's `encryptInput`,
/// which signs an EIP-712 proof. That's not something we can fabricate
/// from plain Foundry/Solidity alone. This test file therefore covers
/// what's testable without the SDK — access control on `fund` and
/// `requestPayout` — and stubs the encrypted-value round trip with a
/// clearly marked TODO.
///
/// TODO(you): once you've got the JS SDK's encryptInput working (see
/// docs.noxprotocol.io -> JS SDK -> Methods -> encryptInput), either:
///   (a) write a Foundry FFI test that shells out to a small Node script
///       to generate a real encrypted input + proof, or
///   (b) check whether Nox ships its own Foundry test helpers/mocks for
///       local unit testing without a live TEE (worth checking the
///       "Hello World" and "Networks" docs pages for this).
contract NoxPayoutModuleTest is Test {
    MockSafe safe;
    NoxPayoutModule module;

    address recipient = address(0xBEEF);

    function setUp() public {
        safe = new MockSafe();
        module = new NoxPayoutModule(address(safe));
    }

    function test_fund_revertsIfNotCalledBySafe() public {
        externalEuint256 dummy; // zero-value placeholder; access check
                                 // reverts before this is ever read
        vm.expectRevert(NoxPayoutModule.NotSafeOwnerFlow.selector);
        module.fund(dummy, bytes(""));
    }

    function test_requestPayout_revertsIfNotCalledBySafe() public {
        externalEuint256 dummy;
        vm.expectRevert(NoxPayoutModule.NotSafeOwnerFlow.selector);
        module.requestPayout(recipient, dummy, bytes(""));
    }

    function test_moduleIsWiredToCorrectSafe() public view {
        assertEq(address(module.safe()), address(safe));
    }

    // TODO(you): add an encrypted-value round trip test once you have a
    // way to produce a real (externalEuint256, proof) pair — assert that
    // fund() followed by requestPayout() results in the recipient's
    // decrypted balance (via the JS SDK, off-chain) matching the amount
    // sent, and that a payout exceeding the treasury balance leaves both
    // balances unchanged per Nox's all-or-nothing semantics.
}
