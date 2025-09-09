// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IAuthentication } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IAuthentication.sol";
import {
    SwapPathExactAmountIn,
    SwapPathExactAmountOut
} from "@balancer-labs/v3-interfaces/contracts/vault/BatchRouterTypes.sol";

import { ArrayHelpers } from "@balancer-labs/v3-solidity-utils/contracts/test/ArrayHelpers.sol";
import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";

import { AngstromRouterAndHookMock } from "../../contracts/test/AngstromRouterAndHookMock.sol";
import { AngstromRouterAndHook } from "../../contracts/AngstromRouterAndHook.sol";

contract AngstromHookTest is BaseVaultTest {
    using ArrayHelpers for *;

    AngstromRouterAndHookMock private _angstromRouterAndHook;

    function setUp() public virtual override {
        super.setUp();
        authorizer.grantRole(_angstromRouterAndHook.getActionId(AngstromRouterAndHook.toggleNodes.selector), admin);
    }

    function createHook() internal override returns (address) {
        // Creating the router and hook in this function ensures that "pool" has the hook set correctly.
        _angstromRouterAndHook = new AngstromRouterAndHookMock(vault, weth, permit2, "AngstromRouterAndHook Mock v1");
        return address(_angstromRouterAndHook);
    }

    function testOnBeforeSwapNotNode() public {
        (, bytes memory userData) = _generateSignatureAndUserData(bob, bobKey);

        vm.expectRevert(AngstromRouterAndHook.NotNode.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, userData);
    }

    function testOnBeforeSwapCannotSwapWhileLocked() public {
        // If no userData was provided (therefore, no signature), the hook treats as if the user expected the pools to
        // be unlocked.
        vm.expectRevert(AngstromRouterAndHook.CannotSwapWhileLocked.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, bytes(""));
    }

    function testOnBeforeSwapUnlockDataTooShort() public {
        // If the userData is too short, there's not enough data to represent the ECDSA signature.
        vm.expectRevert(AngstromRouterAndHook.UnlockDataTooShort.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, bytes("1"));
    }

    function testOnBeforeSwapInvalidSignature() public {
        // If the signature is invalid, the hook reverts (in this case, signer and key do not match).
        (, bytes memory userData) = _generateSignatureAndUserData(bob, aliceKey);

        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());

        vm.expectRevert(AngstromRouterAndHook.InvalidSignature.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, userData);
    }

    function testOnBeforeSwapOnlyOncePerBlock() public {
        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());

        (bytes memory signature, bytes memory userData) = _generateSignatureAndUserData(bob, bobKey);
        vm.prank(bob);
        _angstromRouterAndHook.unlockWithEmptyAttestation(bob, signature);

        vm.expectRevert(AngstromRouterAndHook.OnlyOncePerBlock.selector);
        vm.prank(bob);
        _angstromRouterAndHook.unlockWithEmptyAttestation(bob, signature);
    }

    function testOnBeforeSwapSucceedsAndSetBlockNumber() public {
        (, bytes memory userData) = _generateSignatureAndUserData(bob, bobKey);

        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());

        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, userData);
        assertEq(
            _angstromRouterAndHook.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }

    function _generateSignatureAndUserData(
        address signer,
        uint256 privateKey
    ) private returns (bytes memory signature, bytes memory userData) {
        bytes32 hash = _angstromRouterAndHook.getDigest();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        signature = abi.encodePacked(r, s, v);
        userData = abi.encodePacked(signer, signature);
    }
}
