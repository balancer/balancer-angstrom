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

contract AngstromRouterTest is BaseVaultTest {
    using ArrayHelpers for *;

    AngstromRouterAndHookMock private _angstromRouterAndHook;

    function setUp() public virtual override {
        super.setUp();
        _angstromRouterAndHook = new AngstromRouterAndHookMock(vault, weth, permit2, "AngstromRouterAndHook Mock v1");
        authorizer.grantRole(_angstromRouterAndHook.getActionId(AngstromRouterAndHook.toggleNodes.selector), admin);
    }

    function testSwapExactInNotNode() public {
        SwapPathExactAmountIn[] memory paths;
        vm.expectRevert(AngstromRouterAndHook.NotNode.selector);
        _angstromRouterAndHook.swapExactIn(paths, MAX_UINT256, false, bytes(""));
    }

    function testSwapExactInAlreadyUnlocked() public {
        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());

        SwapPathExactAmountIn[] memory paths;

        vm.startPrank(bob);
        _angstromRouterAndHook.manualUnlockAngstrom();
        vm.expectRevert(AngstromRouterAndHook.OnlyOncePerBlock.selector);
        _angstromRouterAndHook.swapExactIn(paths, MAX_UINT256, false, bytes(""));
        vm.stopPrank();
    }

    function testSwapExactInUnlocksAngstrom() public {
        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());

        SwapPathExactAmountIn[] memory paths;
        vm.prank(bob);
        _angstromRouterAndHook.swapExactIn(paths, MAX_UINT256, false, bytes(""));
        assertEq(
            _angstromRouterAndHook.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }

    function testSwapExactOutNotNode() public {
        SwapPathExactAmountOut[] memory paths;
        vm.expectRevert(AngstromRouterAndHook.NotNode.selector);
        _angstromRouterAndHook.swapExactOut(paths, MAX_UINT256, false, bytes(""));
    }

    function testSwapExactOutAlreadyUnlocked() public {
        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());

        SwapPathExactAmountOut[] memory paths;
        vm.startPrank(bob);
        _angstromRouterAndHook.manualUnlockAngstrom();
        vm.expectRevert(AngstromRouterAndHook.OnlyOncePerBlock.selector);
        _angstromRouterAndHook.swapExactOut(paths, MAX_UINT256, false, bytes(""));
        vm.stopPrank();
    }

    function testSwapExactOutUnlocksRouter() public {
        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());

        SwapPathExactAmountOut[] memory paths;
        vm.prank(bob);
        _angstromRouterAndHook.swapExactOut(paths, MAX_UINT256, false, bytes(""));
        assertEq(
            _angstromRouterAndHook.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }
}
