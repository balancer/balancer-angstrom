// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IAuthentication } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IAuthentication.sol";

import { ArrayHelpers } from "@balancer-labs/v3-solidity-utils/contracts/test/ArrayHelpers.sol";
import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";

import { AngstromRouterAndHookMock } from "../../contracts/test/AngstromRouterAndHookMock.sol";
import { AngstromRouterAndHook } from "../../contracts/AngstromRouterAndHook.sol";

contract AngstromRouterAndHookUnitTest is BaseVaultTest {
    using ArrayHelpers for *;

    AngstromRouterAndHookMock private _angstromRouterAndHook;

    function setUp() public virtual override {
        super.setUp();

        _angstromRouterAndHook = new AngstromRouterAndHookMock(vault, weth, permit2, "AngstromRouterAndHook Mock v1");

        authorizer.grantRole(_angstromRouterAndHook.getActionId(AngstromRouterAndHook.toggleNodes.selector), admin);
    }

    function testToggleNodesIsAuthenticated() public {
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());
    }

    function testToggleNodes() public {
        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());
        assertTrue(_angstromRouterAndHook.isNode(bob), "Bob is not a node");
    }

    function testAddAndRemoveNodes() public {
        vm.startPrank(admin);
        _angstromRouterAndHook.toggleNodes([bob, alice].toMemoryArray());
        assertTrue(_angstromRouterAndHook.isNode(bob), "Bob is not a node");
        assertTrue(_angstromRouterAndHook.isNode(alice), "Alice is not a node");
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());
        vm.stopPrank();
        assertFalse(_angstromRouterAndHook.isNode(bob), "Bob is still a node");
        assertTrue(_angstromRouterAndHook.isNode(alice), "Alice is not a node after bob was removed");
    }

    function testUnlockAngstromNotNode() public {
        vm.expectRevert(AngstromRouterAndHook.NotNode.selector);
        _angstromRouterAndHook.manualUnlockAngstrom();
    }

    function testUnlockAngstromTwice() public {
        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());

        vm.startPrank(bob);
        _angstromRouterAndHook.manualUnlockAngstrom();
        vm.expectRevert(AngstromRouterAndHook.OnlyOncePerBlock.selector);
        _angstromRouterAndHook.manualUnlockAngstrom();
        vm.stopPrank();
    }

    function testUnlockAngstromSetsLastUnlockBlockNumber() public {
        vm.prank(admin);
        _angstromRouterAndHook.toggleNodes([bob].toMemoryArray());

        assertEq(_angstromRouterAndHook.getLastUnlockBlockNumber(), 0, "Last unlock block number is not 0");

        vm.prank(bob);
        _angstromRouterAndHook.manualUnlockAngstrom();
        assertEq(
            _angstromRouterAndHook.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }

    function testGetVault() public {
        assertEq(address(_angstromRouterAndHook.getVault()), address(vault), "Wrong vault address");
    }
}
