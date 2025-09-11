// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IAuthentication } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IAuthentication.sol";

import { ArrayHelpers } from "@balancer-labs/v3-solidity-utils/contracts/test/ArrayHelpers.sol";
import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";

import { AngstromBalancerMock } from "../../contracts/test/AngstromBalancerMock.sol";
import { AngstromBalancer } from "../../contracts/AngstromBalancer.sol";

contract AngstromBalancerUnitTest is BaseVaultTest {
    using ArrayHelpers for *;

    AngstromBalancerMock private angstromBalancer;

    function setUp() public virtual override {
        super.setUp();

        angstromBalancer = new AngstromBalancerMock(vault, weth, permit2, "AngstromBalancer Mock v1");

        authorizer.grantRole(angstromBalancer.getActionId(AngstromBalancer.toggleNodes.selector), admin);
    }

    function testToggleNodesIsAuthenticated() public {
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        angstromBalancer.toggleNodes([bob].toMemoryArray());
    }

    function testToggleNodes() public {
        vm.prank(admin);
        angstromBalancer.toggleNodes([bob].toMemoryArray());
        assertTrue(angstromBalancer.isRegisteredNode(bob), "Bob is not a node");
    }

    function testAddAndRemoveNodes() public {
        vm.startPrank(admin);
        angstromBalancer.toggleNodes([bob, alice].toMemoryArray());
        assertTrue(angstromBalancer.isRegisteredNode(bob), "Bob is not a node");
        assertTrue(angstromBalancer.isRegisteredNode(alice), "Alice is not a node");
        angstromBalancer.toggleNodes([bob].toMemoryArray());
        vm.stopPrank();
        assertFalse(angstromBalancer.isRegisteredNode(bob), "Bob is still a node");
        assertTrue(angstromBalancer.isRegisteredNode(alice), "Alice is not a node after bob was removed");
    }

    function testUnlockAngstromSetsLastUnlockBlockNumber() public {
        vm.prank(admin);
        angstromBalancer.toggleNodes([bob].toMemoryArray());

        assertEq(angstromBalancer.getLastUnlockBlockNumber(), 0, "Last unlock block number is not 0");

        vm.prank(bob);
        angstromBalancer.manualUnlockAngstrom();
        assertEq(
            angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }

    function testGetVault() public view {
        assertEq(address(angstromBalancer.getVault()), address(vault), "Wrong vault address");
    }
}
