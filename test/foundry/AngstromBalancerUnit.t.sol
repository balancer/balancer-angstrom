// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IAuthentication } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IAuthentication.sol";

import { AngstromBalancer } from "../../contracts/AngstromBalancer.sol";
import { BaseAngstromTest } from "./utils/BaseAngstromTest.sol";

contract AngstromBalancerUnitTest is BaseAngstromTest {
    function testAddNodeIsAuthenticated() public {
        vm.prank(alice);
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        angstromBalancer.registerNode(bob);
    }

    function testRemoveNodeIsAuthenticated() public {
        vm.prank(alice);
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        angstromBalancer.deregisterNode(bob);
    }

    function testAddNodeAlreadyRegistered() public {
        registerAngstromNode(bob);
        vm.prank(admin);
        vm.expectRevert(AngstromBalancer.NodeAlreadyRegistered.selector);
        angstromBalancer.registerNode(bob);
    }

    function testRemoveNodeNotRegistered() public {
        vm.prank(admin);
        vm.expectRevert(AngstromBalancer.NodeNotRegistered.selector);
        angstromBalancer.deregisterNode(bob);
    }

    function testAddAndRemoveNodes() public {
        registerAngstromNode(bob);
        registerAngstromNode(alice);
        // Makes sure, when deregistering a node, the other nodes are not affected.
        deregisterAngstromNode(bob);

        assertFalse(angstromBalancer.isRegisteredNode(bob), "Bob is still a node");
        assertTrue(angstromBalancer.isRegisteredNode(alice), "Alice is not a node after bob was removed");
    }

    function testUnlockAngstromSetsLastUnlockBlockNumber() public {
        registerAngstromNode(bob);

        assertEq(angstromBalancer.getLastUnlockBlockNumber(), 0, "Last unlock block number is not 0");

        vm.prank(bob);
        angstromBalancer.manualUnlockAngstrom();
        assertEq(
            angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }
}
