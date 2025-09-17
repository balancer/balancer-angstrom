// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IAuthentication } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IAuthentication.sol";

import { ArrayHelpers } from "@balancer-labs/v3-solidity-utils/contracts/test/ArrayHelpers.sol";

import { AngstromBalancerMock } from "../../contracts/test/AngstromBalancerMock.sol";
import { AngstromBalancer } from "../../contracts/AngstromBalancer.sol";
import { BaseAngstromTest } from "./utils/BaseAngstromTest.sol";

contract AngstromBalancerUnitTest is BaseAngstromTest {
    using ArrayHelpers for *;

    function testAddNodeIsAuthenticated() public {
        vm.prank(alice);
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        angstromBalancer.addNode(bob);
    }

    function testRemoveNodeIsAuthenticated() public {
        vm.prank(alice);
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        angstromBalancer.removeNode(bob);
    }

    function testAddAndRemoveNodes() public {
        addAngstromNode(bob);
        addAngstromNode(alice);
        removeAngstromNode(bob);

        assertFalse(angstromBalancer.isRegisteredNode(bob), "Bob is still a node");
        assertTrue(angstromBalancer.isRegisteredNode(alice), "Alice is not a node after bob was removed");
    }

    function testUnlockAngstromSetsLastUnlockBlockNumber() public {
        addAngstromNode(bob);

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
