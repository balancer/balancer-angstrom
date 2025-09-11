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

    function testToggleNodesIsAuthenticated() public {
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        angstromBalancer.toggleNodes([bob].toMemoryArray());
    }

    function testToggleNodes() public {
        makeAngstromNode(bob);
        assertTrue(angstromBalancer.isRegisteredNode(bob), "Bob is not a node");
    }

    function testAddAndRemoveNodes() public {
        makeAngstromNodes([bob, alice].toMemoryArray());
        assertTrue(angstromBalancer.isRegisteredNode(bob), "Bob is not a node");
        assertTrue(angstromBalancer.isRegisteredNode(alice), "Alice is not a node");

        vm.prank(admin);
        angstromBalancer.toggleNodes([bob].toMemoryArray());

        assertFalse(angstromBalancer.isRegisteredNode(bob), "Bob is still a node");
        assertTrue(angstromBalancer.isRegisteredNode(alice), "Alice is not a node after bob was removed");
    }

    function testUnlockAngstromSetsLastUnlockBlockNumber() public {
        makeAngstromNode(bob);

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
