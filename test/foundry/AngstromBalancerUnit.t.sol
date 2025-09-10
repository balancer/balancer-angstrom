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

    AngstromBalancerMock private _angstromBalancer;

    function setUp() public virtual override {
        super.setUp();

        _angstromBalancer = new AngstromBalancerMock(vault, weth, permit2, "AngstromBalancer Mock v1");

        authorizer.grantRole(_angstromBalancer.getActionId(AngstromBalancer.toggleNodes.selector), admin);
    }

    function testToggleNodesIsAuthenticated() public {
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        _angstromBalancer.toggleNodes([bob].toMemoryArray());
    }

    function testToggleNodes() public {
        vm.prank(admin);
        _angstromBalancer.toggleNodes([bob].toMemoryArray());
        assertTrue(_angstromBalancer.isNode(bob), "Bob is not a node");
    }

    function testAddAndRemoveNodes() public {
        vm.startPrank(admin);
        _angstromBalancer.toggleNodes([bob, alice].toMemoryArray());
        assertTrue(_angstromBalancer.isNode(bob), "Bob is not a node");
        assertTrue(_angstromBalancer.isNode(alice), "Alice is not a node");
        _angstromBalancer.toggleNodes([bob].toMemoryArray());
        vm.stopPrank();
        assertFalse(_angstromBalancer.isNode(bob), "Bob is still a node");
        assertTrue(_angstromBalancer.isNode(alice), "Alice is not a node after bob was removed");
    }

    function testUnlockAngstromNotNode() public {
        vm.expectRevert(AngstromBalancer.NotNode.selector);
        _angstromBalancer.manualUnlockAngstromWithRouter();
    }

    function testUnlockAngstromTwice() public {
        vm.prank(admin);
        _angstromBalancer.toggleNodes([bob].toMemoryArray());

        vm.startPrank(bob);
        _angstromBalancer.manualUnlockAngstromWithRouter();
        vm.expectRevert(AngstromBalancer.OnlyOncePerBlock.selector);
        _angstromBalancer.manualUnlockAngstromWithRouter();
        vm.stopPrank();
    }

    function testUnlockAngstromSetsLastUnlockBlockNumber() public {
        vm.prank(admin);
        _angstromBalancer.toggleNodes([bob].toMemoryArray());

        assertEq(_angstromBalancer.getLastUnlockBlockNumber(), 0, "Last unlock block number is not 0");

        vm.prank(bob);
        _angstromBalancer.manualUnlockAngstromWithRouter();
        assertEq(
            _angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }

    function testGetVault() public view {
        assertEq(address(_angstromBalancer.getVault()), address(vault), "Wrong vault address");
    }
}
