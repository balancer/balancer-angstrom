// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IAuthentication } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IAuthentication.sol";

import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";

import { AngstromRouterMock } from "../../contracts/test/AngstromRouterMock.sol";
import { AngstromRouter } from "../../contracts/AngstromRouter.sol";

contract AngstromRouterUnitTest is BaseVaultTest {
    AngstromRouterMock private _angstromRouter;

    function setUp() public virtual override {
        super.setUp();

        _angstromRouter = new AngstromRouterMock(vault, weth, permit2, "AngstromRouter Mock v1");

        authorizer.grantRole(_angstromRouter.getActionId(AngstromRouter.addNode.selector), admin);
        authorizer.grantRole(_angstromRouter.getActionId(AngstromRouter.removeNode.selector), admin);
    }

    // addNode should only be callable by admin
    function testAddNodeIsAuthenticated() public {
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        _angstromRouter.addNode(bob);
    }

    // addNode should add the address to the nodes mapping
    function testAddNode() public {
        vm.prank(admin);
        _angstromRouter.addNode(bob);
        assertTrue(_angstromRouter.isNode(bob), "Bob is not a node");
    }

    // removeNode should only be callable by admin
    function testRemoveNodeIsAuthenticated() public {
        vm.expectRevert(IAuthentication.SenderNotAllowed.selector);
        _angstromRouter.removeNode(bob);
    }

    // removeNode should remove the address from the nodes mapping
    function testRemoveNode() public {
        vm.startPrank(admin);
        _angstromRouter.addNode(bob);
        _angstromRouter.addNode(alice);
        assertTrue(_angstromRouter.isNode(bob), "Bob is not a node");
        assertTrue(_angstromRouter.isNode(alice), "Alice is not a node");
        _angstromRouter.removeNode(bob);
        vm.stopPrank();
        assertFalse(_angstromRouter.isNode(bob), "Bob is still a node");
        assertTrue(_angstromRouter.isNode(alice), "Alice is not a node after bob was removed");
    }

    // unlockRouter should only be callable by a node
    function testUnlockRouterNotNode() public {
        vm.expectRevert(AngstromRouter.NotNode.selector);
        _angstromRouter.manualUnlockRouter();
    }

    // unlockRouter should revert if called twice
    function testUnlockRouterTwice() public {
        vm.prank(admin);
        _angstromRouter.addNode(bob);

        vm.startPrank(bob);
        _angstromRouter.manualUnlockRouter();
        vm.expectRevert(AngstromRouter.OnlyOncePerBlock.selector);
        _angstromRouter.manualUnlockRouter();
        vm.stopPrank();
    }

    // unlockRouter should set lastUnlockBlockNumber with current block.number
    function testUnlockRouterSetsLastUnlockBlockNumber() public {
        vm.prank(admin);
        _angstromRouter.addNode(bob);

        assertEq(_angstromRouter.getLastUnlockBlockNumber(), 0, "Last unlock block number is not 0");

        vm.prank(bob);
        _angstromRouter.manualUnlockRouter();
        assertEq(
            _angstromRouter.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }
}
