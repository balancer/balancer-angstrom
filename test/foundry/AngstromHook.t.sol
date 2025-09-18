// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { ArrayHelpers } from "@balancer-labs/v3-solidity-utils/contracts/test/ArrayHelpers.sol";
import { FixedPoint } from "@balancer-labs/v3-solidity-utils/contracts/math/FixedPoint.sol";

import { AngstromBalancer } from "../../contracts/AngstromBalancer.sol";
import { BaseAngstromTest } from "./utils/BaseAngstromTest.sol";

contract AngstromHookTest is BaseAngstromTest {
    using ArrayHelpers for *;

    /***************************************************************************
                                    Swaps
    ***************************************************************************/

    function testOnBeforeSwapNotNode() public {
        vm.expectRevert(AngstromBalancer.NotNode.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, bobUserData);
    }

    function testOnBeforeSwapCannotSwapWhileLocked() public {
        // If no userData was provided (therefore, no signature), the hook treats as if the user expected the pools to
        // be unlocked.
        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, bytes(""));
    }

    function testOnBeforeSwapUnlockDataTooShort() public {
        // If the userData is too short, there's not enough data to represent the ECDSA signature.
        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, bytes("1"));
    }

    function testOnBeforeSwapInvalidSignature() public {
        // If the signature is invalid, the hook reverts (in this case, signer and key do not match).
        (, bytes memory userData) = generateSignatureAndUserData(bob, aliceKey);

        registerAngstromNode(bob);

        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, userData);
    }

    function testOnBeforeSwapSucceedsAndSetBlockNumber() public {
        registerAngstromNode(bob);

        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, bobUserData);
        assertEq(
            angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }

    function testOnlyOncePerBlock() public {
        registerAngstromNode(bob);

        vm.prank(bob);
        angstromBalancer.unlockWithEmptyAttestation(bob, bobSignature);

        vm.expectRevert(AngstromBalancer.OnlyOncePerBlock.selector);
        vm.prank(bob);
        angstromBalancer.unlockWithEmptyAttestation(bob, bobSignature);
    }

    /***************************************************************************
                                 Add Liquidity
    ***************************************************************************/
    function testOnBeforeAddLiquidityProportionalNoSignature() public {
        vm.prank(alice);
        router.addLiquidityProportional(pool, [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(), 1e18, false, bytes(""));

        assertEq(IERC20(pool).balanceOf(alice), 1e18, "Alice did not receive BPTs");
    }

    function testOnBeforeAddLiquidityUnbalancedNoSignature() public {
        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(alice);
        router.addLiquidityUnbalanced(pool, [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(), 1e18, false, bytes(""));
    }

    function testOnBeforeAddLiquidityUnbalancedUnlockDataTooShort() public {
        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(alice);
        router.addLiquidityUnbalanced(pool, [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(), 1e18, false, bytes("1"));
    }

    function testOnBeforeAddLiquidityUnbalancedNotNode() public {
        vm.expectRevert(AngstromBalancer.NotNode.selector);
        vm.prank(alice);
        router.addLiquidityUnbalanced(
            pool,
            [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(),
            1e18,
            false,
            aliceUserData
        );
    }

    function testOnBeforeAddLiquidityUnbalancedInvalidSignature() public {
        (, bytes memory userData) = generateSignatureAndUserData(alice, bobKey);

        registerAngstromNode(alice);

        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(alice);
        router.addLiquidityUnbalanced(pool, [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(), 1e18, false, userData);
    }

    function testOnBeforeAddLiquidityUnbalancedSucceedsAndSetBlockNumber() public {
        registerAngstromNode(alice);

        vm.prank(alice);
        uint256 expectedBptAmountOut = router.addLiquidityUnbalanced(
            pool,
            [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(),
            1e18,
            false,
            aliceUserData
        );
        assertEq(
            angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
        assertEq(IERC20(pool).balanceOf(alice), expectedBptAmountOut, "Alice did not receive BPTs");
    }

    /***************************************************************************
                                    Remove Liquidity
    ***************************************************************************/

    function testOnBeforeRemoveLiquidityProportionalNoSignature() public {
        Balances memory balancesBefore = getBalances(lp);

        vm.prank(lp);
        router.removeLiquidityProportional(pool, 1e18, [uint256(0), uint256(0)].toMemoryArray(), false, bytes(""));

        Balances memory balancesAfter = getBalances(lp);

        assertEq(balancesAfter.lpBpt, balancesBefore.lpBpt - 1e18, "LP did not burn BPTs");
    }

    function testOnBeforeRemoveLiquidityUnbalancedNoSignature() public {
        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, bytes(""));
    }

    function testOnBeforeRemoveLiquidityUnbalancedUnlockDataTooShort() public {
        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, bytes("1"));
    }

    function testOnBeforeRemoveLiquidityUnbalancedNotNode() public {
        vm.expectRevert(AngstromBalancer.NotNode.selector);
        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, lpUserData);
    }

    function testOnBeforeRemoveLiquidityUnbalancedInvalidSignature() public {
        (, bytes memory userData) = generateSignatureAndUserData(lp, bobKey);

        registerAngstromNode(lp);

        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, userData);
    }

    function testOnBeforeRemoveLiquidityUnbalancedSucceedsAndSetBlockNumber() public {
        registerAngstromNode(lp);

        Balances memory balancesBefore = getBalances(lp);

        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, lpUserData);

        Balances memory balancesAfter = getBalances(lp);

        assertEq(
            angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
        assertEq(balancesAfter.lpBpt, balancesBefore.lpBpt - 1e18, "LP did not burn BPTs");
    }
}
