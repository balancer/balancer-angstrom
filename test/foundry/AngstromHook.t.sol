// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { IAuthentication } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IAuthentication.sol";
import {
    SwapPathExactAmountIn,
    SwapPathExactAmountOut
} from "@balancer-labs/v3-interfaces/contracts/vault/BatchRouterTypes.sol";

import { ArrayHelpers } from "@balancer-labs/v3-solidity-utils/contracts/test/ArrayHelpers.sol";
import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";
import { FixedPoint } from "@balancer-labs/v3-solidity-utils/contracts/math/FixedPoint.sol";

import { AngstromBalancerMock } from "../../contracts/test/AngstromBalancerMock.sol";
import { AngstromBalancer } from "../../contracts/AngstromBalancer.sol";

contract AngstromHookTest is BaseVaultTest {
    using ArrayHelpers for *;

    AngstromBalancerMock private _angstromBalancer;

    function setUp() public virtual override {
        super.setUp();
        authorizer.grantRole(_angstromBalancer.getActionId(AngstromBalancer.toggleNodes.selector), admin);
    }

    function createHook() internal override returns (address) {
        // Creating the router and hook in this function ensures that "pool" has the hook set correctly.
        _angstromBalancer = new AngstromBalancerMock(vault, weth, permit2, "AngstromBalancer Mock v1");
        return address(_angstromBalancer);
    }

    /***************************************************************************
                                    Swaps
    ***************************************************************************/

    function testOnBeforeSwapNotNode() public {
        (, bytes memory userData) = _generateSignatureAndUserData(bob, bobKey);

        vm.expectRevert(AngstromBalancer.NotNode.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, userData);
    }

    function testOnBeforeSwapCannotSwapWhileLocked() public {
        // If no userData was provided (therefore, no signature), the hook treats as if the user expected the pools to
        // be unlocked.
        vm.expectRevert(AngstromBalancer.CannotSwapWhileLocked.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, bytes(""));
    }

    function testOnBeforeSwapUnlockDataTooShort() public {
        // If the userData is too short, there's not enough data to represent the ECDSA signature.
        vm.expectRevert(AngstromBalancer.UnlockDataTooShort.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, bytes("1"));
    }

    function testOnBeforeSwapInvalidSignature() public {
        // If the signature is invalid, the hook reverts (in this case, signer and key do not match).
        (, bytes memory userData) = _generateSignatureAndUserData(bob, aliceKey);

        vm.prank(admin);
        _angstromBalancer.toggleNodes([bob].toMemoryArray());

        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, userData);
    }

    function testOnBeforeSwapSucceedsAndSetBlockNumber() public {
        (, bytes memory userData) = _generateSignatureAndUserData(bob, bobKey);

        vm.prank(admin);
        _angstromBalancer.toggleNodes([bob].toMemoryArray());

        vm.prank(bob);
        router.swapSingleTokenExactIn(pool, dai, usdc, 1e18, 0, MAX_UINT256, false, userData);
        assertEq(
            _angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }

    function testOnlyOncePerBlock() public {
        vm.prank(admin);
        _angstromBalancer.toggleNodes([bob].toMemoryArray());

        (bytes memory signature, ) = _generateSignatureAndUserData(bob, bobKey);
        vm.prank(bob);
        _angstromBalancer.unlockWithEmptyAttestation(bob, signature);

        vm.expectRevert(AngstromBalancer.OnlyOncePerBlock.selector);
        vm.prank(bob);
        _angstromBalancer.unlockWithEmptyAttestation(bob, signature);
    }

    function testOnlyOncePerBlockCalldata() public {
        vm.prank(admin);
        _angstromBalancer.toggleNodes([bob].toMemoryArray());

        (bytes memory signature, ) = _generateSignatureAndUserData(bob, bobKey);
        vm.prank(bob);
        _angstromBalancer.unlockWithEmptyAttestationCalldata(bob, signature);

        vm.expectRevert(AngstromBalancer.OnlyOncePerBlock.selector);
        vm.prank(bob);
        _angstromBalancer.unlockWithEmptyAttestationCalldata(bob, signature);
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
        vm.expectRevert(AngstromBalancer.CannotSwapWhileLocked.selector);
        vm.prank(alice);
        router.addLiquidityUnbalanced(pool, [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(), 1e18, false, bytes(""));
    }

    function testOnBeforeAddLiquidityUnbalancedUnlockDataTooShort() public {
        vm.expectRevert(AngstromBalancer.UnlockDataTooShort.selector);
        vm.prank(alice);
        router.addLiquidityUnbalanced(pool, [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(), 1e18, false, bytes("1"));
    }

    function testOnBeforeAddLiquidityUnbalancedNotNode() public {
        (, bytes memory userData) = _generateSignatureAndUserData(alice, aliceKey);

        vm.expectRevert(AngstromBalancer.NotNode.selector);
        vm.prank(alice);
        router.addLiquidityUnbalanced(pool, [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(), 1e18, false, userData);
    }

    function testOnBeforeAddLiquidityUnbalancedInvalidSignature() public {
        (, bytes memory userData) = _generateSignatureAndUserData(alice, bobKey);

        vm.prank(admin);
        _angstromBalancer.toggleNodes([alice].toMemoryArray());

        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(alice);
        router.addLiquidityUnbalanced(pool, [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(), 1e18, false, userData);
    }

    function testOnBeforeAddLiquidityUnbalancedSucceedsAndSetBlockNumber() public {
        (, bytes memory userData) = _generateSignatureAndUserData(alice, aliceKey);

        vm.prank(admin);
        _angstromBalancer.toggleNodes([alice].toMemoryArray());

        vm.prank(alice);
        uint256 expectedBptAmountOut = router.addLiquidityUnbalanced(
            pool,
            [FixedPoint.ONE, FixedPoint.ONE].toMemoryArray(),
            1e18,
            false,
            userData
        );
        assertEq(
            _angstromBalancer.getLastUnlockBlockNumber(),
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
        vm.expectRevert(AngstromBalancer.CannotSwapWhileLocked.selector);
        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, bytes(""));
    }

    function testOnBeforeRemoveLiquidityUnbalancedUnlockDataTooShort() public {
        vm.expectRevert(AngstromBalancer.UnlockDataTooShort.selector);
        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, bytes("1"));
    }

    function testOnBeforeRemoveLiquidityUnbalancedNotNode() public {
        (, bytes memory userData) = _generateSignatureAndUserData(lp, lpKey);

        vm.expectRevert(AngstromBalancer.NotNode.selector);
        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, userData);
    }

    function testOnBeforeRemoveLiquidityUnbalancedInvalidSignature() public {
        (, bytes memory userData) = _generateSignatureAndUserData(lp, bobKey);

        vm.prank(admin);
        _angstromBalancer.toggleNodes([lp].toMemoryArray());

        vm.expectRevert(AngstromBalancer.InvalidSignature.selector);
        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, userData);
    }

    function testOnBeforeRemoveLiquidityUnbalancedSucceedsAndSetBlockNumber() public {
        (, bytes memory userData) = _generateSignatureAndUserData(lp, lpKey);

        vm.prank(admin);
        _angstromBalancer.toggleNodes([lp].toMemoryArray());

        Balances memory balancesBefore = getBalances(lp);

        vm.prank(lp);
        router.removeLiquiditySingleTokenExactIn(pool, 1e18, dai, 0.1e18, false, userData);

        Balances memory balancesAfter = getBalances(lp);

        assertEq(
            _angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
        assertEq(balancesAfter.lpBpt, balancesBefore.lpBpt - 1e18, "LP did not burn BPTs");
    }

    function _generateSignatureAndUserData(
        address signer,
        uint256 privateKey
    ) private view returns (bytes memory signature, bytes memory userData) {
        bytes32 hash = _angstromBalancer.getDigest();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        signature = abi.encodePacked(r, s, v);
        userData = abi.encodePacked(signer, signature);
    }
}
