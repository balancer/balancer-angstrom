// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { IAuthentication } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/helpers/IAuthentication.sol";
import {
    SwapPathExactAmountIn,
    SwapPathExactAmountOut,
    SwapPathStep
} from "@balancer-labs/v3-interfaces/contracts/vault/BatchRouterTypes.sol";

import { ArrayHelpers } from "@balancer-labs/v3-solidity-utils/contracts/test/ArrayHelpers.sol";

import { AngstromBalancerMock } from "../../contracts/test/AngstromBalancerMock.sol";
import { AngstromBalancer } from "../../contracts/AngstromBalancer.sol";
import { BaseAngstromTest } from "./utils/BaseAngstromTest.sol";

contract AngstromRouterTest is BaseAngstromTest {
    using ArrayHelpers for *;

    function setUp() public virtual override {
        BaseAngstromTest.setUp();

        _approveAngstromRouterForAllUsers();
        approveAngstromRouterForPool(IERC20(pool));
    }

    function testSwapExactInNotNode() public {
        SwapPathExactAmountIn[] memory paths;
        vm.expectRevert(AngstromBalancer.NotNode.selector);
        angstromBalancer.swapExactIn(paths, MAX_UINT256, false, bytes(""));
    }

    function testSwapExactInAlreadyUnlocked() public {
        makeAngstromNode(bob);

        SwapPathExactAmountIn[] memory paths;

        angstromBalancer.manualUnlockAngstrom();
        vm.expectRevert(AngstromBalancer.OnlyOncePerBlock.selector);

        vm.prank(bob);
        angstromBalancer.swapExactIn(paths, MAX_UINT256, false, bytes(""));
    }

    function testSwapExactInUnlocksAngstrom() public {
        makeAngstromNode(bob);

        SwapPathExactAmountIn[] memory paths;

        vm.prank(bob);
        angstromBalancer.swapExactIn(paths, MAX_UINT256, false, bytes(""));
        assertEq(
            angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }

    function testQuerySwapExactIn() public {
        SwapPathStep[] memory steps = new SwapPathStep[](1);
        steps[0] = SwapPathStep({ pool: pool, tokenOut: usdc, isBuffer: false });
        SwapPathExactAmountIn[] memory paths = new SwapPathExactAmountIn[](1);
        paths[0] = SwapPathExactAmountIn({ tokenIn: dai, steps: steps, exactAmountIn: 1e18, minAmountOut: 0 });

        uint256 snapId = vm.snapshot();
        _prankStaticCall();
        (
            uint256[] memory pathAmountsOutQuery,
            address[] memory tokensOutQuery,
            uint256[] memory amountsOutQuery
        ) = angstromBalancer.querySwapExactIn(paths, bob, bytes(""));
        vm.revertTo(snapId);

        makeAngstromNode(bob);

        vm.prank(bob);
        (uint256[] memory pathAmountsOut, address[] memory tokensOut, uint256[] memory amountsOut) = angstromBalancer
            .swapExactIn(paths, MAX_UINT256, false, bytes(""));

        assertEq(pathAmountsOut.length, pathAmountsOutQuery.length, "Path amounts out length is not equal");
        assertEq(tokensOut.length, tokensOutQuery.length, "Tokens out length is not equal");
        assertEq(amountsOut.length, amountsOutQuery.length, "Amounts out length is not equal");

        for (uint256 i = 0; i < pathAmountsOut.length; i++) {
            assertEq(pathAmountsOut[i], pathAmountsOutQuery[i], "Path amounts out is not equal");
            assertEq(tokensOut[i], tokensOutQuery[i], "Tokens out is not equal");
            assertEq(amountsOut[i], amountsOutQuery[i], "Amounts out is not equal");
        }
    }

    function testSwapExactOutNotNode() public {
        SwapPathExactAmountOut[] memory paths;
        vm.expectRevert(AngstromBalancer.NotNode.selector);
        angstromBalancer.swapExactOut(paths, MAX_UINT256, false, bytes(""));
    }

    function testSwapExactOutAlreadyUnlocked() public {
        makeAngstromNode(bob);

        SwapPathExactAmountOut[] memory paths;

        angstromBalancer.manualUnlockAngstrom();

        vm.expectRevert(AngstromBalancer.OnlyOncePerBlock.selector);
        vm.prank(bob);
        angstromBalancer.swapExactOut(paths, MAX_UINT256, false, bytes(""));
    }

    function testSwapExactOutUnlocksRouter() public {
        makeAngstromNode(bob);

        SwapPathExactAmountOut[] memory paths;
        vm.prank(bob);
        angstromBalancer.swapExactOut(paths, MAX_UINT256, false, bytes(""));
        assertEq(
            angstromBalancer.getLastUnlockBlockNumber(),
            block.number,
            "Last unlock block number is not the current block number"
        );
    }

    function testQuerySwapExactOut() public {
        SwapPathStep[] memory steps = new SwapPathStep[](1);
        steps[0] = SwapPathStep({ pool: pool, tokenOut: usdc, isBuffer: false });
        SwapPathExactAmountOut[] memory paths = new SwapPathExactAmountOut[](1);
        paths[0] = SwapPathExactAmountOut({
            tokenIn: dai,
            steps: steps,
            exactAmountOut: 1e18,
            maxAmountIn: MAX_UINT256
        });

        uint256 snapId = vm.snapshot();
        _prankStaticCall();
        (
            uint256[] memory pathAmountsInQuery,
            address[] memory tokensInQuery,
            uint256[] memory amountsInQuery
        ) = angstromBalancer.querySwapExactOut(paths, bob, bytes(""));
        vm.revertTo(snapId);

        makeAngstromNode(bob);

        vm.prank(bob);
        (uint256[] memory pathAmountsIn, address[] memory tokensIn, uint256[] memory amountsIn) = angstromBalancer
            .swapExactOut(paths, MAX_UINT256, false, bytes(""));

        assertEq(pathAmountsIn.length, pathAmountsInQuery.length, "Path amounts in length is not equal");
        assertEq(tokensIn.length, tokensInQuery.length, "Tokens in length is not equal");
        assertEq(amountsIn.length, amountsInQuery.length, "Amounts in length is not equal");

        for (uint256 i = 0; i < pathAmountsIn.length; i++) {
            assertEq(pathAmountsIn[i], pathAmountsInQuery[i], "Path amounts in is not equal");
            assertEq(tokensIn[i], tokensInQuery[i], "Tokens in is not equal");
            assertEq(amountsIn[i], amountsInQuery[i], "Amounts in is not equal");
        }
    }

    function _approveAngstromRouterForAllUsers() private {
        for (uint256 i = 0; i < users.length; ++i) {
            address user = users[i];
            vm.startPrank(user);
            approveAngstromRouterForSender();
            vm.stopPrank();
        }
    }

    function approveAngstromRouterForSender() internal {
        for (uint256 i = 0; i < tokens.length; ++i) {
            permit2.approve(address(tokens[i]), address(angstromBalancer), type(uint160).max, type(uint48).max);
        }

        for (uint256 i = 0; i < oddDecimalTokens.length; ++i) {
            permit2.approve(
                address(oddDecimalTokens[i]),
                address(angstromBalancer),
                type(uint160).max,
                type(uint48).max
            );
        }

        for (uint256 i = 0; i < erc4626Tokens.length; ++i) {
            permit2.approve(address(erc4626Tokens[i]), address(angstromBalancer), type(uint160).max, type(uint48).max);
        }
    }

    function approveAngstromRouterForPool(IERC20 bpt) internal {
        for (uint256 i = 0; i < users.length; ++i) {
            vm.startPrank(users[i]);
            bpt.approve(address(angstromBalancer), type(uint256).max);
            permit2.approve(address(bpt), address(angstromBalancer), type(uint160).max, type(uint48).max);
            vm.stopPrank();
        }
    }
}
