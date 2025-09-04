// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import { IPermit2 } from "permit2/src/interfaces/IPermit2.sol";

import { IWETH } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/misc/IWETH.sol";
import { IRouter } from "@balancer-labs/v3-interfaces/contracts/vault/IRouter.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import {
    SwapPathExactAmountIn,
    SwapPathExactAmountOut,
    SwapExactInHookParams,
    SwapExactOutHookParams
} from "@balancer-labs/v3-interfaces/contracts/vault/BatchRouterTypes.sol";

import { SingletonAuthentication } from "@balancer-labs/v3-vault/contracts/SingletonAuthentication.sol";
import { BatchRouterHooks } from "@balancer-labs/v3-vault/contracts/BatchRouterHooks.sol";
import { RouterCommon } from "@balancer-labs/v3-vault/contracts/RouterCommon.sol";

// TODO interface
contract AngstromRouter is BatchRouterHooks, SingletonAuthentication {
    uint256 private _lastUnlockBlockNumber;

    error OnlyOncePerBlock();
    error NotNode();

    mapping(address => bool) private _nodes;

    constructor(
        IVault vault,
        IWETH weth,
        IPermit2 permit2,
        string memory routerVersion
    ) BatchRouterHooks(vault, weth, permit2, routerVersion) SingletonAuthentication(vault) {
        // solhint-disable-previous-line no-empty-blocks
    }

    /***************************************************************************
                                       Swaps
    ***************************************************************************/

    function swapExactIn(
        SwapPathExactAmountIn[] memory paths,
        uint256 deadline,
        bool wethIsEth,
        bytes calldata userData
    )
        external
        payable
        saveSender(msg.sender)
        returns (uint256[] memory pathAmountsOut, address[] memory tokensOut, uint256[] memory amountsOut)
    {
        // Unlocks the router in this block. If the router is already unlocked, reverts.
        _unlockRouter();

        return
            abi.decode(
                _vault.unlock(
                    abi.encodeCall(
                        BatchRouterHooks.swapExactInHook,
                        SwapExactInHookParams({
                            sender: msg.sender,
                            paths: paths,
                            deadline: deadline,
                            wethIsEth: wethIsEth,
                            userData: userData
                        })
                    )
                ),
                (uint256[], address[], uint256[])
            );
    }

    function swapExactOut(
        SwapPathExactAmountOut[] memory paths,
        uint256 deadline,
        bool wethIsEth,
        bytes calldata userData
    )
        external
        payable
        saveSender(msg.sender)
        returns (uint256[] memory pathAmountsIn, address[] memory tokensIn, uint256[] memory amountsIn)
    {
        // Unlocks the router in this block. If the router is already unlocked, reverts.
        _unlockRouter();

        return
            abi.decode(
                _vault.unlock(
                    abi.encodeCall(
                        BatchRouterHooks.swapExactOutHook,
                        SwapExactOutHookParams({
                            sender: msg.sender,
                            paths: paths,
                            deadline: deadline,
                            wethIsEth: wethIsEth,
                            userData: userData
                        })
                    )
                ),
                (uint256[], address[], uint256[])
            );
    }

    /***************************************************************************
                                     Queries
    ***************************************************************************/

    function querySwapExactIn(
        SwapPathExactAmountIn[] memory paths,
        address sender,
        bytes calldata userData
    )
        external
        saveSender(sender)
        returns (uint256[] memory pathAmountsOut, address[] memory tokensOut, uint256[] memory amountsOut)
    {
        for (uint256 i = 0; i < paths.length; ++i) {
            paths[i].minAmountOut = 0;
        }

        return
            abi.decode(
                _vault.quote(
                    abi.encodeCall(
                        BatchRouterHooks.querySwapExactInHook,
                        SwapExactInHookParams({
                            sender: address(this),
                            paths: paths,
                            deadline: type(uint256).max,
                            wethIsEth: false,
                            userData: userData
                        })
                    )
                ),
                (uint256[], address[], uint256[])
            );
    }

    function querySwapExactOut(
        SwapPathExactAmountOut[] memory paths,
        address sender,
        bytes calldata userData
    )
        external
        saveSender(sender)
        returns (uint256[] memory pathAmountsIn, address[] memory tokensIn, uint256[] memory amountsIn)
    {
        for (uint256 i = 0; i < paths.length; ++i) {
            paths[i].maxAmountIn = _MAX_AMOUNT;
        }

        return
            abi.decode(
                _vault.quote(
                    abi.encodeCall(
                        BatchRouterHooks.querySwapExactOutHook,
                        SwapExactOutHookParams({
                            sender: address(this),
                            paths: paths,
                            deadline: type(uint256).max,
                            wethIsEth: false,
                            userData: userData
                        })
                    )
                ),
                (uint256[], address[], uint256[])
            );
    }

    /***************************************************************************
                                Nodes Management
    ***************************************************************************/

    function addNode(address node) external authenticate {
        _nodes[node] = true;
    }
    function removeNode(address node) external authenticate {
        _nodes[node] = false;
    }

    /***************************************************************************
                                Getters
    ***************************************************************************/

    function getVault() public view override(RouterCommon, SingletonAuthentication) returns (IVault) {
        return _vault;
    }

    /***************************************************************************
                                Private Functions
    ***************************************************************************/

    function _unlockRouter() internal {
        // The router can only be unlocked once per block.
        if (_isRouterUnlocked()) {
            revert OnlyOncePerBlock();
        }

        // The "unlocker" must be a registered node of the Angstrom network.
        if (_isNode(msg.sender) == false) {
            revert NotNode();
        }

        _lastUnlockBlockNumber = block.number;
    }

    function _isNode(address account) internal view returns (bool) {
        return _nodes[account];
    }

    function _isRouterUnlocked() internal view returns (bool) {
        return _lastUnlockBlockNumber == block.number;
    }
}
