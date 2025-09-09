// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { IPermit2 } from "permit2/src/interfaces/IPermit2.sol";
import { EIP712 } from "solady/utils/EIP712.sol";

import { IBatchRouterQueries } from "@balancer-labs/v3-interfaces/contracts/vault/IBatchRouterQueries.sol";
import { IWETH } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/misc/IWETH.sol";
import { IBatchRouter } from "@balancer-labs/v3-interfaces/contracts/vault/IBatchRouter.sol";
import { IHooks } from "@balancer-labs/v3-interfaces/contracts/vault/IHooks.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import {
    SwapPathExactAmountIn,
    SwapPathExactAmountOut,
    SwapExactInHookParams,
    SwapExactOutHookParams
} from "@balancer-labs/v3-interfaces/contracts/vault/BatchRouterTypes.sol";
import "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";

import { SingletonAuthentication } from "@balancer-labs/v3-vault/contracts/SingletonAuthentication.sol";
import { BatchRouterHooks } from "@balancer-labs/v3-vault/contracts/BatchRouterHooks.sol";
import { RouterCommon } from "@balancer-labs/v3-vault/contracts/RouterCommon.sol";
import { BaseHooks } from "@balancer-labs/v3-vault/contracts/BaseHooks.sol";

contract AngstromRouterAndHook is IBatchRouter, BatchRouterHooks, SingletonAuthentication, BaseHooks, EIP712 {
    uint256 internal _lastUnlockBlockNumber;

    error OnlyOncePerBlock();
    error NotNode();
    error CannotSwapWhileLocked();
    error UnlockDataTooShort();
    error InvalidSignature();

    /// @dev `keccak256("AttestAngstromBlockEmpty(uint64 block_number)")`
    uint256 internal constant ATTEST_EMPTY_BLOCK_TYPE_HASH =
        0x3f25e551746414ff93f076a7dd83828ff53735b39366c74015637e004fcb0223;

    mapping(address => bool) internal _nodes;

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
    /// @inheritdoc IBatchRouter
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
        // Unlocks the Angstrom network in this block. If the Angstrom network is already unlocked, reverts.
        _unlockAngstrom();

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

    /// @inheritdoc IBatchRouter
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
        // Unlocks the Angstrom Network in this block. If the Angstrom Network is already unlocked, reverts.
        _unlockAngstrom();

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

    /// @inheritdoc IBatchRouterQueries
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

    /// @inheritdoc IBatchRouterQueries
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
                                     Hooks
    ***************************************************************************/

    /// @inheritdoc IHooks
    function onRegister(
        address,
        address,
        TokenConfig[] memory,
        LiquidityManagement calldata
    ) public override returns (bool) {
        return true;
    }

    /// @inheritdoc IHooks
    function getHookFlags() public view override returns (HookFlags memory hookFlags) {
        hookFlags.shouldCallBeforeSwap = true;
        // hookFlags.shouldCallBeforeAddLiquidity = true;
        // hookFlags.shouldCallBeforeRemoveLiquidity = true;
    }

    /// @inheritdoc IHooks
    function onBeforeSwap(PoolSwapParams calldata params, address) public override returns (bool) {
        if (_isAngstromUnlocked() == false) {
            if (params.userData.length < 20) {
                if (params.userData.length == 0) {
                    revert CannotSwapWhileLocked();
                }
                revert UnlockDataTooShort();
            } else {
                address node = address(bytes20(params.userData[:20]));
                bytes calldata signature = params.userData[20:];
                unlockWithEmptyAttestation(node, signature);
            }
        }
        return true;
    }

    function unlockWithEmptyAttestation(address node, bytes calldata signature) public {
        // The router can only be unlocked once per block.
        if (_isAngstromUnlocked()) {
            revert OnlyOncePerBlock();
        }

        // The "unlocker" must be a registered node of the Angstrom network.
        if (_isNode(node) == false) {
            revert NotNode();
        }

        bytes32 digest = _getDigest();

        if (SignatureCheckerLib.isValidSignatureNowCalldata(node, digest, signature) == false) {
            revert InvalidSignature();
        }

        _lastUnlockBlockNumber = block.number;
    }

    function _getDigest() internal view returns (bytes32) {
        bytes32 attestationStructHash;
        assembly ("memory-safe") {
            mstore(0x00, ATTEST_EMPTY_BLOCK_TYPE_HASH)
            mstore(0x20, number())
            attestationStructHash := keccak256(0x00, 0x40)
        }
        return _hashTypedData(attestationStructHash);
    }

    /***************************************************************************
                                 Nodes Management
    ***************************************************************************/

    function toggleNodes(address[] memory nodes) external authenticate {
        for (uint256 i = 0; i < nodes.length; i++) {
            _nodes[nodes[i]] = !_nodes[nodes[i]];
        }
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

    function _unlockAngstrom() internal {
        // The router can only be unlocked once per block.
        if (_isAngstromUnlocked()) {
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

    function _isAngstromUnlocked() internal view returns (bool) {
        return _lastUnlockBlockNumber == block.number;
    }

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("Angstrom", "v1");
    }
}
