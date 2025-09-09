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

import { EVMCallModeHelpers } from "@balancer-labs/v3-solidity-utils/contracts/helpers/EVMCallModeHelpers.sol";
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
    ) public pure override returns (bool) {
        return true;
    }

    /// @inheritdoc IHooks
    function getHookFlags() public pure override returns (HookFlags memory hookFlags) {
        hookFlags.shouldCallBeforeSwap = true;
        hookFlags.shouldCallBeforeAddLiquidity = true;
        hookFlags.shouldCallBeforeRemoveLiquidity = true;
    }

    /// @inheritdoc IHooks
    function onBeforeSwap(PoolSwapParams calldata params, address) public override returns (bool) {
        // Unlocks the Angstrom network in this block. If the Angstrom network is already unlocked, reverts.
        // Differently from the unlock in the router, an unlock in the hook level requires a signature, because any
        // router can call it.
        _unlockAngstromWithSignatureCalldata(params.userData);

        return true;
    }

    /// @inheritdoc IHooks
    function onBeforeAddLiquidity(
        address,
        address,
        AddLiquidityKind kind,
        uint256[] memory,
        uint256,
        uint256[] memory,
        bytes memory userData
    ) public override returns (bool) {
        // If the liquidity operation is proportional, rates are not affected, so it's a safe operation. Unbalanced
        // liquidity operations affects the rate, so we need to unlock the Angstrom network.
        if (kind != AddLiquidityKind.PROPORTIONAL) {
            // Unlocks the Angstrom network in this block. If the Angstrom network is already unlocked, reverts.
            // Differently from the unlock in the router, an unlock in the hook level requires a signature, because any
            // router can call it.
            _unlockAngstromWithSignature(userData);
        }
        return true;
    }

    /// @inheritdoc IHooks
    function onBeforeRemoveLiquidity(
        address,
        address,
        RemoveLiquidityKind kind,
        uint256,
        uint256[] memory,
        uint256[] memory,
        bytes memory userData
    ) public override returns (bool) {
        // If the liquidity operation is proportional, rates are not affected, so it's a safe operation. Unbalanced
        // liquidity operations affects the rate, so we need to unlock the Angstrom network.
        if (kind != RemoveLiquidityKind.PROPORTIONAL) {
            // Unlocks the Angstrom network in this block. If the Angstrom network is already unlocked, reverts.
            // Differently from the unlock in the router, an unlock in the hook level requires a signature, because any
            // router can call it.
            _unlockAngstromWithSignature(userData);
        }

        return true;
    }

    function unlockWithEmptyAttestation(address node, bytes memory signature) public {
        // The router can only be unlocked once per block.
        if (_isAngstromUnlocked()) {
            revert OnlyOncePerBlock();
        }

        // The "unlocker" must be a registered node of the Angstrom network.
        if (_isNode(node) == false) {
            revert NotNode();
        }

        bytes32 digest = _getDigest();

        if (SignatureCheckerLib.isValidSignatureNow(node, digest, signature) == false) {
            revert InvalidSignature();
        }

        _lastUnlockBlockNumber = block.number;
    }

    function unlockWithEmptyAttestationCalldata(address node, bytes calldata signature) public {
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

    function _unlockAngstromWithSignature(bytes memory userData) internal {
        // If the call is a query, do not revert if the block is unlocked.
        if (_isAngstromUnlocked() == false && EVMCallModeHelpers.isStaticCall() == false) {
            if (userData.length < 20) {
                if (userData.length == 0) {
                    revert CannotSwapWhileLocked();
                }
                revert UnlockDataTooShort();
            } else {
                (address node, bytes memory signature) = _splitUserData(userData);
                unlockWithEmptyAttestation(node, signature);
            }
        }
    }

    // TODO Explain why we need this function
    function _splitUserData(
        bytes memory userData
    ) internal pure returns (address extractedAddress, bytes memory remainingData) {
        uint256 signatureLength = userData.length - 20;

        // Extract first 20 bytes as address
        assembly {
            // `add(userData, 32)` is a pointer to the start of the data
            // `shr(96, mload(...))` right-shifts 12 bytes (96 bits) to fit into 20 bytes
            extractedAddress := shr(96, mload(add(userData, 32)))
        }

        // Copy the remaining 65 bytes into a new bytes array
        remainingData = new bytes(signatureLength);
        for (uint256 i = 0; i < signatureLength; i++) {
            remainingData[i] = userData[i + 20];
        }
    }

    function _unlockAngstromWithSignatureCalldata(bytes calldata userData) internal {
        // If the call is a query, do not revert if the block is unlocked.
        if (_isAngstromUnlocked() == false && EVMCallModeHelpers.isStaticCall() == false) {
            if (userData.length < 20) {
                if (userData.length == 0) {
                    revert CannotSwapWhileLocked();
                }
                revert UnlockDataTooShort();
            } else {
                address node = address(bytes20(userData[:20]));
                bytes calldata signature = userData[20:];
                unlockWithEmptyAttestationCalldata(node, signature);
            }
        }
    }

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("Angstrom", "v1");
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
}
