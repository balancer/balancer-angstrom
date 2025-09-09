// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";
import { IPermit2 } from "permit2/src/interfaces/IPermit2.sol";
import { EIP712 } from "solady/src/utils/EIP712.sol";

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

/**
 * @notice Angstrom Router and Hook, used to trade against angstrom pools.
 * @dev This contract is a combination of a batch router and a hook. The goal is to only allow swaps and unbalanced
 * liquidity operations for nodes registered as such and with the valid signature for a certain block, before the
 * router and the hook are unlocked. This ensures that the node has preference to trade against pools in a that block,
 * which also ensures that the pool rates are the same as the computed offchain for that block.
 * Notice that unlock is "global" for a certain block, i.e., if a node unlocks a hook or router in a block, all pools
 * are unlocked. Unlocked pools accept any operation (swap, unbalanced liquidity, etc) from any router.
 */
contract AngstromRouterAndHook is IBatchRouter, BatchRouterHooks, SingletonAuthentication, BaseHooks, EIP712 {
    uint256 internal _lastUnlockBlockNumber;

    /**
     * @notice The router and hook can only be unlocked once per block.
     * @dev The Angstrom router cannot be called twice in the same block. So, this error prevents a transaction from
     * being called twice in the same block.
     */
    error OnlyOncePerBlock();

    /**
     * @notice The node (sender of transaction) is not registered as an Angstrom node.
     * @dev The node must be registered as an Angstrom node to be able to trade against angstrom pools before unlock.
     */
    error NotNode();

    /// @notice No signature is provided and Angstrom network is still locked.
    error CannotSwapWhileLocked();

    /**
     * @notice The userData with node address and signature is too short.
     * @dev The unlock data must be at least 20 bytes (address length) + 64/65 bytes (signature length).
     */
    error UnlockDataTooShort();

    /// @notice The signature matches the length, the node address is registered, but the hashed message is wrong.
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
        _unlockAngstromWithRouter();

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
        _unlockAngstromWithRouter();

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
        // This is a regular query, no need to unlock Angstrom network. It's in here to comply with IBatchRouter.
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
        // This is a regular query, no need to unlock Angstrom network. It's in here to comply with IBatchRouter.

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
        // Any type of pool is allowed, from any factory. No need to validate `onRegister` inputs.
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
        _unlockAngstromWithHookCalldata(params.userData);

        // If the signature is wrong, the hook will revert in the _unlockAngstromWithHookCalldata` function.
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
            _unlockAngstromWithHook(userData);
        }

        // If the signature is wrong, the hook will revert in the _unlockAngstromWithHook` function.
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
            _unlockAngstromWithHook(userData);
        }

        // If the signature is wrong, the hook will revert in the _unlockAngstromWithHook` function.
        return true;
    }

    /**
     * @notice Unlocks the Angstrom network.
     * @dev This function is used to unlock the Angstrom network. To be able to do that, the node must be registered as
     * an Angstrom node and the signature must be valid (it means, the hash mush match the expected hash, according to
     * EIP-712). Also, this function waits a signature located in the memory (as sent through the liquidity hooks). For
     * swap hook, check `unlockWithEmptyAttestationCalldata`.
     *
     * @param node The node that is unlocking the Angstrom network
     * @param signature The signature of the node that is unlocking the Angstrom network
     */
    function unlockWithEmptyAttestation(address node, bytes memory signature) public {
        bytes32 digest = _ensureUnlockedAndNodeReturningDigest(node);

        if (SignatureCheckerLib.isValidSignatureNow(node, digest, signature) == false) {
            revert InvalidSignature();
        }

        _lastUnlockBlockNumber = block.number;
    }

    /**
     * @notice Unlocks the Angstrom network.
     * @dev This function is used to unlock the Angstrom network. To be able to do that, the node must be registered as
     * an Angstrom node and the signature must be valid (it means, the hash mush match the expected hash, according to
     * EIP-712). Also, this function waits a signature located in the calldata (as sent through the swap hooks). For
     * liquidity hooks, check `unlockWithEmptyAttestation`.
     *
     * @param node The node that is unlocking the Angstrom network
     * @param signature The signature of the node that is unlocking the Angstrom network
     */
    function unlockWithEmptyAttestationCalldata(address node, bytes calldata signature) public {
        bytes32 digest = _ensureUnlockedAndNodeReturningDigest(node);

        if (SignatureCheckerLib.isValidSignatureNowCalldata(node, digest, signature) == false) {
            revert InvalidSignature();
        }

        _lastUnlockBlockNumber = block.number;
    }

    /***************************************************************************
                                 Nodes Management
    ***************************************************************************/

    /**
     * @notice Register/unregister nodes for a given block.
     * @param nodes The nodes to toggle (register/unregister)
     */
    function toggleNodes(address[] memory nodes) external authenticate {
        for (uint256 i = 0; i < nodes.length; i++) {
            _nodes[nodes[i]] = !_nodes[nodes[i]];
        }
    }

    /***************************************************************************
                                     Getters
    ***************************************************************************/

    /**
     * @notice Get the vault contract.
     * @dev This function is needed since RouterCommon and SingletonAuthentication implementations of getVault()
     * collide.
     *
     * @return vault The vault contract
     */
    function getVault() public view override(RouterCommon, SingletonAuthentication) returns (IVault vault) {
        return _vault;
    }

    /***************************************************************************
                                Private Functions
    ***************************************************************************/

    function _unlockAngstromWithRouter() internal {
        _ensureUnlockedAndRegisteredNode(msg.sender);
        _lastUnlockBlockNumber = block.number;
    }

    function _isNode(address account) internal view returns (bool) {
        return _nodes[account];
    }

    function _isAngstromUnlocked() internal view returns (bool) {
        return _lastUnlockBlockNumber == block.number;
    }

    function _unlockAngstromWithHook(bytes memory userData) internal {
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

    function _unlockAngstromWithHookCalldata(bytes calldata userData) internal {
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

    function _ensureUnlockedAndNodeReturningDigest(address node) internal view returns (bytes32) {
        _ensureUnlockedAndRegisteredNode(node);

        return _getDigest();
    }

    function _ensureUnlockedAndRegisteredNode(address node) internal view {
        // The router can only be unlocked once per block.
        if (_isAngstromUnlocked()) {
            revert OnlyOncePerBlock();
        }

        // The "unlocker" must be a registered node of the Angstrom network.
        if (_isNode(node) == false) {
            revert NotNode();
        }
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
}
