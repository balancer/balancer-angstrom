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
import "@balancer-labs/v3-interfaces/contracts/vault/BatchRouterTypes.sol";
import "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";

import { EVMCallModeHelpers } from "@balancer-labs/v3-solidity-utils/contracts/helpers/EVMCallModeHelpers.sol";
import { SingletonAuthentication } from "@balancer-labs/v3-vault/contracts/SingletonAuthentication.sol";
import { BatchRouterHooks } from "@balancer-labs/v3-vault/contracts/BatchRouterHooks.sol";
import { RouterCommon } from "@balancer-labs/v3-vault/contracts/RouterCommon.sol";
import { BaseHooks } from "@balancer-labs/v3-vault/contracts/BaseHooks.sol";

/**
 * @notice Angstrom Router and Hook, used to trade against Angstrom pools.
 * @dev This contract is a combination of a batch router and a hook, designed to work with pools traded primarily on
 * the [Angstrom network](https://github.com/SorellaLabs/angstrom). Angstrom is not an L2, but an application built by
 * Sorella Labs on Uniswap V4, and here adapted to Balancer. The hook portion is a port from `UnlockHook`; see
 * https://github.com/SorellaLabs/angstrom/blob/main/contracts/src/modules/UnlockHook.sol. The names of errors and many
 * functions have been retained for consistency.
 *
 * OFF-CHAIN CONTEXT
 *
 * The Angstrom network consists of off-chain validator nodes that conduct high-frequency auctions to determine fair
 * prices and optimal trade settlement, minimizing LVR and effectively eliminating LP losses to MEV.
 *
 * Retail traders submit limit orders to network nodes (not directly to Ethereum), while market makers bid for
 * zero-fee arbitrage rights. The matching system combines both liquidity sources to determine optimal execution
 * prices, with all participants getting the same auction-determined price per block.
 *
 * Similar to Ethereum's consensus layer, the Angstrom network chooses a validator to sign an attestation called
 * `AttestAngstromBlockEmpty(blockNumber)`, and submit a bundle transaction with all the Angstrom trades for the
 * current block. Price-altering transactions (swaps and unbalanced liquidity operations) must be coordinated through
 * this system, while price-neutral operations (queries and proportional liquidity) can bypass Angstrom entirely.
 *
 * To prevent front-running, Angstrom uses private mempools before submitting to Ethereum. Since Ethereum validators
 * control transaction ordering, Angstrom operations may appear in any order within a block - but this doesn't matter
 * because the first valid operation unlocks the system and everyone in the Angstrom bundle gets the same
 * pre-negotiated price.
 *
 * ON-CHAIN FUNCTIONALITY
 *
 * This contract maintains a registry of Angstrom validators in `_angstromValidatorNodes` (managed via `toggleNodes`),
 * and tracks the unlocked block in `_lastUnlockBlockNumber`.
 *
 * **Direct operations** (via this router): Only validators can call `swapExactIn`/`swapExactOut`, protected by
 * the `fromValidator` modifier.
 *
 * **Indirect operations** (via external routers): Anyone with a valid validator signature can execute swaps or
 * unbalanced liquidity operations by providing the signature in `userData` (for liquidity operations) or calldata
 * (for swaps). These trades all happen during execution of the Angstrom bundle transaction.
 *
 * The first validated operation unlocks the hook for that block. Post-bundle transactions will succeed, but incur
 * regular fees and prices can diverge from those guaranteed within the Angstrom bundle.
 *
 * See [this diagram](https://drive.google.com/file/d/1A4kNi0ocI_V8tWcy3ruGNf-AaoP04bmR/view?usp=sharing).
 */
contract AngstromBalancer is IBatchRouter, BatchRouterHooks, SingletonAuthentication, BaseHooks, EIP712 {
    /// @dev `keccak256("AttestAngstromBlockEmpty(uint64 block_number)")`.
    uint256 internal constant _ATTEST_EMPTY_BLOCK_TYPE_HASH =
        0x3f25e551746414ff93f076a7dd83828ff53735b39366c74015637e004fcb0223;

    /// @dev Set of active Angstrom validator nodes, authorized to unlock this contract for operations.
    mapping(address node => bool isActive) internal _angstromValidatorNodes;

    /// @dev The currently "unlocked" block. The contract is locked if the current block does not equal this number.
    uint256 internal _lastUnlockBlockNumber;

    /**
     * @notice This contract can only be unlocked once per block.
     * @dev This should not happen, but could if an Angstrom validator manually unlocks the contract twice, or manually
     * unlocks in the same block after the Angstrom bundle has been executed, or if there is more than one direct swap
     * in the bundle.
     */
    error OnlyOncePerBlock();

    /**
     * @notice An account attempted to unlock this contract that was not a registered Angstrom validator.
     * @dev The node must be registered as an Angstrom node to unlock the contract for operations, either directly or
     * by executing a permissioned operation. This can also occur for a valid signature, if the node address is
     * unregistered.
     */
    error NotNode();

    /// @notice A user attempted a swap without a signature.
    error CannotSwapWhileLocked();

    /**
     * @notice The userData with node address and signature is too short.
     * @dev The unlock data must be at least 20 bytes (address length) + 64/65 bytes (signature length).
     */
    error UnlockDataTooShort();

    /**
     * @notice The signature provided on a swap or liquidity operation was invalid.
     * @dev The user provided a signature of the correct length, and the node address is registered, but the hashed
     * message is wrong.
     */
    error InvalidSignature();

    modifier fromValidator() {
        // Only Validators can call direct swaps on this router.
        _ensureRegisteredNode(msg.sender);
        _;
    }

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
        fromValidator
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
        fromValidator
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

    // Note that queries do not require coordination with Angstrom, and can be called by anyone at any time.
    // We include them here to satisfy the IBatchRouter interface.

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
        // If the liquidity operation is proportional, prices are not affected, so it's a safe operation. Unbalanced
        // liquidity operations do affect prices, so we need to unlock the Angstrom network.
        if (kind != AddLiquidityKind.PROPORTIONAL) {
            // Unlocks the Angstrom network in this block, if necessary. An unlock through a hook requires a signature,
            // since any router can be used.
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
        // If the liquidity operation is proportional, prices are not affected, so it's a safe operation. Unbalanced
        // liquidity operations do affect prices, so we need to unlock the Angstrom network.
        if (kind != RemoveLiquidityKind.PROPORTIONAL) {
            // Unlocks the Angstrom network in this block, if necessary. An unlock through a hook requires a signature,
            // since any router can be used.
            _unlockAngstromWithHook(userData);
        }

        // If the signature is wrong, the hook will revert in the _unlockAngstromWithHook` function.
        return true;
    }

    /***************************************************************************
                                Manual Unlock
    ***************************************************************************/

    /**
     * @notice Unlocks the Angstrom network without requiring an operation.
     * @dev This function is used to manually unlock the Angstrom network. To be able to do that, the node must be
     * registered as an Angstrom node, and the signature must be valid (i.e., the hash must match the expected value
     * per EIP-712).
     *
     * @param node The node unlocking the Angstrom network
     * @param signature The signature of the node unlocking the Angstrom network
     */
    function unlockWithEmptyAttestation(address node, bytes memory signature) public {
        bytes32 digest = _ensureUnlockedAndNodeReturningDigest(node);

        if (SignatureCheckerLib.isValidSignatureNow(node, digest, signature) == false) {
            revert InvalidSignature();
        }

        _lastUnlockBlockNumber = block.number;
    }

    /**
     * @notice Unlocks the Angstrom network without requiring an operation.
     * @dev This function is used to manually unlock the Angstrom network. To be able to do that, the node must be
     * registered as an Angstrom node, and the signature must be valid (i.e., the hash must match the expected value
     * per EIP-712).
     *
     * @param node The node unlocking the Angstrom network
     * @param signature The signature of the node unlocking the Angstrom network
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
            _angstromValidatorNodes[nodes[i]] = !_angstromValidatorNodes[nodes[i]];
        }
    }

    /***************************************************************************
                                     Getters
    ***************************************************************************/

    /**
     * @notice Get the Vault contract.
     * @dev This function is needed since RouterCommon and SingletonAuthentication implementations of getVault()
     * collide.
     *
     * @return vault The address of the Vault contract
     */
    function getVault() public view override(RouterCommon, SingletonAuthentication) returns (IVault vault) {
        return _vault;
    }

    /**
     * @notice Check whether a given account is a registered Angstrom node.
     * @param account The address being checked for node status
     * @return isNode True if the address is a registered Angstrom node
     */
    function isRegisteredNode(address account) public view returns (bool) {
        return _angstromValidatorNodes[account];
    }

    /***************************************************************************
                                Internal Functions
    ***************************************************************************/

    function _unlockAngstromWithRouter() internal {
        _ensureUnlockedAndRegisteredNode(msg.sender);
        _lastUnlockBlockNumber = block.number;
    }

    function _isNode(address account) internal view returns (bool) {
        return _angstromValidatorNodes[account];
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

    function _ensureRegisteredNode(address account) internal view {
        if (isRegisteredNode(account) == false) {
            revert NotNode();
        }
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
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            mstore(0x00, _ATTEST_EMPTY_BLOCK_TYPE_HASH)
            mstore(0x20, number())
            attestationStructHash := keccak256(0x00, 0x40)
        }
        return _hashTypedData(attestationStructHash);
    }

    // The first 20 bytes of the user data is the node address; the rest is the signature.
    // This function separates the two so that the node signature can be verified.
    function _splitUserData(
        bytes memory userData
    ) internal pure returns (address extractedAddress, bytes memory remainingData) {
        uint256 signatureLength = userData.length - 20;

        // Extract first 20 bytes as address.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // `add(userData, 32)` is a pointer to the start of the data.
            // `shr(96, mload(...))` right-shifts 12 bytes (96 bits) to fit into 20 bytes.
            extractedAddress := shr(96, mload(add(userData, 32)))
        }

        // Copy the remaining 65 bytes into a new bytes array
        remainingData = new bytes(signatureLength);
        for (uint256 i = 0; i < signatureLength; i++) {
            remainingData[i] = userData[i + 20];
        }
    }
}
