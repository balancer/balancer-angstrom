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
import { OwnableAuthentication } from "@balancer-labs/v3-standalone-utils/contracts/OwnableAuthentication.sol";
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
 * the `onlyValidatorNode` modifier. The router can only be called once per block.
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
contract AngstromBalancer is IBatchRouter, BatchRouterHooks, OwnableAuthentication, BaseHooks, EIP712 {
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

    /**
     * @notice The signature provided on a swap or liquidity operation was invalid.
     * @dev The user provided a signature of the correct length, and the node address is registered, but the hashed
     * message is wrong.
     */
    error InvalidSignature();

    /**
     * @notice The node was already registered.
     * @dev The node was already registered as an Angstrom node
     */
    error NodeAlreadyRegistered();

    /**
     * @notice The node was not registered.
     * @dev The node was not registered as an Angstrom node
     */
    error NodeNotRegistered();

    /// @notice A node was registered and is allowed to unlock Angstrom pools.
    event NodeRegistered(address indexed node);

    /// @notice A node was deregistered and is no longer able to unlock Angstrom pools.
    event NodeDeregistered(address indexed node);

    modifier onlyValidatorNode() {
        // Only Validators can call direct swaps on this router.
        _ensureRegisteredNode(msg.sender);
        _;
    }

    modifier onlyWhenLocked() {
        _ensureAngstromLocked();
        _;
    }

    constructor(
        IVault vault,
        IWETH weth,
        IPermit2 permit2,
        string memory routerVersion
    ) BatchRouterHooks(vault, weth, permit2, routerVersion) OwnableAuthentication(vault, msg.sender) {
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
        onlyValidatorNode
        onlyWhenLocked
        saveSender(msg.sender)
        returns (uint256[] memory pathAmountsOut, address[] memory tokensOut, uint256[] memory amountsOut)
    {
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
        onlyValidatorNode
        onlyWhenLocked
        saveSender(msg.sender)
        returns (uint256[] memory pathAmountsIn, address[] memory tokensIn, uint256[] memory amountsIn)
    {
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
        // If the system is locked and signature is not valid, or node is not registered, the hook will revert.
        _unlockAngstromWithSignature(params.userData);

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
            _unlockAngstromWithSignature(userData);
        }

        // If the signature is wrong, the hook will revert in the _unlockAngstromWithSignature` function.
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
            _unlockAngstromWithSignature(userData);
        }

        // If the signature is wrong, the hook will revert in the _unlockAngstromWithSignature` function.
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
    function unlockWithEmptyAttestation(address node, bytes calldata signature) external onlyWhenLocked {
        // The following function uses a signature in memory instead of calldata. Using it in calldata would be cheaper
        // (~100 gas cheaper) in terms of gas, but would require code duplication. We opted to keep it simple.
        _unlockWithEmptyAttestation(node, signature);
    }

    /***************************************************************************
                                 Node Management
    ***************************************************************************/

    /**
     * @notice Register a node that is allowed to unlock the system.
     * @param node The node to register
     */
    function addNode(address node) external authenticate {
        if (_angstromValidatorNodes[node]) {
            revert NodeAlreadyRegistered();
        }
        _angstromValidatorNodes[node] = true;
        emit NodeRegistered(node);
    }

    /**
     * @notice Unregister a node that is no longer allowed to unlock the system.
     * @param node The node to unregister
     */
    function removeNode(address node) external authenticate {
        if (_angstromValidatorNodes[node] == false) {
            revert NodeNotRegistered();
        }
        _angstromValidatorNodes[node] = false;
        emit NodeUnregistered(node);
    }

    /***************************************************************************
                                     Getters
    ***************************************************************************/
    /**
     * @notice Get the block number the last time this contract was locked.
     * @dev If it is equal to the current block number, the contract is unlocked.
     * @return lastUnlockBlockNumber The block number when the contract was last locked
     */
    function getLastUnlockBlockNumber() external view returns (uint256) {
        return _lastUnlockBlockNumber;
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

    /// @inheritdoc EIP712
    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("Angstrom", "v1");
    }

    function _isAngstromUnlocked() internal view returns (bool) {
        return _lastUnlockBlockNumber == block.number;
    }

    /// @dev This function fails if the signature is invalid or the node is not registered.
    function _unlockAngstromWithSignature(bytes memory userData) internal {
        // Queries are always allowed.
        if (_isAngstromUnlocked() == false && EVMCallModeHelpers.isStaticCall() == false) {
            if (userData.length < 20) {
                revert InvalidSignature();
            } else {
                (address node, bytes memory signature) = _splitUserData(userData);
                // The signature looks well-formed. Revert if it doesn't correspond to a registered node.
                _unlockWithEmptyAttestation(node, signature);
            }
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
    ) internal pure returns (address extractedAddress, bytes memory hashedMessage) {
        uint256 signatureLength = userData.length - 20;
        // Initializes the hashed message to the correct length.
        hashedMessage = new bytes(signatureLength);

        // Extract first 20 bytes as address and the rest as the hashed message.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // `add(userData, 32)` is a pointer to the start of the data (the first 32 bytes are the length).
            // `shr(96, mload(...))` right-shifts 12 bytes (96 bits) to fit into 20 bytes.
            extractedAddress := shr(96, mload(add(userData, 32)))
            // The remaining bytes are the hashed message. 52 is 32 + 20 (length + address length).
            mcopy(add(hashedMessage, 32), add(userData, 52), signatureLength)
        }
    }

    // Signature passed in memory (from userData).
    function _unlockWithEmptyAttestation(address node, bytes memory signature) internal {
        bytes32 digest = _ensureRegisteredNodeAndReturnDigest(node);

        if (SignatureCheckerLib.isValidSignatureNow(node, digest, signature) == false) {
            revert InvalidSignature();
        }

        _unlockAngstrom();
    }

    function _ensureRegisteredNodeAndReturnDigest(address account) internal view returns (bytes32) {
        _ensureRegisteredNode(account);

        return _getDigest();
    }

    function _ensureRegisteredNode(address account) internal view {
        if (isRegisteredNode(account) == false) {
            revert NotNode();
        }
    }

    function _ensureAngstromLocked() internal view {
        // Only one manual unlock or direct swap is permitted per block.
        if (_isAngstromUnlocked()) {
            revert OnlyOncePerBlock();
        }
    }

    function _unlockAngstrom() internal {
        _lastUnlockBlockNumber = block.number;
    }
}
