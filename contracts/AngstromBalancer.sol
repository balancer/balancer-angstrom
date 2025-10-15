// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";
import { IPermit2 } from "permit2/src/interfaces/IPermit2.sol";
import { EIP712 } from "solady/src/utils/EIP712.sol";

import { IWETH } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/misc/IWETH.sol";
import { IHooks } from "@balancer-labs/v3-interfaces/contracts/vault/IHooks.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import "@balancer-labs/v3-interfaces/contracts/vault/BatchRouterTypes.sol";
import "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";

import { EVMCallModeHelpers } from "@balancer-labs/v3-solidity-utils/contracts/helpers/EVMCallModeHelpers.sol";
import { OwnableAuthentication } from "@balancer-labs/v3-standalone-utils/contracts/OwnableAuthentication.sol";
import { BatchRouterHooks } from "@balancer-labs/v3-vault/contracts/BatchRouterHooks.sol";
import {
    TransientEnumerableSet
} from "@balancer-labs/v3-solidity-utils/contracts/openzeppelin/TransientEnumerableSet.sol";
import {
    TransientStorageHelpers
} from "@balancer-labs/v3-solidity-utils/contracts/helpers/TransientStorageHelpers.sol";
import { BaseHooks } from "@balancer-labs/v3-vault/contracts/BaseHooks.sol";

import { IAngstromBalancer } from "./interfaces/IAngstromBalancer.sol";

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
contract AngstromBalancer is IAngstromBalancer, BatchRouterHooks, OwnableAuthentication, BaseHooks, EIP712 {
    using TransientEnumerableSet for TransientEnumerableSet.AddressSet;
    using TransientStorageHelpers for *;

    /// @dev `keccak256("AttestAngstromBlockEmpty(uint64 block_number)")`.
    uint256 internal constant _ATTEST_EMPTY_BLOCK_TYPE_HASH =
        0x3f25e551746414ff93f076a7dd83828ff53735b39366c74015637e004fcb0223;

    /// @dev `keccak256("SwapExactIn(SwapPathExactAmountIn[] paths, uint64 block_number)")`.
    uint256 internal constant _SWAP_EXACT_IN_TYPE_HASH =
        0xc3810e534961c3152a90c6e5342d0ef3cdd6517c38c42e01b7640beffc3e41c2;

    /// @dev `keccak256("SwapExactOut(SwapPathExactAmountOut[] paths, uint64 block_number)")`.
    uint256 internal constant _SWAP_EXACT_OUT_TYPE_HASH =
        0xb26cc9223a5f7a414a15401ce11a9ef78c5c9daf4bc40c11e20d3f53cb9d79a5;

    /**
     * @dev `keccak256("ToBSwap(address tokenIn,address tokenOut,uint256 exactAmountIn,uint256 exactAmountOut,address
     * payer,uint64 block_number)")`.
     */
    uint256 internal constant _TOB_SWAP_TYPE_HASH = 0x33ea2c5351079a10fb30dea7d5e13a7b1a184012f4f990b1ce23e7a65822518f;

    uint256 internal constant _MINIMUM_USER_DATA_LENGTH = 20;

    /// @dev Set of active Angstrom validator nodes, authorized to unlock this contract for operations.
    mapping(address node => bool isActive) internal _angstromValidatorNodes;

    /// @dev The currently "unlocked" block. The contract is locked if the current block does not equal this number.
    uint256 internal _lastUnlockBlockNumber;

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

    /// @inheritdoc IAngstromBalancer
    function swapExactInAngstrom(
        SwapPathExactAmountIn[] memory pathsToB,
        ToBSwapData[] memory tobSwaps,
        uint256 deadline,
        bool wethIsEth,
        bytes calldata userData
    ) external payable onlyValidatorNode onlyWhenLocked saveSender(msg.sender) {
        _unlockAngstrom();

        _vault.unlock(
            abi.encodeCall(
                AngstromBalancer.swapExactInAngstromHook,
                (
                    SwapExactInHookParams({
                        sender: msg.sender,
                        paths: pathsToB,
                        deadline: deadline,
                        wethIsEth: wethIsEth,
                        userData: userData
                    }),
                    tobSwaps
                )
            )
        );
    }

    function swapExactInAngstromHook(
        SwapExactInHookParams calldata params,
        ToBSwapData[] calldata tobSwaps
    )
        external
        nonReentrant
        onlyVault
        returns (uint256[] memory pathAmountsOut, address[] memory tokensOut, uint256[] memory amountsOut)
    {
        for (uint256 i = 0; i < tobSwaps.length; i++) {
            bytes32 digest = _computeDigestToB(tobSwaps[i]);

            if (SignatureCheckerLib.isValidSignatureNow(tobSwaps[i].payer, digest, tobSwaps[i].signature) == false) {
                revert InvalidSignature();
            }
        }

        (pathAmountsOut, tokensOut, amountsOut) = _swapExactInHook(params);

        _settleToBPath(tobSwaps, params.wethIsEth);
    }

    /// @inheritdoc IAngstromBalancer
    function swapExactOutAngstrom(
        SwapPathExactAmountOut[] memory pathsToB,
        ToBSwapData[] memory tobSwaps,
        uint256 deadline,
        bool wethIsEth,
        bytes calldata userData
    ) external payable onlyValidatorNode onlyWhenLocked saveSender(msg.sender) {
        _unlockAngstrom();

        _vault.unlock(
            abi.encodeCall(
                AngstromBalancer.swapExactOutAngstromHook,
                (
                    SwapExactOutHookParams({
                        sender: msg.sender,
                        paths: pathsToB,
                        deadline: deadline,
                        wethIsEth: wethIsEth,
                        userData: userData
                    }),
                    tobSwaps
                )
            )
        );
    }

    function swapExactOutAngstromHook(
        SwapExactOutHookParams calldata params,
        ToBSwapData[] calldata tobSwaps
    )
        external
        nonReentrant
        onlyVault
        returns (uint256[] memory pathAmountsIn, address[] memory tokensIn, uint256[] memory amountsIn)
    {
        for (uint256 i = 0; i < tobSwaps.length; i++) {
            bytes32 digest = _computeDigestToB(tobSwaps[i]);

            if (SignatureCheckerLib.isValidSignatureNow(tobSwaps[i].payer, digest, tobSwaps[i].signature) == false) {
                revert InvalidSignature();
            }
        }

        (pathAmountsIn, tokensIn, amountsIn) = _swapExactOutHook(params);

        _settleToBPath(tobSwaps, params.wethIsEth);
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
    function registerNode(address node) external authenticate {
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
    function deregisterNode(address node) external authenticate {
        if (_angstromValidatorNodes[node] == false) {
            revert NodeNotRegistered();
        }
        _angstromValidatorNodes[node] = false;
        emit NodeDeregistered(node);
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
            if (userData.length < _MINIMUM_USER_DATA_LENGTH) {
                revert InvalidSignature();
            } else {
                (address node, bytes memory signature) = _splitUserDataMemory(userData);
                // The signature looks well-formed. Revert if it doesn't correspond to a registered node.
                _unlockWithEmptyAttestation(node, signature);
            }
        }
    }

    function _computeDigestSwapExactIn(SwapPathExactAmountIn[] memory paths) internal view returns (bytes32) {
        // First, hash the paths array according to EIP-712.
        bytes32 pathsHash = _hashSwapExactInPathArray(paths);
        bytes32 structHash = _computeStructHashWithBlockNumber(_SWAP_EXACT_IN_TYPE_HASH, pathsHash);

        return _hashTypedData(structHash);
    }

    // Helper function to hash the SwapPathExactAmountIn array.
    function _hashSwapExactInPathArray(SwapPathExactAmountIn[] memory paths) internal pure returns (bytes32) {
        bytes32[] memory pathHashes = new bytes32[](paths.length);

        for (uint256 i = 0; i < paths.length; i++) {
            pathHashes[i] = _hashSwapExactInPath(paths[i]);
        }

        return keccak256(abi.encodePacked(pathHashes));
    }

    // Helper function to hash a single SwapPathExactAmountIn
    function _hashSwapExactInPath(SwapPathExactAmountIn memory path) internal pure returns (bytes32) {
        // We need to define a type hash for SwapPathExactAmountIn.
        // For now, using a simple encoding (adjust based on the EIP-712 schema).
        bytes32[] memory stepHashes = new bytes32[](path.steps.length);

        for (uint256 i = 0; i < path.steps.length; i++) {
            stepHashes[i] = keccak256(abi.encode(path.steps[i].pool, path.steps[i].tokenOut, path.steps[i].isBuffer));
        }

        bytes32 stepsHash = keccak256(abi.encodePacked(stepHashes));

        return keccak256(abi.encode(path.tokenIn, stepsHash, path.exactAmountIn, path.minAmountOut));
    }

    function _computeDigestSwapExactOut(SwapPathExactAmountOut[] memory paths) internal view returns (bytes32) {
        // First, hash the paths array according to EIP-712.
        bytes32 pathsHash = _hashSwapExactOutPathArray(paths);
        bytes32 structHash = _computeStructHashWithBlockNumber(_SWAP_EXACT_OUT_TYPE_HASH, pathsHash);

        return _hashTypedData(structHash);
    }

    function _computeStructHashWithBlockNumber(uint256 typeHash, bytes32 contentHash) internal view returns (bytes32) {
        bytes32 structHash;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, typeHash)
            mstore(add(ptr, 0x20), contentHash)
            mstore(add(ptr, 0x40), number())
            structHash := keccak256(ptr, 0x60)
        }

        return structHash;
    }

    // Helper function to hash the SwapPathExactAmountOut array.
    function _hashSwapExactOutPathArray(SwapPathExactAmountOut[] memory paths) internal pure returns (bytes32) {
        bytes32[] memory pathHashes = new bytes32[](paths.length);

        for (uint256 i = 0; i < paths.length; i++) {
            pathHashes[i] = _hashSwapExactOutPath(paths[i]);
        }

        return keccak256(abi.encodePacked(pathHashes));
    }

    // Helper function to hash a single SwapPathExactAmountOut.
    function _hashSwapExactOutPath(SwapPathExactAmountOut memory path) internal pure returns (bytes32) {
        // We need to define a type hash for SwapPathExactAmountOut.
        // For now, using a simple encoding (adjust based on the EIP-712 schema).
        bytes32[] memory stepHashes = new bytes32[](path.steps.length);

        for (uint256 i = 0; i < path.steps.length; i++) {
            stepHashes[i] = keccak256(abi.encode(path.steps[i].pool, path.steps[i].tokenOut, path.steps[i].isBuffer));
        }

        bytes32 stepsHash = keccak256(abi.encodePacked(stepHashes));

        return keccak256(abi.encode(path.tokenIn, stepsHash, path.maxAmountIn, path.exactAmountOut));
    }

    function _computeDigestEmptyAttestation() internal view returns (bytes32) {
        bytes32 structHash = _computeStructHashWithBlockNumber(
            _ATTEST_EMPTY_BLOCK_TYPE_HASH,
            bytes32(0) // no content for empty attestation
        );
        return _hashTypedData(structHash);
    }

    function _computeDigestToB(ToBSwapData memory swapData) internal view returns (bytes32) {
        bytes32 structHash;

        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, _TOB_SWAP_TYPE_HASH)
            mstore(add(ptr, 0x20), mload(swapData)) // tokenIn
            mstore(add(ptr, 0x40), mload(add(swapData, 0x20))) // tokenOut
            mstore(add(ptr, 0x60), mload(add(swapData, 0x40))) // exactAmountIn
            mstore(add(ptr, 0x80), mload(add(swapData, 0x60))) // exactAmountOut
            mstore(add(ptr, 0xa0), mload(add(swapData, 0x80))) // payer
            mstore(add(ptr, 0xc0), number()) // block_number
            structHash := keccak256(ptr, 0xe0)
        }

        return _hashTypedData(structHash);
    }

    // The first 20 bytes of the user data is the node address; the rest is the signature.
    // This function separates the two so that the node signature can be verified.
    function _splitUserDataMemory(
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

    function _splitUserData(
        bytes calldata userData
    ) internal pure returns (address extractedAddress, bytes calldata signature) {
        extractedAddress = address(bytes20(userData[0:20]));
        signature = userData[20:];
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

        return _computeDigestEmptyAttestation();
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

    function _extractPayerWithValidSignature(
        bytes32 digest,
        bytes calldata userData
    ) internal view returns (address payer) {
        bytes memory signature;
        (payer, signature) = _splitUserData(userData);

        if (SignatureCheckerLib.isValidSignatureNow(payer, digest, signature) == false) {
            revert InvalidSignature();
        }
    }

    function _unlockAngstrom() internal {
        _lastUnlockBlockNumber = block.number;
    }

    function _settleToBPath(ToBSwapData[] calldata tobSwaps, bool wethIsEth) internal {
        for (uint256 i = 0; i < tobSwaps.length; ++i) {
            ToBSwapData calldata swap = tobSwaps[i];

            // Take tokens from the payer or settle if prepaid
            _takeOrSettle(swap.payer, wethIsEth, swap.tokenIn, swap.exactAmountIn);

            // These parameters are not used for tobSwaps and should be erased in case other swaps happen
            // in the same transaction using this router.
            _currentSwapTokenInAmounts().tSet(swap.tokenIn, 0);
            _currentSwapTokensIn().remove(swap.tokenIn);

            // Send tokens to the payer
            _sendTokenOut(swap.payer, IERC20(swap.tokenOut), swap.exactAmountOut, wethIsEth);

            // These parameters are not used for tobSwaps and should be erased in case other swaps happen
            // in the same transaction using this router.
            _currentSwapTokenOutAmounts().tSet(swap.tokenOut, 0);
            _currentSwapTokensOut().remove(swap.tokenOut);
        }

        // TODO: Should _returnEth be implemented here?
    }
}
