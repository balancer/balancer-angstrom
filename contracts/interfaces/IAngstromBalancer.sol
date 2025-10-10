// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

/**
 * @notice Interface for the Angstrom Router and Hook.
 * @dev This interface defines the public API for the AngstromBalancer contract.
 */
interface IAngstromBalancer {
    /***************************************************************************
                                       Errors
    ***************************************************************************/

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

    /***************************************************************************
                                       Events
    ***************************************************************************/

    /// @notice A node was registered and is allowed to unlock Angstrom pools.
    event NodeRegistered(address indexed node);

    /// @notice A node was deregistered and is no longer able to unlock Angstrom pools.
    event NodeDeregistered(address indexed node);

    /***************************************************************************
                                   Public Functions
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
    function unlockWithEmptyAttestation(address node, bytes calldata signature) external;

    /**
     * @notice Register a node that is allowed to unlock the system.
     * @param node The node to register
     */
    function registerNode(address node) external;

    /**
     * @notice Unregister a node that is no longer allowed to unlock the system.
     * @param node The node to unregister
     */
    function deregisterNode(address node) external;

    /**
     * @notice Get the block number the last time this contract was locked.
     * @dev If it is equal to the current block number, the contract is unlocked.
     * @return lastUnlockBlockNumber The block number when the contract was last locked
     */
    function getLastUnlockBlockNumber() external view returns (uint256);

    /**
     * @notice Check whether a given account is a registered Angstrom node.
     * @param account The address being checked for node status
     * @return isNode True if the address is a registered Angstrom node
     */
    function isRegisteredNode(address account) external view returns (bool);
}

