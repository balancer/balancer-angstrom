// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import { IPermit2 } from "permit2/src/interfaces/IPermit2.sol";

import { IWETH } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/misc/IWETH.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";

import { AngstromRouterAndHook } from "../AngstromRouterAndHook.sol";

contract AngstromRouterAndHookMock is AngstromRouterAndHook {
    constructor(
        IVault vault,
        IWETH weth,
        IPermit2 permit2,
        string memory routerVersion
    ) AngstromRouterAndHook(vault, weth, permit2, routerVersion) {
        // solhint-disable-previous-line no-empty-blocks
    }

    function manualUnlockAngstromWithRouter() external {
        _unlockAngstromWithRouter();
    }

    function getLastUnlockBlockNumber() external view returns (uint256) {
        return _lastUnlockBlockNumber;
    }

    function isNode(address account) external view returns (bool) {
        return _isNode(account);
    }

    function getDigest() external view returns (bytes32) {
        return _getDigest();
    }
}
