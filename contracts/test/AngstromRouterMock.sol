// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import { IPermit2 } from "permit2/src/interfaces/IPermit2.sol";

import { IWETH } from "@balancer-labs/v3-interfaces/contracts/solidity-utils/misc/IWETH.sol";
import { IVault } from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";

import { AngstromRouter } from "../AngstromRouter.sol";

contract AngstromRouterMock is AngstromRouter {
    constructor(
        IVault vault,
        IWETH weth,
        IPermit2 permit2,
        string memory routerVersion
    ) AngstromRouter(vault, weth, permit2, routerVersion) {
        // solhint-disable-previous-line no-empty-blocks
    }

    function manualUnlockRouter() external {
        _unlockRouter();
    }

    function getLastUnlockBlockNumber() external view returns (uint256) {
        return _lastUnlockBlockNumber;
    }

    function isNode(address account) external view returns (bool) {
        return _isNode(account);
    }
}
