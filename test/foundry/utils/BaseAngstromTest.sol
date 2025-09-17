// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { ArrayHelpers } from "@balancer-labs/v3-solidity-utils/contracts/test/ArrayHelpers.sol";
import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";

import { AngstromBalancerMock } from "../../../contracts/test/AngstromBalancerMock.sol";
import { AngstromBalancer } from "../../../contracts/AngstromBalancer.sol";

contract BaseAngstromTest is BaseVaultTest {
    using ArrayHelpers for *;

    string private artifactsRootDir = "artifacts/";

    AngstromBalancerMock internal angstromBalancer;

    bytes internal aliceSignature;
    bytes internal aliceUserData;

    bytes internal bobSignature;
    bytes internal bobUserData;

    bytes internal lpSignature;
    bytes internal lpUserData;

    function setUp() public virtual override {
        BaseVaultTest.setUp();

        (aliceSignature, aliceUserData) = generateSignatureAndUserData(alice, aliceKey);
        (bobSignature, bobUserData) = generateSignatureAndUserData(bob, bobKey);
        (lpSignature, lpUserData) = generateSignatureAndUserData(lp, lpKey);
    }

    function createHook() internal override returns (address) {
        if (reusingArtifacts) {
            angstromBalancer = AngstromBalancerMock(
                payable(
                    deployCode(
                        _computeAngstromBalancerTestPath(type(AngstromBalancerMock).name),
                        abi.encode(vault, weth, permit2, "AngstromBalancer Mock v1")
                    )
                )
            );
        } else {
            angstromBalancer = new AngstromBalancerMock(vault, weth, permit2, "AngstromBalancer Mock v1");
        }
        authorizer.grantRole(angstromBalancer.getActionId(AngstromBalancer.toggleNodes.selector), admin);

        return address(angstromBalancer);
    }

    function makeAngstromNode(address account) internal {
        _ensureEventTogglingNode(account);

        vm.prank(admin);
        angstromBalancer.toggleNodes([account].toMemoryArray());
        assertTrue(angstromBalancer.isRegisteredNode(account), "Node registration failed");
    }

    function makeAngstromNodes(address[] memory accounts) internal {
        for (uint256 i = 0; i < accounts.length; i++) {
            address account = accounts[i];
            _ensureEventTogglingNode(account);
        }

        vm.prank(admin);
        angstromBalancer.toggleNodes(accounts);
    }

    function generateSignatureAndUserData(
        address signer,
        uint256 privateKey
    ) internal view returns (bytes memory signature, bytes memory userData) {
        bytes32 hash = angstromBalancer.getDigest();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        signature = abi.encodePacked(r, s, v);
        userData = abi.encodePacked(signer, signature);
    }

    function _computeAngstromBalancerTestPath(string memory name) private view returns (string memory) {
        return string(abi.encodePacked(artifactsRootDir, "contracts/test/", name, ".sol/", name, ".json"));
    }

    function _ensureEventTogglingNode(address account) internal {
        bool isNode = angstromBalancer.isRegisteredNode(account);
        vm.expectEmit();
        if (isNode) {
            emit AngstromBalancer.NodeUnregistered(account);
        } else {
            emit AngstromBalancer.NodeRegistered(account);
        }
    }
}
