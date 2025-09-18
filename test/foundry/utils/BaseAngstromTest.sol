// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";

import { AngstromBalancerMock } from "../../../contracts/test/AngstromBalancerMock.sol";
import { AngstromBalancer } from "../../../contracts/AngstromBalancer.sol";

contract BaseAngstromTest is BaseVaultTest {
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
        vm.startPrank(admin);
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
        vm.stopPrank();

        return address(angstromBalancer);
    }

    function registerAngstromNode(address account) internal {
        vm.expectEmit();
        emit AngstromBalancer.NodeRegistered(account);

        vm.prank(admin);
        angstromBalancer.registerNode(account);
        assertTrue(angstromBalancer.isRegisteredNode(account), "Node registration failed");
    }

    function deregisterAngstromNode(address account) internal {
        vm.expectEmit();
        emit AngstromBalancer.NodeDeregistered(account);

        vm.prank(admin);
        angstromBalancer.deregisterNode(account);
        assertFalse(angstromBalancer.isRegisteredNode(account), "Node registration failed");
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
}
