// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import "@balancer-labs/v3-interfaces/contracts/vault/BatchRouterTypes.sol";

import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";

import { IAngstromBalancer } from "../../../contracts/interfaces/IAngstromBalancer.sol";
import { AngstromBalancerMock } from "../../../contracts/test/AngstromBalancerMock.sol";

contract BaseAngstromTest is BaseVaultTest {
    string private artifactsRootDir = "artifacts/";

    AngstromBalancerMock internal angstromBalancer;

    bytes internal aliceSignature;
    bytes internal aliceUserData;

    bytes internal bobSignature;
    bytes internal bobUserData;

    bytes internal lpSignature;
    bytes internal lpUserData;

    uint256 internal usdcIdx;
    uint256 internal daiIdx;

    function setUp() public virtual override {
        BaseVaultTest.setUp();

        (aliceSignature, aliceUserData) = generateSignatureAndUserDataEmptyAttestation(alice, aliceKey);
        (bobSignature, bobUserData) = generateSignatureAndUserDataEmptyAttestation(bob, bobKey);
        (lpSignature, lpUserData) = generateSignatureAndUserDataEmptyAttestation(lp, lpKey);
    
        (usdcIdx, daiIdx) = getSortedIndexes(address(usdc), address(dai));
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
        emit IAngstromBalancer.NodeRegistered(account);

        vm.prank(admin);
        angstromBalancer.registerNode(account);
        assertTrue(angstromBalancer.isRegisteredNode(account), "Node registration failed");
    }

    function deregisterAngstromNode(address account) internal {
        vm.expectEmit();
        emit IAngstromBalancer.NodeDeregistered(account);

        vm.prank(admin);
        angstromBalancer.deregisterNode(account);
        assertFalse(angstromBalancer.isRegisteredNode(account), "Node registration failed");
    }

    function generateSignatureAndUserDataEmptyAttestation(
        address signer,
        uint256 privateKey
    ) internal view returns (bytes memory signature, bytes memory userData) {
        bytes32 hash = angstromBalancer.getDigest();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        signature = abi.encodePacked(r, s, v);
        userData = abi.encodePacked(signer, signature);
    }

    function generateSignatureAndUserDataSwapExactIn(
        address signer,
        uint256 privateKey,
        SwapPathExactAmountIn[] memory paths
    ) internal view returns (bytes memory signature, bytes memory userData) {
        bytes32 hash = angstromBalancer.computeDigestSwapExactIn(paths);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        signature = abi.encodePacked(r, s, v);
        userData = abi.encodePacked(signer, signature);
    }

    function generateSignatureAndUserDataSwapExactOut(
        address signer,
        uint256 privateKey,
        SwapPathExactAmountOut[] memory paths
    ) internal view returns (bytes memory signature, bytes memory userData) {
        bytes32 hash = angstromBalancer.computeDigestSwapExactOut(paths);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        signature = abi.encodePacked(r, s, v);
        userData = abi.encodePacked(signer, signature);
    }

    function generateSignatureToBSwap(
        uint256 privateKey,
        IAngstromBalancer.ToBSwapData memory swap
    ) internal view returns (bytes memory signature) {
        bytes32 hash = angstromBalancer.computeDigestToB(swap);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        signature = abi.encodePacked(r, s, v);
    }

    function _computeAngstromBalancerTestPath(string memory name) private view returns (string memory) {
        return string(abi.encodePacked(artifactsRootDir, "contracts/test/", name, ".sol/", name, ".json"));
    }
}
