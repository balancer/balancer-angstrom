// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { ArrayHelpers } from "@balancer-labs/v3-solidity-utils/contracts/test/ArrayHelpers.sol";
import { BaseVaultTest } from "@balancer-labs/v3-vault/test/foundry/utils/BaseVaultTest.sol";

import { AngstromBalancerMock } from "../../../contracts/test/AngstromBalancerMock.sol";
import { AngstromBalancer } from "../../../contracts/AngstromBalancer.sol";

contract BaseAngstromTest is BaseVaultTest {
    using ArrayHelpers for *;

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
        angstromBalancer = new AngstromBalancerMock(vault, weth, permit2, "AngstromBalancer Mock v1");
        authorizer.grantRole(angstromBalancer.getActionId(AngstromBalancer.toggleNodes.selector), admin);

        return address(angstromBalancer);
    }

    function makeAngstromNode(address account) internal {
        vm.prank(admin);
        angstromBalancer.toggleNodes([account].toMemoryArray());
        assertTrue(angstromBalancer.isRegisteredNode(account), "Node registration failed");
    }

    function makeAngstromNodes(address[] memory accounts) internal {
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
}
