// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../test/JoltE2ETest.t.sol";

/// @notice Submits a real Jolt proof to a deployed JoltVerifier on Sepolia.
///
/// Usage:
///   PRIVATE_KEY=0x... VERIFIER=0x... forge script script/SubmitProof.s.sol:SubmitProof \
///     --rpc-url $SEPOLIA_RPC --broadcast -vvvv
contract SubmitProof is Script, JoltE2ETest {
    function run() external {
        address verifierAddr = vm.envAddress("VERIFIER");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();

        vm.startBroadcast(deployerKey);
        JoltVerifier(verifierAddr).verify(proof);
        vm.stopBroadcast();

        console.log("Proof verified successfully on-chain!");
    }
}
