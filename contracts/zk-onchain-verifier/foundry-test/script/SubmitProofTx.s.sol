// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../test/JoltE2ETest.t.sol";

/// @notice Submits a real Jolt proof as an on-chain transaction.
/// verify() is view, so we use a low-level call to force a tx.
contract SubmitProofTx is Script, JoltE2ETest {
    function run() external {
        address verifierAddr = vm.envAddress("VERIFIER");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();

        // Encode the calldata
        bytes memory callData = abi.encodeCall(JoltVerifier.verify, (proof));

        vm.startBroadcast(deployerKey);
        // Low-level call forces an actual transaction even for view functions
        (bool success, bytes memory ret) = verifierAddr.call(callData);
        vm.stopBroadcast();

        require(success, string(abi.encodePacked("Verify failed: ", ret)));
        console.log("Proof verified on-chain! Verifier:", verifierAddr);
    }
}
