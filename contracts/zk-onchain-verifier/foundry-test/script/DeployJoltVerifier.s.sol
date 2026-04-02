// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "contracts/JoltVerifier.sol";
import "contracts/JoltVerifierPhase1.sol";
import "contracts/DoryOnChainVerifier.sol";
import "../src/DoryVerifier7.sol";

/// @notice Mock Groth16 verifier that always passes.
/// Used until InputHash alignment between Solidity MiMC and gnark circuit is resolved.
contract MockGroth16Verifier is IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[1] calldata
    ) external pure override {}
}

contract DeployJoltVerifier is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        bool useMock = vm.envOr("MOCK_GROTH16", true);

        vm.startBroadcast(deployerKey);

        address groth16Addr;
        if (useMock) {
            MockGroth16Verifier mock = new MockGroth16Verifier();
            groth16Addr = address(mock);
            console.log("MockGroth16Verifier:", groth16Addr);
        } else {
            DoryGroth16Verifier7 groth16 = new DoryGroth16Verifier7();
            groth16Addr = address(groth16);
            console.log("DoryGroth16Verifier7:", groth16Addr);
        }

        DoryOnChainVerifier dory = new DoryOnChainVerifier(groth16Addr);
        console.log("DoryOnChainVerifier:", address(dory));

        JoltVerifierPhase1 phase1 = new JoltVerifierPhase1();
        console.log("JoltVerifierPhase1:", address(phase1));

        JoltVerifier verifier = new JoltVerifier(address(phase1), address(dory));
        console.log("JoltVerifier:", address(verifier));

        vm.stopBroadcast();

        console.log("\n=== Deployment Summary ===");
        console.log("Groth16 (mock=%s):   ", useMock ? "true" : "false", groth16Addr);
        console.log("DoryOnChainVerifier: ", address(dory));
        console.log("JoltVerifierPhase1:  ", address(phase1));
        console.log("JoltVerifier:        ", address(verifier));
    }
}
