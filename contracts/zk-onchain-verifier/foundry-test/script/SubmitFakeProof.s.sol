// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../test/JoltE2ETest.t.sol";

/// @notice Submits a corrupted SHA3 proof on-chain — expects rejection.
/// Corrupts a sumcheck polynomial coefficient in stage 1, which poisons
/// the Fiat-Shamir transcript and causes an output claim mismatch.
contract SubmitFakeProof is Script, JoltE2ETest {
    function run() external {
        address verifierAddr = vm.envAddress("VERIFIER");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        string memory json = vm.readFile("testdata/jolt_onchain_proof_sha3.json");
        string memory groth16Json = vm.readFile("testdata/jolt_groth16_proof_sha3.json");

        JoltTypes.JoltOnChainProof memory proof = _buildFromJson(json, groth16Json);

        // Corrupt: flip a byte in the first commitment (poisons transcript from the start)
        proof.commitmentBlob[0] = bytes1(uint8(proof.commitmentBlob[0]) ^ 0xff);
        console.log("Corrupted first commitment byte - proof should be rejected");

        bytes memory callData = abi.encodeCall(JoltVerifier.verify, (proof));
        console.log("Calldata size:", callData.length, "bytes");

        vm.startBroadcast(deployerKey);
        (bool success, bytes memory ret) = verifierAddr.call(callData);
        vm.stopBroadcast();

        if (!success) {
            console.log("REJECTED as expected! Verifier correctly refused the fake proof.");
        } else {
            revert("BUG: fake proof was accepted!");
        }
    }

    function _buildFromJson(string memory json, string memory groth16Json)
        internal view returns (JoltTypes.JoltOnChainProof memory proof)
    {
        uint256 nCycleVars = _log2(uint64(vm.parseJsonUint(json, ".trace_length")));

        proof.preamble.maxInputSize = uint64(vm.parseJsonUint(json, ".max_input_size"));
        proof.preamble.maxOutputSize = uint64(vm.parseJsonUint(json, ".max_output_size"));
        proof.preamble.heapSize = uint64(vm.parseJsonUint(json, ".heap_size"));
        proof.preamble.inputs = vm.parseJsonBytes(json, ".inputs");
        proof.preamble.outputs = vm.parseJsonBytes(json, ".outputs");
        proof.preamble.panic = uint64(vm.parseJsonUint(json, ".panic"));
        proof.preamble.ramK = uint64(vm.parseJsonUint(json, ".ram_k"));
        proof.preamble.traceLength = uint64(vm.parseJsonUint(json, ".trace_length"));
        proof.preamble.entryAddress = uint64(vm.parseJsonUint(json, ".entry_address"));

        (proof.commitmentBlob, proof.commitmentSize) = _packCommitments(json);

        _fillE2EStage1(proof, json, nCycleVars);
        _fillE2EStage2(proof, json, nCycleVars);
        _fillE2EStage3(proof, json, nCycleVars);
        _fillE2EStage4(proof, json, nCycleVars);
        _fillE2EStage5(proof, json, nCycleVars);
        _fillE2EStage6(proof, json, nCycleVars);
        _fillE2EStage7(proof, json);

        _fillStage8(proof, json, groth16Json);
        _loadDoryCommitment(proof, json);
    }
}
