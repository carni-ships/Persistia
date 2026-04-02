// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./JoltE2ETest.t.sol";

/// @title Jolt Edge Case Tests
/// @notice Tests the verifier under different proof configurations.
/// - muldiv: 512-step trace, 7-round Dory (small program)
/// - sha3: 8192-step trace, 9-round Dory (production-scale program)
///
/// Also tests structural invariants and boundary conditions.
contract JoltEdgeCaseTest is JoltE2ETest {
    using JoltTranscript for JoltTranscript.Transcript;
    uint256 constant R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    string constant SHA3_PROOF_PATH = "testdata/jolt_onchain_proof_sha3.json";

    // ================================================================
    //  Full verification on sha3 (8K trace, 9-round Dory)
    // ================================================================

    function test_edge_sha3_fullVerify() public {
        JoltTypes.JoltOnChainProof memory proof = _buildProofFromPath(SHA3_PROOF_PATH);
        verifier.verify(proof);
    }

    // ================================================================
    //  Structural invariant: proof dimensions match between programs
    // ================================================================

    function test_edge_proofStructureComparison() public view {
        string memory muldivJson = vm.readFile(PROOF_PATH);
        string memory sha3Json = vm.readFile(SHA3_PROOF_PATH);

        // Same commitment count (same polynomial structure)
        bytes[] memory muldivCm = vm.parseJsonBytesArray(muldivJson, ".commitment_bytes");
        bytes[] memory sha3Cm = vm.parseJsonBytesArray(sha3Json, ".commitment_bytes");
        assertEq(muldivCm.length, sha3Cm.length, "Commitment count should match");

        // Same flush history structure
        for (uint256 i = 0; i < 9; i++) {
            string memory flushKey = string(abi.encodePacked(".flush_history[", vm.toString(i), "]"));
            uint256[] memory mFlush = vm.parseJsonUintArray(muldivJson, flushKey);
            uint256[] memory sFlush = vm.parseJsonUintArray(sha3Json, flushKey);
            assertEq(mFlush.length, sFlush.length,
                string(abi.encodePacked("Flush length mismatch at index ", vm.toString(i))));
        }

        // Different trace lengths
        uint256 mTrace = vm.parseJsonUint(muldivJson, ".trace_length");
        uint256 sTrace = vm.parseJsonUint(sha3Json, ".trace_length");
        assertTrue(mTrace != sTrace, "Trace lengths should differ");
        assertEq(mTrace, 512, "muldiv trace");
        assertEq(sTrace, 8192, "sha3 trace");

        // Different Dory round counts
        uint256 mRounds = vm.parseJsonUint(muldivJson, ".dory_witness.num_rounds");
        uint256 sRounds = vm.parseJsonUint(sha3Json, ".dory_witness.num_rounds");
        assertEq(mRounds, 7, "muldiv dory rounds");
        assertEq(sRounds, 9, "sha3 dory rounds");
    }

    // ================================================================
    //  Gas comparison between programs
    // ================================================================

    function test_edge_sha3_gasComparison() public {
        JoltTypes.JoltOnChainProof memory sha3Proof = _buildProofFromPath(SHA3_PROOF_PATH);
        uint256 gasBefore = gasleft();
        verifier.verify(sha3Proof);
        uint256 sha3Gas = gasBefore - gasleft();
        emit log_named_uint("sha3 verify() gas", sha3Gas);

        JoltTypes.JoltOnChainProof memory muldivProof = _buildValidProof();
        gasBefore = gasleft();
        verifier.verify(muldivProof);
        uint256 muldivGas = gasBefore - gasleft();
        emit log_named_uint("muldiv verify() gas", muldivGas);

        // sha3 should cost more (larger trace → more sumcheck rounds)
        assertTrue(sha3Gas > muldivGas, "sha3 should cost more gas than muldiv");
    }

    // ================================================================
    //  Negative test on sha3: ensure corruption is caught on different trace size
    // ================================================================

    function test_edge_sha3_reject_corruptedStage1() public {
        JoltTypes.JoltOnChainProof memory proof = _buildProofFromPath(SHA3_PROOF_PATH);
        proof.stage1Proof.uniSkipCoeffs[0] = addmod(proof.stage1Proof.uniSkipCoeffs[0], 1, R_);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_edge_sha3_reject_corruptedStage5() public {
        JoltTypes.JoltOnChainProof memory proof = _buildProofFromPath(SHA3_PROOF_PATH);
        proof.stage5Proof.flushedClaims[0] = addmod(proof.stage5Proof.flushedClaims[0], 1, R_);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_edge_sha3_reject_wrongPreamble() public {
        JoltTypes.JoltOnChainProof memory proof = _buildProofFromPath(SHA3_PROOF_PATH);
        proof.preamble.traceLength = 512; // wrong trace length
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Helpers
    // ================================================================

    function _buildProofFromPath(string memory proofPath)
        internal view returns (JoltTypes.JoltOnChainProof memory proof)
    {
        string memory json = vm.readFile(proofPath);
        string memory groth16Path = keccak256(bytes(proofPath)) == keccak256(bytes(SHA3_PROOF_PATH))
            ? "testdata/jolt_groth16_proof_sha3.json"
            : "testdata/jolt_groth16_proof.json";
        string memory groth16Json = vm.readFile(groth16Path);

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
