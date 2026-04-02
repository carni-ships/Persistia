// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./JoltE2ETest.t.sol";

/// @title Jolt Differential Tests
/// @notice Compares Solidity verifier intermediate state against Rust-exported reference values.
/// Tests run with both muldiv (1K trace, 7-round Dory) and sha3 (8K trace, 9-round Dory) proofs
/// to verify correctness across different programs and trace sizes.
contract JoltDifferentialTest is JoltE2ETest {
    using JoltTranscript for JoltTranscript.Transcript;
    uint256 constant R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    string constant SHA3_PROOF_PATH = "testdata/jolt_onchain_proof_sha3.json";

    // ================================================================
    //  Transcript state comparison at every stage boundary
    // ================================================================

    function test_differential_transcriptStates_muldiv() public view {
        _verifyAllTranscriptStates(PROOF_PATH);
    }

    function test_differential_transcriptStates_sha3() public view {
        _verifyAllTranscriptStates(SHA3_PROOF_PATH);
    }

    function _verifyAllTranscriptStates(string memory proofPath) internal view {
        string memory json = vm.readFile(proofPath);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[0]")),
            "After preamble+commitments");

        // Stage 1
        {
            t.challengeVector(vm.parseJsonUint(json, ".num_rows_bits"));
            t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), vm.parseJsonUintArray(json, ".uniskip_polys[0]"));
            t.challengeScalar();
            uint256[] memory uniFlush = vm.parseJsonUintArray(json, ".flush_history[0]");
            for (uint256 i = 0; i < uniFlush.length; i++)
                t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniFlush[i]);
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[0]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[0]"),
                vm.parseJsonUintArray(json, ".flush_history[1]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[1]")), "After stage 1");

        // Stage 2
        {
            t.challengeScalar();
            t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), vm.parseJsonUintArray(json, ".uniskip_polys[1]"));
            t.challengeScalar();
            uint256[] memory uniFlush2 = vm.parseJsonUintArray(json, ".flush_history[2]");
            for (uint256 i = 0; i < uniFlush2.length; i++)
                t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniFlush2[i]);
            t.challengeScalar(); // ramRwGamma
            t.challengeScalar(); // instrGamma
            uint256 ramKLog2 = _log2(uint64(vm.parseJsonUint(json, ".ram_k")));
            t.challengeVector(ramKLog2);
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[1]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[1]"),
                vm.parseJsonUintArray(json, ".flush_history[3]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[2]")), "After stage 2");

        // Stage 3
        {
            t.challengeScalarPowers(5);
            t.challengeScalar(); // instrGamma
            t.challengeScalar(); // regGamma
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[2]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[2]"),
                vm.parseJsonUintArray(json, ".flush_history[4]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[3]")), "After stage 3");

        // Stage 4
        {
            t.challengeScalar(); // regGamma
            t.appendLabeledBytes(bytes24(bytes19("ram_val_check_gamma")), 0, "");
            t.challengeScalar(); // ramValCheckGamma
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[3]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[3]"),
                vm.parseJsonUintArray(json, ".flush_history[5]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[4]")), "After stage 4");

        // Stage 5
        {
            t.challengeScalar(); // instrRafGamma
            t.challengeScalar(); // ramRaGamma
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[4]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[4]"),
                vm.parseJsonUintArray(json, ".flush_history[6]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[5]")), "After stage 5");

        // Stage 6
        {
            t.challengeScalar(); t.challengeScalar(); t.challengeScalar();
            t.challengeScalar(); t.challengeScalar(); t.challengeScalar();
            t.challengeScalar(); t.challengeScalar(); t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[5]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[5]"),
                vm.parseJsonUintArray(json, ".flush_history[7]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[6]")), "After stage 6");

        // Stage 7
        {
            t.challengeScalar(); // hwGamma
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[6]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[6]"),
                vm.parseJsonUintArray(json, ".flush_history[8]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[7]")), "After stage 7");

        // Stage 8: joint_claim
        {
            uint256[] memory claims = vm.parseJsonUintArray(json, ".stage8_committed_claims");
            t.appendLabeledScalars(bytes24(bytes10("rlc_claims")), claims);
            uint256[] memory gammaPowers = t.challengeScalarPowers(claims.length);
            uint256 jointClaim = 0;
            for (uint256 i = 0; i < claims.length; i++) {
                jointClaim = addmod(jointClaim, mulmod(gammaPowers[i], claims[i], R_), R_);
            }
            assertEq(jointClaim, vm.parseJsonUint(json, ".stage8_joint_claim"), "Joint claim");
        }
    }

    // ================================================================
    //  Full verification: sha3 proof (different program, 8K trace, 9-round Dory)
    // ================================================================

    function test_differential_fullVerify_sha3() public {
        JoltTypes.JoltOnChainProof memory proof = _buildProofFromPath(SHA3_PROOF_PATH);
        verifier.verify(proof);
    }

    function test_differential_fullVerify_muldiv() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
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
