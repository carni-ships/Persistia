// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "contracts/JoltVerifier.sol";
import "contracts/JoltVerifierPhase1.sol";
import "contracts/JoltTypes.sol";
import "contracts/JoltTranscript.sol";
import "contracts/StageVerification.sol";
import "contracts/DoryOnChainVerifier.sol";
import "../src/DoryVerifier7.sol";

/// @notice Mock Groth16 verifier that always passes (for unit testing Stage 8 flow).
contract MockGroth16Verifier is IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[1] calldata
    ) external pure override {
        // Always passes — real e2e test will use actual Groth16 verifier
    }
}

/// @title Jolt End-to-End Test
/// @notice Tests the full JoltVerifier pipeline (stages 1-8) using real proof data.
///
/// To regenerate test data:
///   cargo nextest run -p jolt-core export_onchain_proof_json --features host
contract JoltE2ETest is Test {
    using JoltTranscript for JoltTranscript.Transcript;

    JoltVerifier verifier;
    JoltVerifierPhase1 phase1;
    DoryOnChainVerifier doryVerifier;
    MockGroth16Verifier mockGroth16;

    string constant PROOF_PATH = "testdata/jolt_onchain_proof.json";

    function setUp() public virtual {
        mockGroth16 = new MockGroth16Verifier();
        doryVerifier = new DoryOnChainVerifier(address(mockGroth16));
        phase1 = new JoltVerifierPhase1();
        verifier = new JoltVerifier(address(phase1), address(doryVerifier));
    }

    /// @notice Verify the contract deploys and links correctly.
    function test_deployment() public view {
        assertEq(address(verifier.doryVerifier()), address(doryVerifier));
    }

    /// @notice Smoke test: verify() with minimal mock proof data.
    function test_e2e_smokeTest() public {
        JoltTypes.JoltOnChainProof memory proof;

        proof.preamble.maxInputSize = 4096;
        proof.preamble.maxOutputSize = 4096;
        proof.preamble.heapSize = 65536;
        proof.preamble.inputs = hex"090000000500000003000000";
        proof.preamble.outputs = "";
        proof.preamble.panic = 0;
        proof.preamble.ramK = 65536;
        proof.preamble.traceLength = 1024;
        proof.preamble.entryAddress = 0x80000000;

        proof.commitmentBlob = "";
        proof.commitmentSize = 0;

        proof.stage1Proof.uniSkipCoeffs = new uint256[](1);
        proof.stage1Proof.compressedPolys = new uint256[][](0);
        proof.stage1Inputs.numRowsBits = 1;
        proof.stage1Inputs.nCycleVars = 10;

        vm.expectRevert();
        verifier.verify(proof);
    }

    /// @notice Build transcript through preamble + commitments from JSON.
    function _replayPreambleAndCommitments(string memory json)
        internal
        view
        returns (JoltTranscript.Transcript memory t)
    {
        // Parse preamble values
        uint64 traceLength = uint64(vm.parseJsonUint(json, ".trace_length"));
        uint64 ramK = uint64(vm.parseJsonUint(json, ".ram_k"));
        uint64 entryAddress = uint64(vm.parseJsonUint(json, ".entry_address"));
        uint64 panic_ = uint64(vm.parseJsonUint(json, ".panic"));
        bytes memory inputs = vm.parseJsonBytes(json, ".inputs");
        bytes memory outputs = vm.parseJsonBytes(json, ".outputs");

        // Parse commitment bytes
        bytes[] memory commitmentBytes = vm.parseJsonBytesArray(json, ".commitment_bytes");

        // Initialize transcript (matches Rust: KeccakTranscript::new(b"Jolt"))
        t = JoltTranscript.newTranscript("Jolt");

        // Parse MemoryLayout fields
        uint64 maxInputSize = uint64(vm.parseJsonUint(json, ".max_input_size"));
        uint64 maxOutputSize = uint64(vm.parseJsonUint(json, ".max_output_size"));
        uint64 heapSize = uint64(vm.parseJsonUint(json, ".heap_size"));

        // Replay preamble (matches Rust: fiat_shamir_preamble)
        t.appendLabeledU64(bytes32(bytes14("max_input_size")), maxInputSize);
        t.appendLabeledU64(bytes32(bytes15("max_output_size")), maxOutputSize);
        t.appendLabeledU64(bytes32(bytes9("heap_size")), heapSize);
        t.appendLabeledBytes(
            bytes24(bytes6("inputs")),
            uint64(inputs.length),
            inputs
        );
        t.appendLabeledBytes(
            bytes24(bytes7("outputs")),
            uint64(outputs.length),
            outputs
        );
        t.appendLabeledU64(bytes32(bytes5("panic")), panic_);
        t.appendLabeledU64(bytes32(bytes5("ram_K")), ramK);
        t.appendLabeledU64(bytes32(bytes12("trace_length")), traceLength);
        t.appendLabeledU64(bytes32(bytes13("entry_address")), entryAddress);

        // Replay commitments
        for (uint256 i = 0; i < commitmentBytes.length; i++) {
            t.appendLabeledBytes(
                bytes24(bytes10("commitment")),
                uint64(commitmentBytes[i].length),
                commitmentBytes[i]
            );
        }

    }

    /// @notice Transcript consistency: replay preamble + commitments from real proof,
    /// verify Keccak Fiat-Shamir state matches Rust verifier.
    function test_transcriptConsistency_preamble() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);

        string memory expectedState = vm.parseJsonString(json, ".transcript_states[0]");
        assertEq(
            t.state,
            vm.parseBytes32(expectedState),
            "Transcript state after preamble+commitments does not match Rust"
        );
    }

    /// @notice Transcript consistency: replay Stage 1 (Spartan outer) from real proof,
    /// verify Keccak Fiat-Shamir state matches Rust verifier after stage 1.
    ///
    /// Stage 1 transcript operations:
    ///   1. challengeVector(numRowsBits=11) → 11 tau challenges
    ///   2. UniSkip: appendLabeledScalars("uniskip_poly", 28 coeffs) + challengeScalar() → r0
    ///   3. Flush 1 opening claim (UniSkip eval s(r0))
    ///   4. Batched sumcheck (1 instance, 10 rounds):
    ///      a. appendLabeledScalar("sumcheck_claim", uniSkipClaim)
    ///      b. challengeVector(1) → 1 batching coeff
    ///      c. Per round: appendLabeledScalars("sumcheck_poly", 3 coeffs) + challengeScalarMont()
    ///   5. Flush 35 opening claims (R1CS input evaluations)
    function test_transcriptConsistency_stage1() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);

        uint256 numRowsBits = vm.parseJsonUint(json, ".num_rows_bits");

        // 1. Sample tau vector (11 challenges)
        t.challengeVector(numRowsBits);

        // 2. UniSkip first round: append coefficients + derive r0
        uint256[] memory uniSkipCoeffs = vm.parseJsonUintArray(json, ".uniskip_polys[0]");
        t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), uniSkipCoeffs);
        t.challengeScalar(); // r0

        // 3. Flush UniSkip opening claim
        uint256 uniSkipClaim = vm.parseJsonUint(json, ".flush_history[0][0]");
        t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniSkipClaim);

        // 4. Batched sumcheck: 1 instance, 10 rounds
        // 4a. Append input claim
        t.appendLabeledScalar(bytes32(bytes14("sumcheck_claim")), uniSkipClaim);

        // 4b. Derive batching coefficient (1 instance → 1 coeff)
        t.challengeVector(1);

        // 4c. Sumcheck rounds
        uint256[][] memory compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[0]");
        for (uint256 i = 0; i < compressedPolys.length; i++) {
            t.appendLabeledScalars(bytes24(bytes13("sumcheck_poly")), compressedPolys[i]);
            t.challengeScalarMont(); // round challenge
        }

        // 5. Flush 35 R1CS input evaluation claims
        uint256[] memory r1csClaims = vm.parseJsonUintArray(json, ".flush_history[1]");
        require(r1csClaims.length == 35, "expected 35 R1CS claims");
        for (uint256 i = 0; i < r1csClaims.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), r1csClaims[i]);
        }

        // Verify transcript state matches Rust after Stage 1
        string memory expectedState = vm.parseJsonString(json, ".transcript_states[1]");
        assertEq(
            t.state,
            vm.parseBytes32(expectedState),
            "Transcript state after Stage 1 does not match Rust"
        );
    }

    /// @notice Full algebraic verification of Stage 1 with real proof data.
    /// Calls verifyStage1 which validates:
    ///   - UniSkip domain sum == 0
    ///   - Sumcheck round consistency
    ///   - Expected output claim matches Az*Bz*tau_kernel
    ///   - Correct number of opening claims flushed
    function test_verifyStage1_algebraic() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);

        uint256[] memory uniSkipCoeffs = vm.parseJsonUintArray(json, ".uniskip_polys[0]");
        uint256[][] memory compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[0]");
        uint256[] memory r1csClaims = vm.parseJsonUintArray(json, ".flush_history[1]");
        uint256 numRowsBits = vm.parseJsonUint(json, ".num_rows_bits");
        uint64 traceLength = uint64(vm.parseJsonUint(json, ".trace_length"));
        uint256 nCycleVars = _log2(traceLength);

        // Inline Stage 1 verification (mirrors StageVerification.verifyStage1)
        _verifyStage1Inline(t, uniSkipCoeffs, compressedPolys, r1csClaims, numRowsBits, nCycleVars);

        // Verify transcript state after Stage 1
        string memory expectedState = vm.parseJsonString(json, ".transcript_states[1]");
        assertEq(
            t.state,
            vm.parseBytes32(expectedState),
            "Transcript state after verifyStage1 does not match Rust"
        );
    }

    /// @notice Inline Stage 1 verification — same logic as StageVerification.verifyStage1
    /// but accepting memory parameters for test compatibility.
    function _verifyStage1Inline(
        JoltTranscript.Transcript memory t,
        uint256[] memory uniSkipCoeffs,
        uint256[][] memory compressedPolys,
        uint256[] memory r1csInputEvals,
        uint256 numRowsBits,
        uint256 nCycleVars
    ) internal view {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

        // 1. Sample tau vector (Montgomery to match Rust challenge_vector_optimized)
        uint256[] memory tau = t.challengeVectorMont(numRowsBits);

        // 2. UniSkip first round
        t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), uniSkipCoeffs);
        uint256 r0 = t.challengeScalarMont();

        // Check domain sum (outer: 10 points)
        uint256 domainSum = 0;
        int256[10] memory domain = [int256(-4), int256(-3), int256(-2), int256(-1), int256(0), int256(1), int256(2), int256(3), int256(4), int256(5)];
        for (uint256 i = 0; i < 10; i++) {
            domainSum = addmod(domainSum, _evalPolyAtInt(uniSkipCoeffs, domain[i]), R_);
        }
        require(domainSum == 0, "uniskip domain sum != 0");

        // Evaluate s1(r0)
        uint256 uniSkipClaim = _evalPoly(uniSkipCoeffs, r0);

        // 3. Flush UniSkip claim
        t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniSkipClaim);

        // 4. Batched sumcheck (1 instance)
        uint256[] memory instanceClaims = new uint256[](1);
        instanceClaims[0] = uniSkipClaim;
        uint256[] memory instanceNumRounds = new uint256[](1);
        instanceNumRounds[0] = 1 + nCycleVars;

        (uint256 finalClaim, uint256[] memory challenges, uint256[] memory batchingCoeffs) =
            BatchedSumcheckVerifier.verify(compressedPolys, instanceClaims, instanceNumRounds, 3, t);

        // 5. Compute expected output: tau_kernel * Az * Bz
        uint256 tauHigh = tau[tau.length - 1];
        uint256 tauHighBoundR0 = _lagrangeKernel10(tauHigh, r0);

        uint256[] memory tauLow = new uint256[](tau.length - 1);
        for (uint256 i = 0; i < tau.length - 1; i++) {
            tauLow[i] = tau[i];
        }
        uint256[] memory rTailReversed = new uint256[](challenges.length);
        for (uint256 i = 0; i < challenges.length; i++) {
            rTailReversed[i] = challenges[challenges.length - 1 - i];
        }
        uint256 tauKernel = mulmod(tauHighBoundR0, EqPolynomial.mle(tauLow, rTailReversed), R_);

        uint256[10] memory lagrangeW = R1CSEvaluator.lagrangeWeights10(r0);
        uint256 rStream = challenges[0];
        uint256 azBz = R1CSEvaluator.evaluateAzBz(
            _toFixed35(r1csInputEvals), lagrangeW, rStream
        );

        uint256 expectedOutput = mulmod(mulmod(tauKernel, azBz, R_), batchingCoeffs[0], R_);
        require(finalClaim == expectedOutput, "stage1: output claim mismatch");

        // 6. Flush 35 opening claims
        for (uint256 i = 0; i < 35; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), r1csInputEvals[i]);
        }
    }

    function _toFixed35(uint256[] memory arr) internal pure returns (uint256[35] memory result) {
        require(arr.length == 35, "expected 35 elements");
        for (uint256 i = 0; i < 35; i++) {
            result[i] = arr[i];
        }
    }

    function _lagrangeKernel10(uint256 tau_, uint256 r) internal pure returns (uint256) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256[10] memory wTau = R1CSEvaluator.lagrangeWeights10(tau_);
        uint256[10] memory wR = R1CSEvaluator.lagrangeWeights10(r);
        uint256 result = 0;
        for (uint256 i = 0; i < 10; i++) {
            result = addmod(result, mulmod(wTau[i], wR[i], R_), R_);
        }
        return result;
    }

    function _evalPoly(uint256[] memory coeffs, uint256 x) internal pure returns (uint256 result) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        if (coeffs.length == 0) return 0;
        result = coeffs[coeffs.length - 1];
        for (uint256 i = coeffs.length - 1; i > 0; ) {
            unchecked { i--; }
            result = addmod(mulmod(result, x, R_), coeffs[i], R_);
        }
    }

    function _evalPolyAtInt(uint256[] memory coeffs, int256 point) internal pure returns (uint256 result) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        if (coeffs.length == 0) return 0;
        uint256 x;
        if (point >= 0) { x = uint256(point); }
        else { x = R_ - uint256(-point); }
        result = coeffs[coeffs.length - 1];
        for (uint256 i = coeffs.length - 1; i > 0; ) {
            unchecked { i--; }
            result = addmod(mulmod(result, x, R_), coeffs[i], R_);
        }
    }

    function _log2(uint64 x) internal pure returns (uint256) {
        uint256 result = 0;
        uint256 v = uint256(x);
        require(v > 0, "log2(0)");
        while (v > 1) {
            v >>= 1;
            result++;
        }
        return result;
    }

    /// @notice Parse a nested JSON array of uint256 arrays (e.g., compressed polys).
    function _parseNestedUintArray(string memory json, string memory path)
        internal
        pure
        returns (uint256[][] memory result)
    {
        bytes memory raw = vm.parseJson(json, path);
        result = abi.decode(raw, (uint256[][]));
    }

    // ================================================================
    //  Multi-stage transcript consistency
    // ================================================================

    /// @notice Replay generic batched sumcheck transcript operations.
    /// For each instance: append input claim, then derive batching, run rounds, flush.
    function _replaySumcheck(
        JoltTranscript.Transcript memory t,
        uint256[] memory inputClaims,
        uint256[][] memory compressedPolys,
        uint256[] memory flushClaims
    ) internal pure {
        // Append input claims
        for (uint256 i = 0; i < inputClaims.length; i++) {
            t.appendLabeledScalar(bytes32(bytes14("sumcheck_claim")), inputClaims[i]);
        }
        // Batching coefficients
        t.challengeVector(inputClaims.length);
        // Sumcheck rounds
        for (uint256 i = 0; i < compressedPolys.length; i++) {
            t.appendLabeledScalars(bytes24(bytes13("sumcheck_poly")), compressedPolys[i]);
            t.challengeScalarMont(); // round challenge
        }
        // Flush opening claims
        for (uint256 i = 0; i < flushClaims.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), flushClaims[i]);
        }
    }

    /// @notice Full transcript consistency across all 7 stages.
    function test_transcriptConsistency_allStages() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);

        // Verify post-preamble state
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[0]")));

        // === Stage 1: Spartan Outer ===
        {
            // Pre-sumcheck: tau(11) + UniSkip(28 coeffs, r0) + flush(1)
            t.challengeVector(vm.parseJsonUint(json, ".num_rows_bits"));
            uint256[] memory uniSkipCoeffs = vm.parseJsonUintArray(json, ".uniskip_polys[0]");
            t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), uniSkipCoeffs);
            t.challengeScalar(); // r0
            uint256[] memory uniFlush = vm.parseJsonUintArray(json, ".flush_history[0]");
            for (uint256 i = 0; i < uniFlush.length; i++) {
                t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniFlush[i]);
            }
            // Sumcheck + flush
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[0]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[0]"),
                vm.parseJsonUintArray(json, ".flush_history[1]")
            );
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[1]")),
            "State mismatch after Stage 1");

        // === Stage 2: Product Virtual ===
        {
            // UniSkip: tauHigh + poly append + r0 + flush
            t.challengeScalar(); // tauHigh (challenge_scalar_optimized)
            uint256[] memory uniSkipCoeffs2 = vm.parseJsonUintArray(json, ".uniskip_polys[1]");
            t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), uniSkipCoeffs2);
            t.challengeScalar(); // r0 (challenge_scalar_optimized)
            uint256[] memory uniFlush2 = vm.parseJsonUintArray(json, ".flush_history[2]");
            for (uint256 i = 0; i < uniFlush2.length; i++) {
                t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniFlush2[i]);
            }
            // Instance constructors: ramRwGamma, instrGamma, r_address
            t.challengeScalar(); // ramRwGamma
            t.challengeScalar(); // instrGamma
            uint256 ramK = vm.parseJsonUint(json, ".ram_k");
            uint256 ramKLog2 = 0;
            { uint256 tmp = ramK; while (tmp > 1) { tmp >>= 1; ramKLog2++; } }
            t.challengeVector(ramKLog2); // r_address (challenge_vector_optimized)
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[1]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[1]"),
                vm.parseJsonUintArray(json, ".flush_history[3]")
            );
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[2]")),
            "State mismatch after Stage 2");

        // === Stage 3: Shift + InstrReadRaf + RegClaimReduction ===
        {
            t.challengeScalarPowers(5); // shift gammas
            t.challengeScalar(); // instrGamma
            t.challengeScalar(); // regGamma
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[2]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[2]"),
                vm.parseJsonUintArray(json, ".flush_history[4]")
            );
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[3]")),
            "State mismatch after Stage 3");

        // === Stage 4: RegistersRW + RamValCheck ===
        {
            t.challengeScalar(); // regGamma
            t.appendLabeledBytes(bytes24(bytes19("ram_val_check_gamma")), 0, ""); // domain separator
            t.challengeScalar(); // ramValCheckGamma
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[3]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[3]"),
                vm.parseJsonUintArray(json, ".flush_history[5]")
            );
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[4]")),
            "State mismatch after Stage 4");

        // === Stage 5: InstrReadRaf + RamRa + RegValEval ===
        {
            t.challengeScalar(); // instrRafGamma
            t.challengeScalar(); // ramRaGamma
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[4]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[4]"),
                vm.parseJsonUintArray(json, ".flush_history[6]")
            );
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[5]")),
            "State mismatch after Stage 5");

        // === Stage 6: Bytecode + Booleanity + HammingBool + RamRaVirt + LookupsRaVirt + IncReduction ===
        {
            // 9 challenge derivations (each challengeScalarPowers calls challengeScalar once)
            t.challengeScalar(); // bytecodeGammaBase
            t.challengeScalar(); // stage1GammaBase
            t.challengeScalar(); // stage2GammaBase
            t.challengeScalar(); // stage3GammaBase
            t.challengeScalar(); // stage4GammaBase
            t.challengeScalar(); // stage5GammaBase
            t.challengeScalar(); // boolGamma
            t.challengeScalar(); // lookupsRaGammaBase
            t.challengeScalar(); // incGamma
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[5]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[5]"),
                vm.parseJsonUintArray(json, ".flush_history[7]")
            );
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[6]")),
            "State mismatch after Stage 6");

        // === Stage 7: HammingWeight claim reduction ===
        {
            t.challengeScalar(); // hwGamma
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[6]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[6]"),
                vm.parseJsonUintArray(json, ".flush_history[8]")
            );
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[7]")),
            "State mismatch after Stage 7");

        // === Stage 8: Verify joint_claim RLC computation ===
        // Note: The Dory PCS::verify call modifies the transcript with reduce-and-fold
        // challenges that are internal to the Dory protocol. On-chain, this is replaced
        // by the Groth16 wrapper, so we only verify the joint_claim computation.
        {
            uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

            // 1. Append committed claims to transcript (matches Rust: append_scalars("rlc_claims", &claims))
            uint256[] memory claims = vm.parseJsonUintArray(json, ".stage8_committed_claims");
            t.appendLabeledScalars(bytes24(bytes10("rlc_claims")), claims);

            // 2. Sample gamma powers (matches Rust: challenge_scalar_powers)
            uint256[] memory gammaPowers = t.challengeScalarPowers(claims.length);

            // 3. Compute joint_claim = Σ γ^i * claim_i
            uint256 jointClaim = 0;
            for (uint256 i = 0; i < claims.length; i++) {
                jointClaim = addmod(jointClaim, mulmod(gammaPowers[i], claims[i], R_), R_);
            }

            // Verify joint_claim matches Rust export
            uint256 expectedJointClaim = vm.parseJsonUint(json, ".stage8_joint_claim");
            assertEq(jointClaim, expectedJointClaim, "Stage 8: joint_claim mismatch");
        }
    }

    // ================================================================
    //  Stage 3 Algebraic Verification
    // ================================================================

    struct Stage3TestData {
        uint256[10] virtEvals;  // 10 virtual polynomial evaluations
        uint256[] rOuter;       // rOuter == rSpartan (9 coords)
        uint256[] rProduct;     // rProduct == rCycleStage2 (9 coords)
        uint256[][] compressedPolys;
        uint256[] flushedClaims;
        uint256 nCycleVars;
    }

    function _parseStage3Data(string memory json) internal view returns (Stage3TestData memory d) {
        d.nCycleVars = _log2(uint64(vm.parseJsonUint(json, ".trace_length")));
        string memory base = ".stage_intermediate_values[2].";
        d.virtEvals[0] = vm.parseJsonUint(json, string(abi.encodePacked(base, "nextUnexpandedPC")));
        d.virtEvals[1] = vm.parseJsonUint(json, string(abi.encodePacked(base, "nextPC")));
        d.virtEvals[2] = vm.parseJsonUint(json, string(abi.encodePacked(base, "nextIsVirtual")));
        d.virtEvals[3] = vm.parseJsonUint(json, string(abi.encodePacked(base, "nextIsFirstInSeq")));
        d.virtEvals[4] = vm.parseJsonUint(json, string(abi.encodePacked(base, "nextIsNoop")));
        d.virtEvals[5] = vm.parseJsonUint(json, string(abi.encodePacked(base, "rightInstructionInput")));
        d.virtEvals[6] = vm.parseJsonUint(json, string(abi.encodePacked(base, "leftInstructionInput")));
        d.virtEvals[7] = vm.parseJsonUint(json, string(abi.encodePacked(base, "rdWriteValue")));
        d.virtEvals[8] = vm.parseJsonUint(json, string(abi.encodePacked(base, "rs1Value")));
        d.virtEvals[9] = vm.parseJsonUint(json, string(abi.encodePacked(base, "rs2Value")));
        d.rOuter = _parseIndexedPoints(json, ".stage_intermediate_values[2]", "rOuter_", d.nCycleVars);
        d.rProduct = _parseIndexedPoints(json, ".stage_intermediate_values[2]", "rProduct_", d.nCycleVars);
        d.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[2]");
        d.flushedClaims = vm.parseJsonUintArray(json, ".flush_history[4]");
    }

    /// @notice Full algebraic verification of Stage 3.
    function test_verifyStage3_algebraic() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);

        _replayStage1Transcript(t, json);
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[1]")));
        _replayStage2Transcript(t, json);
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[2]")));

        Stage3TestData memory d = _parseStage3Data(json);
        require(d.flushedClaims.length == 13, "expected 13 flushed claims");

        _verifyStage3Core(t, d);

        // Flush opening claims
        for (uint256 i = 0; i < 13; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), d.flushedClaims[i]);
        }

        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[3]")),
            "Transcript state after Stage 3 does not match Rust");
    }

    function _verifyStage3Core(
        JoltTranscript.Transcript memory t,
        Stage3TestData memory d
    ) internal view {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

        // 1. Sample challenges
        uint256[5] memory gp;
        {
            uint256[] memory powers = t.challengeScalarPowers(5);
            for (uint256 i = 0; i < 5; i++) gp[i] = powers[i];
        }
        uint256 instrGamma = t.challengeScalar();
        uint256 regGamma = t.challengeScalar();
        uint256 regGammaSqr = mulmod(regGamma, regGamma, R_);

        // 2. Compute input claims
        uint256[] memory ic = new uint256[](3);
        // Instance 0: ShiftSumcheck
        ic[0] = _shiftInputClaim(d.virtEvals, gp);
        // Instance 1: InstructionInput
        ic[1] = addmod(d.virtEvals[5], mulmod(instrGamma, d.virtEvals[6], R_), R_);
        // Instance 2: RegistersClaimReduction
        ic[2] = addmod(d.virtEvals[7],
            addmod(mulmod(regGamma, d.virtEvals[8], R_), mulmod(regGammaSqr, d.virtEvals[9], R_), R_), R_);

        // 3. Batched sumcheck
        uint256[] memory inr = new uint256[](3);
        inr[0] = d.nCycleVars; inr[1] = d.nCycleVars; inr[2] = d.nCycleVars;

        (uint256 finalClaim, uint256[] memory challenges, uint256[] memory bc) =
            BatchedSumcheckVerifier.verify(d.compressedPolys, ic, inr, 3, t);

        // 4. Expected output
        uint256[] memory r = _reverse(challenges);
        uint256 expected = _stage3ShiftExpected(r, d, gp, bc[0]);
        expected = addmod(expected, _stage3InstrExpected(r, d, instrGamma, bc[1]), R_);
        expected = addmod(expected, _stage3RegExpected(r, d, regGamma, regGammaSqr, bc[2]), R_);

        require(finalClaim == expected, "stage3: output claim mismatch");
    }

    function _shiftInputClaim(uint256[10] memory v, uint256[5] memory gp) internal pure returns (uint256 c) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        c = v[0]; // nextUnexpandedPC
        c = addmod(c, mulmod(gp[1], v[1], R_), R_); // + gamma^1 * nextPC
        c = addmod(c, mulmod(gp[2], v[2], R_), R_); // + gamma^2 * nextIsVirtual
        c = addmod(c, mulmod(gp[3], v[3], R_), R_); // + gamma^3 * nextIsFirstInSeq
        c = addmod(c, mulmod(gp[4], addmod(1, R_ - v[4], R_), R_), R_); // + gamma^4 * (1 - nextIsNoop)
    }

    function _stage3ShiftExpected(
        uint256[] memory r, Stage3TestData memory d,
        uint256[5] memory gp, uint256 bc0
    ) internal view returns (uint256) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256 eqPO = EqPolynomial.eqPlusOne(d.rOuter, r);
        uint256 eqPP = EqPolynomial.eqPlusOne(d.rProduct, r);

        uint256 batched = mulmod(gp[0], d.flushedClaims[0], R_);
        batched = addmod(batched, mulmod(gp[1], d.flushedClaims[1], R_), R_);
        batched = addmod(batched, mulmod(gp[2], d.flushedClaims[2], R_), R_);
        batched = addmod(batched, mulmod(gp[3], d.flushedClaims[3], R_), R_);
        uint256 sc = mulmod(batched, eqPO, R_);
        sc = addmod(sc, mulmod(gp[4], mulmod(addmod(1, R_ - d.flushedClaims[4], R_), eqPP, R_), R_), R_);
        return mulmod(sc, bc0, R_);
    }

    function _stage3InstrExpected(
        uint256[] memory r, Stage3TestData memory d,
        uint256 instrGamma, uint256 bc1
    ) internal view returns (uint256) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256 eqCycle = EqPolynomial.mle(r, d.rProduct);
        uint256 leftInput = addmod(
            mulmod(d.flushedClaims[5], d.flushedClaims[6], R_),
            mulmod(d.flushedClaims[7], d.flushedClaims[0], R_),
            R_
        );
        uint256 rightInput = addmod(
            mulmod(d.flushedClaims[8], d.flushedClaims[9], R_),
            mulmod(d.flushedClaims[10], d.flushedClaims[11], R_),
            R_
        );
        uint256 ic = mulmod(eqCycle, addmod(rightInput, mulmod(instrGamma, leftInput, R_), R_), R_);
        return mulmod(ic, bc1, R_);
    }

    function _stage3RegExpected(
        uint256[] memory r, Stage3TestData memory d,
        uint256 regGamma, uint256 regGammaSqr, uint256 bc2
    ) internal view returns (uint256) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256 eqSpartan = EqPolynomial.mle(r, d.rOuter);
        uint256 br = d.flushedClaims[12];
        br = addmod(br, mulmod(regGamma, d.flushedClaims[6], R_), R_);
        br = addmod(br, mulmod(regGammaSqr, d.flushedClaims[9], R_), R_);
        return mulmod(mulmod(eqSpartan, br, R_), bc2, R_);
    }

    /// @notice Helper: replay Stage 1 transcript operations.
    function _replayStage1Transcript(
        JoltTranscript.Transcript memory t,
        string memory json
    ) internal view {
        t.challengeVector(vm.parseJsonUint(json, ".num_rows_bits"));
        uint256[] memory uniSkipCoeffs = vm.parseJsonUintArray(json, ".uniskip_polys[0]");
        t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), uniSkipCoeffs);
        t.challengeScalar();
        uint256[] memory uniFlush = vm.parseJsonUintArray(json, ".flush_history[0]");
        for (uint256 i = 0; i < uniFlush.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniFlush[i]);
        }
        _replaySumcheck(
            t,
            vm.parseJsonUintArray(json, ".sumcheck_input_claims[0]"),
            _parseNestedUintArray(json, ".stage_compressed_polys[0]"),
            vm.parseJsonUintArray(json, ".flush_history[1]")
        );
    }

    /// @notice Helper: replay Stage 2 transcript operations.
    function _replayStage2Transcript(
        JoltTranscript.Transcript memory t,
        string memory json
    ) internal view {
        t.challengeScalar();
        uint256[] memory uniSkipCoeffs2 = vm.parseJsonUintArray(json, ".uniskip_polys[1]");
        t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), uniSkipCoeffs2);
        t.challengeScalar();
        uint256[] memory uniFlush2 = vm.parseJsonUintArray(json, ".flush_history[2]");
        for (uint256 i = 0; i < uniFlush2.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniFlush2[i]);
        }
        t.challengeScalar();
        t.challengeScalar();
        uint256 ramK = vm.parseJsonUint(json, ".ram_k");
        uint256 ramKLog2 = 0;
        { uint256 tmp = ramK; while (tmp > 1) { tmp >>= 1; ramKLog2++; } }
        t.challengeVector(ramKLog2);
        _replaySumcheck(
            t,
            vm.parseJsonUintArray(json, ".sumcheck_input_claims[1]"),
            _parseNestedUintArray(json, ".stage_compressed_polys[1]"),
            vm.parseJsonUintArray(json, ".flush_history[3]")
        );
    }

    // ================================================================
    //  Stage 4 Algebraic Verification
    // ================================================================

    struct Stage4TestData {
        uint256 rdWriteValue;
        uint256 rs1Value;
        uint256 rs2Value;
        uint256 ramVal;
        uint256 ramValFinal;
        uint256 initEval;
        uint256[] rCycleStage3;
        uint256[] rCycleStage2Ram;
        uint256[][] compressedPolys;
        uint256[7] flushedClaims;
        uint256 nCycleVars;
        uint256 regPhase1Rounds;
        uint256 regPhase2Rounds;
    }

    function _parseStage4Data(string memory json) internal view returns (Stage4TestData memory d) {
        d.nCycleVars = _log2(uint64(vm.parseJsonUint(json, ".trace_length")));
        string memory base = ".stage_intermediate_values[3].";
        d.rdWriteValue = vm.parseJsonUint(json, string(abi.encodePacked(base, "rdWriteValue")));
        d.rs1Value = vm.parseJsonUint(json, string(abi.encodePacked(base, "rs1Value")));
        d.rs2Value = vm.parseJsonUint(json, string(abi.encodePacked(base, "rs2Value")));
        d.ramVal = vm.parseJsonUint(json, string(abi.encodePacked(base, "ramVal")));
        d.ramValFinal = vm.parseJsonUint(json, string(abi.encodePacked(base, "ramValFinal")));
        d.initEval = vm.parseJsonUint(json, string(abi.encodePacked(base, "initEval")));
        d.rCycleStage3 = _parseIndexedPoints(json, ".stage_intermediate_values[3]", "rCycleStage3_", d.nCycleVars);
        d.rCycleStage2Ram = _parseIndexedPoints(json, ".stage_intermediate_values[3]", "rCycleStage2Ram_", d.nCycleVars);
        d.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[3]");

        uint256[] memory fc = vm.parseJsonUintArray(json, ".flush_history[5]");
        require(fc.length == 7, "expected 7 flushed claims for stage 4");
        for (uint256 i = 0; i < 7; i++) d.flushedClaims[i] = fc[i];

        d.regPhase1Rounds = vm.parseJsonUint(json, ".rw_config.registers_rw_phase1_num_rounds");
        d.regPhase2Rounds = vm.parseJsonUint(json, ".rw_config.registers_rw_phase2_num_rounds");
    }

    function test_verifyStage4_algebraic() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);

        _replayStage1Transcript(t, json);
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[1]")));
        _replayStage2Transcript(t, json);
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[2]")));
        // Replay stage 3 transcript
        {
            t.challengeScalarPowers(5);
            t.challengeScalar();
            t.challengeScalar();
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[2]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[2]"),
                vm.parseJsonUintArray(json, ".flush_history[4]")
            );
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[3]")));

        Stage4TestData memory d = _parseStage4Data(json);
        _verifyStage4Core(t, d);

        // Flush opening claims
        for (uint256 i = 0; i < 7; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), d.flushedClaims[i]);
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[4]")),
            "Transcript state after Stage 4 does not match Rust");
    }

    function _verifyStage4Core(
        JoltTranscript.Transcript memory t,
        Stage4TestData memory d
    ) internal view {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

        // 1. Sample challenges
        uint256 regGamma = t.challengeScalar();
        t.appendLabeledBytes(bytes24(bytes19("ram_val_check_gamma")), 0, "");
        uint256 ramValCheckGamma = t.challengeScalar();

        // 2. Compute input claims
        uint256[] memory ic = new uint256[](2);
        // Instance 0: RegistersRW: rdWriteValue + γ*(rs1Value + γ*rs2Value)
        ic[0] = addmod(d.rdWriteValue, mulmod(regGamma, addmod(d.rs1Value, mulmod(regGamma, d.rs2Value, R_), R_), R_), R_);
        // Instance 1: RamValCheck: (ramVal - initEval) + γ_ram*(ramValFinal - initEval)
        {
            uint256 diff1 = addmod(d.ramVal, R_ - d.initEval, R_);
            uint256 diff2 = addmod(d.ramValFinal, R_ - d.initEval, R_);
            ic[1] = addmod(diff1, mulmod(ramValCheckGamma, diff2, R_), R_);
        }

        // 3. Batched sumcheck
        uint256 regRounds = 7 + d.nCycleVars; // LOG_K_REGISTERS=7
        uint256[] memory inr = new uint256[](2);
        inr[0] = regRounds;
        inr[1] = d.nCycleVars;

        (uint256 finalClaim, uint256[] memory challenges, uint256[] memory bc) =
            BatchedSumcheckVerifier.verify(d.compressedPolys, ic, inr, 3, t);

        // 4. Expected output — Instance 0: RegistersRW
        uint256 batchedExpected;
        {
            uint256[] memory rCycleOutput = _extractCyclePoint3Phase(
                challenges, d.regPhase1Rounds, d.regPhase2Rounds, d.nCycleVars);
            uint256 eqEval = EqPolynomial.mle(d.rCycleStage3, rCycleOutput);

            uint256 val = d.flushedClaims[0];
            uint256 rdWa = d.flushedClaims[3];
            uint256 inc = d.flushedClaims[4];
            uint256 rdWriteVal = mulmod(rdWa, addmod(inc, val, R_), R_);
            uint256 rs1Val = mulmod(d.flushedClaims[1], val, R_);
            uint256 rs2Val = mulmod(d.flushedClaims[2], val, R_);
            uint256 batchedReg = addmod(rdWriteVal,
                mulmod(regGamma, addmod(rs1Val, mulmod(regGamma, rs2Val, R_), R_), R_), R_);
            batchedExpected = mulmod(mulmod(eqEval, batchedReg, R_), bc[0], R_);
        }

        // Instance 1: RamValCheck
        {
            uint256 ltEval = EqPolynomial.ltSliceReversed(challenges, regRounds - d.nCycleVars, d.nCycleVars, d.rCycleStage2Ram);
            uint256 wa = d.flushedClaims[5];
            uint256 incRam = d.flushedClaims[6];
            uint256 ramClaim = mulmod(mulmod(incRam, wa, R_), addmod(ltEval, ramValCheckGamma, R_), R_);
            batchedExpected = addmod(batchedExpected, mulmod(ramClaim, bc[1], R_), R_);
        }

        require(finalClaim == batchedExpected, "stage4: output claim mismatch");
    }

    function _extractCyclePoint3Phase(
        uint256[] memory challenges,
        uint256 phase1Rounds,
        uint256 phase2Rounds,
        uint256 logT
    ) internal pure returns (uint256[] memory rCycle) {
        uint256 remainingCycle = logT - phase1Rounds;
        rCycle = new uint256[](logT);
        uint256 phase3Start = phase1Rounds + phase2Rounds;
        for (uint256 i = 0; i < remainingCycle; i++) {
            rCycle[i] = challenges[phase3Start + remainingCycle - 1 - i];
        }
        for (uint256 i = 0; i < phase1Rounds; i++) {
            rCycle[remainingCycle + i] = challenges[phase1Rounds - 1 - i];
        }
    }

    // ================================================================
    //  Stage 5 Algebraic Verification
    // ================================================================

    struct Stage5TestData {
        uint256 lookupOutput;
        uint256 leftOperand;
        uint256 rightOperand;
        uint256[] valEvals;       // 40 table MLE evaluations
        uint256 leftOperandEval;
        uint256 rightOperandEval;
        uint256 identityEval;
        uint256[] rReduction;     // 9 elements
        uint256 claimRaf;
        uint256 claimRw;
        uint256 claimVal;
        uint256[] rCycleRaf;      // 9 elements
        uint256[] rCycleRw;       // 9 elements
        uint256[] rCycleVal;      // 9 elements
        uint256 registersVal;
        uint256[] rCycleStage4Reg; // 12 elements (LOG_K_REGISTERS + nCycleVars - phase1 overlap)
        uint256[][] compressedPolys;
        uint256[] flushedClaims;  // 52 claims
        uint256 nCycleVars;
        uint256 nTables;
        uint256 nRaChunks;
        uint256 logKInstr;
    }

    function _parseStage5Data(string memory json) internal view returns (Stage5TestData memory d) {
        d.nCycleVars = _log2(uint64(vm.parseJsonUint(json, ".trace_length")));
        string memory base = ".stage_intermediate_values[4]";

        d.lookupOutput = vm.parseJsonUint(json, string(abi.encodePacked(base, ".lookupOutput")));
        d.leftOperand = vm.parseJsonUint(json, string(abi.encodePacked(base, ".leftOperand")));
        d.rightOperand = vm.parseJsonUint(json, string(abi.encodePacked(base, ".rightOperand")));
        d.leftOperandEval = vm.parseJsonUint(json, string(abi.encodePacked(base, ".leftOperandEval")));
        d.rightOperandEval = vm.parseJsonUint(json, string(abi.encodePacked(base, ".rightOperandEval")));
        d.identityEval = vm.parseJsonUint(json, string(abi.encodePacked(base, ".identityEval")));
        d.claimRaf = vm.parseJsonUint(json, string(abi.encodePacked(base, ".claimRaf")));
        d.claimRw = vm.parseJsonUint(json, string(abi.encodePacked(base, ".claimRw")));
        d.claimVal = vm.parseJsonUint(json, string(abi.encodePacked(base, ".claimVal")));
        d.registersVal = vm.parseJsonUint(json, string(abi.encodePacked(base, ".registersVal")));

        d.nTables = 40;
        d.nRaChunks = 8;
        d.logKInstr = 128;

        d.valEvals = new uint256[](d.nTables);
        for (uint256 i = 0; i < d.nTables; i++) {
            d.valEvals[i] = vm.parseJsonUint(json, string(abi.encodePacked(base, ".valEval_", vm.toString(i))));
        }

        d.rReduction = _parseIndexedPoints(json, base, "rReduction_", d.nCycleVars);
        d.rCycleRaf = _parseIndexedPoints(json, base, "rCycleRaf_", d.nCycleVars);
        d.rCycleRw = _parseIndexedPoints(json, base, "rCycleRw_", d.nCycleVars);
        d.rCycleVal = _parseIndexedPoints(json, base, "rCycleVal_", d.nCycleVars);
        d.rCycleStage4Reg = _parseIndexedPoints(json, base, "rCycleStage4Reg_", d.nCycleVars);

        d.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[4]");
        d.flushedClaims = vm.parseJsonUintArray(json, ".flush_history[6]");
    }

    function test_verifyStage5_algebraic() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);

        // Replay stages 1-4
        _replayStage1Transcript(t, json);
        _replayStage2Transcript(t, json);
        {
            t.challengeScalarPowers(5);
            t.challengeScalar();
            t.challengeScalar();
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[2]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[2]"),
                vm.parseJsonUintArray(json, ".flush_history[4]")
            );
        }
        {
            t.challengeScalar();
            t.appendLabeledBytes(bytes24(bytes19("ram_val_check_gamma")), 0, "");
            t.challengeScalar();
            _replaySumcheck(
                t,
                vm.parseJsonUintArray(json, ".sumcheck_input_claims[3]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[3]"),
                vm.parseJsonUintArray(json, ".flush_history[5]")
            );
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[4]")),
            "Transcript state after Stage 4 does not match Rust");

        Stage5TestData memory d = _parseStage5Data(json);
        _verifyStage5Core(t, d);

        // Flush opening claims
        for (uint256 i = 0; i < d.flushedClaims.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), d.flushedClaims[i]);
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[5]")),
            "Transcript state after Stage 5 does not match Rust");
    }

    function _verifyStage5Core(
        JoltTranscript.Transcript memory t,
        Stage5TestData memory d
    ) internal view {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

        // 1. Sample challenges
        uint256 instrRafGamma = t.challengeScalar();
        uint256 instrRafGammaSqr = mulmod(instrRafGamma, instrRafGamma, R_);
        uint256 ramRaGamma = t.challengeScalar();
        uint256 ramRaGammaSqr = mulmod(ramRaGamma, ramRaGamma, R_);

        // 2. Compute input claims
        uint256[] memory ic = new uint256[](3);
        ic[0] = addmod(d.lookupOutput,
            addmod(mulmod(instrRafGamma, d.leftOperand, R_),
                   mulmod(instrRafGammaSqr, d.rightOperand, R_), R_), R_);
        ic[1] = addmod(d.claimRaf,
            addmod(mulmod(ramRaGamma, d.claimRw, R_),
                   mulmod(ramRaGammaSqr, d.claimVal, R_), R_), R_);
        ic[2] = d.registersVal;

        // 3. Batched sumcheck
        uint256 instrRafRounds = d.logKInstr + d.nCycleVars;
        uint256[] memory inr = new uint256[](3);
        inr[0] = instrRafRounds;
        inr[1] = d.nCycleVars;
        inr[2] = d.nCycleVars;

        (uint256 finalClaim, uint256[] memory challenges, uint256[] memory bc) =
            BatchedSumcheckVerifier.verify(d.compressedPolys, ic, inr, 10, t);

        // 4. Expected output — Instance 0: InstructionReadRaf
        uint256 batchedExpected;
        {
            uint256 instrOffset = instrRafRounds - d.nCycleVars;
            uint256 eqEval = EqPolynomial.mleSliceReversed(d.rReduction, challenges, instrOffset, d.nCycleVars);

            uint256 raProduct = 1;
            for (uint256 i = 0; i < d.nRaChunks; i++) {
                raProduct = mulmod(raProduct, d.flushedClaims[d.nTables + i], R_);
            }

            uint256 valClaim = 0;
            for (uint256 i = 0; i < d.nTables; i++) {
                valClaim = addmod(valClaim, mulmod(d.valEvals[i], d.flushedClaims[i], R_), R_);
            }

            uint256 rafFlag = d.flushedClaims[d.nTables + d.nRaChunks];
            uint256 rafClaim = addmod(
                mulmod(addmod(1, R_ - rafFlag, R_),
                    addmod(d.leftOperandEval, mulmod(instrRafGamma, d.rightOperandEval, R_), R_), R_),
                mulmod(rafFlag, mulmod(instrRafGamma, d.identityEval, R_), R_), R_);

            uint256 instrClaim = mulmod(eqEval, mulmod(raProduct, addmod(valClaim, mulmod(instrRafGamma, rafClaim, R_), R_), R_), R_);
            batchedExpected = mulmod(instrClaim, bc[0], R_);
        }

        // Instance 1: RamRaClaimReduction
        {
            uint256 raOffset = instrRafRounds - d.nCycleVars;
            uint256 eqCombined = EqPolynomial.mleSliceReversed(d.rCycleRaf, challenges, raOffset, d.nCycleVars);
            eqCombined = addmod(eqCombined,
                mulmod(ramRaGamma, EqPolynomial.mleSliceReversed(d.rCycleRw, challenges, raOffset, d.nCycleVars), R_), R_);
            eqCombined = addmod(eqCombined,
                mulmod(ramRaGammaSqr, EqPolynomial.mleSliceReversed(d.rCycleVal, challenges, raOffset, d.nCycleVars), R_), R_);

            uint256 ramRaIdx = d.nTables + d.nRaChunks + 1;
            uint256 raClaim = d.flushedClaims[ramRaIdx];
            batchedExpected = addmod(batchedExpected, mulmod(mulmod(eqCombined, raClaim, R_), bc[1], R_), R_);
        }

        // Instance 2: RegistersValEvaluation
        {
            uint256 regOffset = instrRafRounds - d.nCycleVars;
            uint256 ltEval = EqPolynomial.ltSliceReversed(challenges, regOffset, d.nCycleVars, d.rCycleStage4Reg);

            uint256 regValIdx = d.nTables + d.nRaChunks + 2;
            uint256 incClaim = d.flushedClaims[regValIdx];
            uint256 waClaim = d.flushedClaims[regValIdx + 1];
            batchedExpected = addmod(batchedExpected, mulmod(mulmod(mulmod(incClaim, waClaim, R_), ltEval, R_), bc[2], R_), R_);
        }

        require(finalClaim == batchedExpected, "stage5: output claim mismatch");
    }

    // ================================================================
    //  Stage 7 Algebraic Verification
    // ================================================================

    struct Stage7TestData {
        uint256 logKChunk;
        uint256 nPolynomials;
        uint256[] hwClaims;
        uint256[] boolClaims;
        uint256[] virtClaims;
        uint256[] rAddrBool;
        uint256[][] rAddrVirt;
        uint256[][] compressedPolys;
        uint256[] flushedClaims;
    }

    function _parseStage7Data(string memory json) internal view returns (Stage7TestData memory d) {
        d.logKChunk = vm.parseJsonUint(json, ".one_hot_config.log_k_chunk");
        d.nPolynomials = 40; // InstructionRa(8) + BytecodeRa(4) + RamRa(4) + ... = counted from flush_history[8]
        d.flushedClaims = vm.parseJsonUintArray(json, ".flush_history[8]");
        d.nPolynomials = d.flushedClaims.length;

        string memory base = ".stage_intermediate_values[6]";
        d.hwClaims = new uint256[](d.nPolynomials);
        d.boolClaims = new uint256[](d.nPolynomials);
        d.virtClaims = new uint256[](d.nPolynomials);
        for (uint256 i = 0; i < d.nPolynomials; i++) {
            d.hwClaims[i] = vm.parseJsonUint(json, string(abi.encodePacked(base, ".hwClaim_", vm.toString(i))));
            d.boolClaims[i] = vm.parseJsonUint(json, string(abi.encodePacked(base, ".boolClaim_", vm.toString(i))));
            d.virtClaims[i] = vm.parseJsonUint(json, string(abi.encodePacked(base, ".virtClaim_", vm.toString(i))));
        }

        d.rAddrBool = _parseIndexedPoints(json, base, "rAddrBool_", d.logKChunk);
        d.rAddrVirt = new uint256[][](d.nPolynomials);
        for (uint256 i = 0; i < d.nPolynomials; i++) {
            string memory prefix = string(abi.encodePacked("rAddrVirt_", vm.toString(i), "_"));
            d.rAddrVirt[i] = _parseIndexedPoints(json, base, prefix, d.logKChunk);
        }

        d.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[6]");
    }

    function test_verifyStage7_algebraic() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);

        // Replay stages 1-6
        _replayStage1Transcript(t, json);
        _replayStage2Transcript(t, json);
        // Stage 3
        {
            t.challengeScalarPowers(5);
            t.challengeScalar();
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[2]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[2]"),
                vm.parseJsonUintArray(json, ".flush_history[4]"));
        }
        // Stage 4
        {
            t.challengeScalar();
            t.appendLabeledBytes(bytes24(bytes19("ram_val_check_gamma")), 0, "");
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[3]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[3]"),
                vm.parseJsonUintArray(json, ".flush_history[5]"));
        }
        // Stage 5
        {
            t.challengeScalar();
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[4]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[4]"),
                vm.parseJsonUintArray(json, ".flush_history[6]"));
        }
        // Stage 6
        {
            for (uint256 i = 0; i < 6; i++) t.challengeScalar();
            t.challengeScalarMont();
            t.challengeScalar();
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[5]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[5]"),
                vm.parseJsonUintArray(json, ".flush_history[7]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[6]")),
            "Transcript state after Stage 6 does not match Rust");

        Stage7TestData memory d = _parseStage7Data(json);
        _verifyStage7Core(t, d);

        for (uint256 i = 0; i < d.flushedClaims.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), d.flushedClaims[i]);
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[7]")),
            "Transcript state after Stage 7 does not match Rust");
    }

    function _verifyStage7Core(
        JoltTranscript.Transcript memory t,
        Stage7TestData memory d
    ) internal view {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256 N = d.nPolynomials;

        // 1. Sample challenge
        uint256 hwGamma = t.challengeScalar();

        // Precompute gamma powers
        uint256[] memory gp = new uint256[](3 * N);
        gp[0] = 1;
        for (uint256 i = 1; i < 3 * N; i++) {
            gp[i] = mulmod(gp[i - 1], hwGamma, R_);
        }

        // 2. Input claim
        uint256[] memory ic = new uint256[](1);
        for (uint256 i = 0; i < N; i++) {
            ic[0] = addmod(ic[0], mulmod(gp[3 * i], d.hwClaims[i], R_), R_);
            ic[0] = addmod(ic[0], mulmod(gp[3 * i + 1], d.boolClaims[i], R_), R_);
            ic[0] = addmod(ic[0], mulmod(gp[3 * i + 2], d.virtClaims[i], R_), R_);
        }

        // 3. Batched sumcheck
        uint256[] memory inr = new uint256[](1);
        inr[0] = d.logKChunk;

        (uint256 finalClaim, uint256[] memory challenges, uint256[] memory bc) =
            BatchedSumcheckVerifier.verify(d.compressedPolys, ic, inr, 2, t);

        // 4. Expected output
        uint256[] memory rhoRev = _reverse(challenges);
        uint256 eqBoolEval = EqPolynomial.mle(rhoRev, d.rAddrBool);

        uint256 batchedExpected = 0;
        for (uint256 i = 0; i < N; i++) {
            uint256 eqVirtEval = EqPolynomial.mle(rhoRev, d.rAddrVirt[i]);
            uint256 weight = addmod(gp[3 * i],
                addmod(mulmod(gp[3 * i + 1], eqBoolEval, R_),
                       mulmod(gp[3 * i + 2], eqVirtEval, R_), R_), R_);
            batchedExpected = addmod(batchedExpected, mulmod(d.flushedClaims[i], weight, R_), R_);
        }
        batchedExpected = mulmod(batchedExpected, bc[0], R_);

        require(finalClaim == batchedExpected, "stage7: output claim mismatch");
    }

    // ================================================================
    //  Stage 6 Algebraic Verification
    // ================================================================

    struct Stage6TestData {
        uint256 nCycleVars;
        uint256 logKBytecode;
        uint256 logKChunk;
        uint256 bytecodeD;
        uint256 ramD;
        uint256 instructionD;
        uint256 entryBytecodeIndex;
        uint256[5] valPolyEvals;
        uint256[] rCycles;           // 5 * nCycleVars flattened
        uint256[] rCycleHamming;
        uint256[] rAddressBool;
        uint256[] rCycleBool;
        uint256 ramRaInputClaim;
        uint256[] rCycleRamRa;
        uint256[] rCycleLookupsRa;
        uint256 nVirtualRaPolys;
        uint256 nCommittedPerVirtual;
        uint256 nCommittedRaPolys;
        uint256[] lookupsRaInputClaims;
        uint256 incV1;
        uint256 incV2;
        uint256 incW1;
        uint256 incW2;
        uint256[] rCycleIncStage2;
        uint256[] rCycleIncStage4;
        uint256[] sCycleIncStage4;
        uint256[] sCycleIncStage5;
        uint256 bytecodeGammaBase;
        uint256 boolGamma;
        uint256 lookupsRaGammaBase;
        uint256 incGamma;
        uint256[][] compressedPolys;
        uint256[] flushedClaims;
        uint256[] inputClaims;
        uint256[] instanceNumRounds;
        uint256 maxDeg;
    }

    function _parseStage6Data(
        JoltTranscript.Transcript memory t,
        string memory json
    ) internal view returns (Stage6TestData memory d) {
        d.nCycleVars = _log2(uint64(vm.parseJsonUint(json, ".trace_length")));
        d.logKBytecode = _log2(uint64(vm.parseJsonUint(json, ".one_hot_config.bytecode_k")));
        d.logKChunk = vm.parseJsonUint(json, ".one_hot_config.log_k_chunk");
        d.bytecodeD = vm.parseJsonUint(json, ".one_hot_config.bytecode_d");
        d.ramD = vm.parseJsonUint(json, ".one_hot_config.ram_d");
        d.instructionD = vm.parseJsonUint(json, ".one_hot_config.instruction_d");
        string memory base = ".stage_intermediate_values[5]";

        d.entryBytecodeIndex = vm.parseJsonUint(json, string(abi.encodePacked(base, ".entryBytecodeIndex")));

        for (uint256 i = 0; i < 5; i++) {
            d.valPolyEvals[i] = vm.parseJsonUint(json, string(abi.encodePacked(base, ".valPolyEval_", vm.toString(i))));
        }

        // 5 cycle reference points for BytecodeReadRaf
        d.rCycles = new uint256[](5 * d.nCycleVars);
        for (uint256 s = 0; s < 5; s++) {
            string memory prefix = string(abi.encodePacked("rCycle", vm.toString(s + 1), "_"));
            for (uint256 j = 0; j < d.nCycleVars; j++) {
                d.rCycles[s * d.nCycleVars + j] = vm.parseJsonUint(json, string(abi.encodePacked(base, ".", prefix, vm.toString(j))));
            }
        }

        d.rCycleHamming = _parseIndexedPoints(json, base, "rCycleHamming_", d.nCycleVars);
        d.rAddressBool = _parseIndexedPoints(json, base, "rAddressBool_", d.logKChunk);
        d.rCycleBool = _parseIndexedPoints(json, base, "rCycleBool_", d.nCycleVars);

        d.ramRaInputClaim = vm.parseJsonUint(json, string(abi.encodePacked(base, ".ramRaInputClaim")));
        d.rCycleRamRa = _parseIndexedPoints(json, base, "rCycleRamRa_", d.nCycleVars);
        d.rCycleLookupsRa = _parseIndexedPoints(json, base, "rCycleLookupsRa_", d.nCycleVars);

        d.incV1 = vm.parseJsonUint(json, string(abi.encodePacked(base, ".incV1")));
        d.incV2 = vm.parseJsonUint(json, string(abi.encodePacked(base, ".incV2")));
        d.incW1 = vm.parseJsonUint(json, string(abi.encodePacked(base, ".incW1")));
        d.incW2 = vm.parseJsonUint(json, string(abi.encodePacked(base, ".incW2")));
        d.rCycleIncStage2 = _parseIndexedPoints(json, base, "rCycleIncStage2_", d.nCycleVars);
        d.rCycleIncStage4 = _parseIndexedPoints(json, base, "rCycleIncStage4_", d.nCycleVars);
        d.sCycleIncStage4 = _parseIndexedPoints(json, base, "sCycleIncStage4_", d.nCycleVars);
        d.sCycleIncStage5 = _parseIndexedPoints(json, base, "sCycleIncStage5_", d.nCycleVars);

        // Sample challenges from transcript
        d.bytecodeGammaBase = t.challengeScalar();
        for (uint256 i = 0; i < 5; i++) t.challengeScalar(); // stage1-5 gamma bases (unused)
        d.boolGamma = t.challengeScalarMont();
        d.lookupsRaGammaBase = t.challengeScalar();
        d.incGamma = t.challengeScalar();

        d.inputClaims = vm.parseJsonUintArray(json, ".sumcheck_input_claims[5]");
        d.instanceNumRounds = vm.parseJsonUintArray(json, ".stage_instance_configs[5].num_rounds");
        d.maxDeg = vm.parseJsonUint(json, ".stage_instance_configs[5].max_degree");
        d.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[5]");
        d.flushedClaims = vm.parseJsonUintArray(json, ".flush_history[7]");

        // LookupsRa config from one_hot
        uint256 raVirtLogKChunk = vm.parseJsonUint(json, ".one_hot_config.lookups_ra_virtual_log_k_chunk");
        uint256 logKInstr = 128; // LOG_K = XLEN * 2 = 64 * 2
        d.nVirtualRaPolys = logKInstr / raVirtLogKChunk;
        d.nCommittedPerVirtual = raVirtLogKChunk / d.logKChunk;
        d.nCommittedRaPolys = d.nVirtualRaPolys * d.nCommittedPerVirtual;
        d.lookupsRaInputClaims = new uint256[](d.nVirtualRaPolys);
    }

    function test_verifyStage6_algebraic() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);

        // Replay stages 1-5
        _replayStage1Transcript(t, json);
        _replayStage2Transcript(t, json);
        {
            t.challengeScalarPowers(5);
            t.challengeScalar();
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[2]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[2]"),
                vm.parseJsonUintArray(json, ".flush_history[4]"));
        }
        {
            t.challengeScalar();
            t.appendLabeledBytes(bytes24(bytes19("ram_val_check_gamma")), 0, "");
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[3]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[3]"),
                vm.parseJsonUintArray(json, ".flush_history[5]"));
        }
        {
            t.challengeScalar();
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[4]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[4]"),
                vm.parseJsonUintArray(json, ".flush_history[6]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[5]")),
            "Transcript state after Stage 5 does not match Rust");

        Stage6TestData memory d = _parseStage6Data(t, json);

        (uint256 finalClaim, uint256[] memory challenges, uint256[] memory bc) =
            BatchedSumcheckVerifier.verify(d.compressedPolys, d.inputClaims, d.instanceNumRounds, d.maxDeg, t);

        uint256 batchedExpected = _stage6ExpectedOutput(d, challenges, bc);
        require(finalClaim == batchedExpected, "stage6: output claim mismatch");

        for (uint256 i = 0; i < d.flushedClaims.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), d.flushedClaims[i]);
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[6]")),
            "Transcript state after Stage 6 does not match Rust");
    }

    function _stage6ExpectedOutput(
        Stage6TestData memory d,
        uint256[] memory challenges,
        uint256[] memory bc
    ) internal pure returns (uint256 batchedExpected) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256 bytecodeRounds = d.logKBytecode + d.nCycleVars;

        // Precompute bytecode gamma powers [0..7]
        uint256[8] memory bcGP;
        bcGP[0] = 1;
        for (uint256 i = 1; i < 8; i++) bcGP[i] = mulmod(bcGP[i - 1], d.bytecodeGammaBase, R_);

        uint256 claimIdx;

        // [0] BytecodeReadRaf
        {
            uint256 logK = d.logKBytecode;
            uint256[] memory rAddrPrime = new uint256[](logK);
            for (uint256 i = 0; i < logK; i++) rAddrPrime[i] = challenges[logK - 1 - i];

            uint256[] memory rCyclePrime = new uint256[](d.nCycleVars);
            for (uint256 i = 0; i < d.nCycleVars; i++) {
                rCyclePrime[i] = challenges[logK + d.nCycleVars - 1 - i];
            }

            uint256 valAndEntry = _bytecodeValAndEntryTest(bcGP, d, rAddrPrime, rCyclePrime);

            uint256 raProduct = 1;
            for (uint256 i = 0; i < d.bytecodeD; i++) {
                raProduct = mulmod(raProduct, d.flushedClaims[i], R_);
            }

            batchedExpected = mulmod(mulmod(valAndEntry, raProduct, R_), bc[0], R_);
            claimIdx = d.bytecodeD;
        }

        // [1] Booleanity
        {
            uint256 totalD = d.instructionD + d.bytecodeD + d.ramD;
            uint256 boolRounds = d.logKChunk + d.nCycleVars;
            uint256 boolOffset = bytecodeRounds - boolRounds;

            // Booleanity uses eq(challenges, [r_addr_BE, r_cycle_BE]) with direct pairing.
            // Build the combined_r and challenges slice.
            uint256[] memory boolChallenges = new uint256[](boolRounds);
            for (uint256 i = 0; i < boolRounds; i++) boolChallenges[i] = challenges[boolOffset + i];
            uint256[] memory combinedR = new uint256[](boolRounds);
            for (uint256 i = 0; i < d.logKChunk; i++) combinedR[i] = d.rAddressBool[i];
            for (uint256 i = 0; i < d.nCycleVars; i++) combinedR[d.logKChunk + i] = d.rCycleBool[i];
            uint256 eqBool = EqPolynomial.mle(boolChallenges, combinedR);

            uint256 boolGammaSq = mulmod(d.boolGamma, d.boolGamma, R_);
            uint256 boolSum = 0;
            uint256 gamma2i = 1;
            for (uint256 i = 0; i < totalD; i++) {
                uint256 ra = d.flushedClaims[claimIdx + i];
                boolSum = addmod(boolSum, mulmod(gamma2i, addmod(mulmod(ra, ra, R_), R_ - ra, R_), R_), R_);
                gamma2i = mulmod(gamma2i, boolGammaSq, R_);
            }

            batchedExpected = addmod(batchedExpected, mulmod(mulmod(eqBool, boolSum, R_), bc[1], R_), R_);
            claimIdx += totalD;
        }

        // [2] HammingBooleanity
        {
            uint256 hammingOffset = bytecodeRounds - d.nCycleVars;
            uint256 h = d.flushedClaims[claimIdx];
            batchedExpected = addmod(
                batchedExpected,
                mulmod(
                    mulmod(addmod(mulmod(h, h, R_), R_ - h, R_), EqPolynomial.mleSliceReversed(d.rCycleHamming, challenges, hammingOffset, d.nCycleVars), R_),
                    bc[2], R_
                ),
                R_
            );
            claimIdx += 1;
        }

        // [3] RamRaVirtual
        {
            uint256 ramRaOffset = bytecodeRounds - d.nCycleVars;
            uint256 raProduct = 1;
            for (uint256 i = 0; i < d.ramD; i++) {
                raProduct = mulmod(raProduct, d.flushedClaims[claimIdx + i], R_);
            }
            batchedExpected = addmod(
                batchedExpected,
                mulmod(mulmod(EqPolynomial.mleSliceReversed(d.rCycleRamRa, challenges, ramRaOffset, d.nCycleVars), raProduct, R_), bc[3], R_),
                R_
            );
            claimIdx += d.ramD;
        }

        // [4] LookupsRaVirtual
        {
            uint256 lookupOffset = bytecodeRounds - d.nCycleVars;
            uint256 eqL = EqPolynomial.mleSliceReversed(d.rCycleLookupsRa, challenges, lookupOffset, d.nCycleVars);
            uint256 m = d.nCommittedPerVirtual;

            uint256 raAcc = 0;
            uint256 gPow = 1;
            for (uint256 i = 0; i < d.nVirtualRaPolys; i++) {
                uint256 prod = 1;
                for (uint256 j = 0; j < m; j++) {
                    prod = mulmod(prod, d.flushedClaims[claimIdx + i * m + j], R_);
                }
                raAcc = addmod(raAcc, mulmod(gPow, prod, R_), R_);
                gPow = mulmod(gPow, d.lookupsRaGammaBase, R_);
            }

            batchedExpected = addmod(batchedExpected, mulmod(mulmod(eqL, raAcc, R_), bc[4], R_), R_);
            claimIdx += d.nCommittedRaPolys;
        }

        // [5] IncClaimReduction
        {
            uint256 incOffset = bytecodeRounds - d.nCycleVars;
            uint256 incGammaSqr = mulmod(d.incGamma, d.incGamma, R_);

            uint256 eqRam = addmod(
                EqPolynomial.mleSliceReversed(d.rCycleIncStage2, challenges, incOffset, d.nCycleVars),
                mulmod(d.incGamma, EqPolynomial.mleSliceReversed(d.rCycleIncStage4, challenges, incOffset, d.nCycleVars), R_),
                R_
            );
            uint256 eqRd = addmod(
                EqPolynomial.mleSliceReversed(d.sCycleIncStage4, challenges, incOffset, d.nCycleVars),
                mulmod(d.incGamma, EqPolynomial.mleSliceReversed(d.sCycleIncStage5, challenges, incOffset, d.nCycleVars), R_),
                R_
            );

            batchedExpected = addmod(
                batchedExpected,
                mulmod(
                    addmod(
                        mulmod(d.flushedClaims[claimIdx], eqRam, R_),
                        mulmod(incGammaSqr, mulmod(d.flushedClaims[claimIdx + 1], eqRd, R_), R_),
                        R_
                    ),
                    bc[5], R_
                ),
                R_
            );
        }
    }

    function _bytecodeValAndEntryTest(
        uint256[8] memory bcGP,
        Stage6TestData memory d,
        uint256[] memory rAddrPrime,
        uint256[] memory rCyclePrime
    ) internal pure returns (uint256) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

        // Identity poly eval at rAddrPrime
        uint256 intPolyEval = 0;
        for (uint256 i = 0; i < d.logKBytecode; i++) {
            intPolyEval = addmod(mulmod(intPolyEval, 2, R_), rAddrPrime[i], R_);
        }

        // Val + RAF: Σ_s γ^s * (val_s + raf_s*int) * eq(r_cycle_s, r_cycle_prime)
        uint256 valContrib = 0;
        for (uint256 s = 0; s < 5; s++) {
            uint256 rafWeight = 0;
            if (s == 0) rafWeight = bcGP[5];
            else if (s == 2) rafWeight = bcGP[4];

            uint256 valPlusRaf = addmod(d.valPolyEvals[s], mulmod(rafWeight, intPolyEval, R_), R_);

            uint256[] memory rCycleS = new uint256[](d.nCycleVars);
            for (uint256 j = 0; j < d.nCycleVars; j++) {
                rCycleS[j] = d.rCycles[s * d.nCycleVars + j];
            }

            valContrib = addmod(
                valContrib,
                mulmod(bcGP[s], mulmod(valPlusRaf, EqPolynomial.mle(rCycleS, rCyclePrime), R_), R_),
                R_
            );
        }

        // Entry constraint: γ^7 * eq(entry_bits, r_addr) * eq_zero(r_cycle)
        uint256 logK = d.logKBytecode;
        uint256[] memory entryBits = new uint256[](logK);
        uint256 e = d.entryBytecodeIndex;
        for (uint256 i = 0; i < logK; i++) {
            entryBits[i] = (e >> (logK - 1 - i)) & 1;
        }

        // eq_zero(r_cycle) = Π_i (1 - r_i)
        uint256 eqZero = 1;
        for (uint256 i = 0; i < rCyclePrime.length; i++) {
            eqZero = mulmod(eqZero, addmod(1, R_ - rCyclePrime[i], R_), R_);
        }

        return addmod(
            valContrib,
            mulmod(bcGP[7], mulmod(EqPolynomial.mle(entryBits, rAddrPrime), eqZero, R_), R_),
            R_
        );
    }

    // ================================================================
    //  Stage 2 Algebraic Verification
    // ================================================================

    struct Stage2TestData {
        uint256 nCycleVars;
        uint256 logK;
        uint256 phase1Rounds;
        uint256 phase2Rounds;
        uint256 tauHigh;
        uint256 r0;
        uint256 ramRwGamma;
        uint256 instrGamma;
        uint256[] rAddressStage2;
        uint256[] rCycleStage1;
        uint256[] rSpartan;
        uint256 unmapEval;
        uint256 ioMaskEval;
        uint256 valIoEval;
        uint256[][] compressedPolys;
        uint256[] flushedClaims;
        uint256[] inputClaims;
        uint256[] instanceNumRounds;
    }

    function test_verifyStage2_algebraic() public view {
        string memory json = vm.readFile(PROOF_PATH);
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);
        _replayStage1Transcript(t, json);
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[1]")));

        Stage2TestData memory d = _parseAndSetupStage2(t, json);

        (uint256 finalClaim, uint256[] memory challenges, uint256[] memory bc) =
            BatchedSumcheckVerifier.verify(d.compressedPolys, d.inputClaims, d.instanceNumRounds, 3, t);

        uint256 batchedExpected = _stage2ExpectedOutput(d, challenges, bc);
        require(finalClaim == batchedExpected, "stage2: output claim mismatch");

        for (uint256 i = 0; i < d.flushedClaims.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), d.flushedClaims[i]);
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[2]")),
            "Transcript state after Stage 2 does not match Rust");
    }

    function _parseAndSetupStage2(
        JoltTranscript.Transcript memory t,
        string memory json
    ) internal view returns (Stage2TestData memory d) {
        d.nCycleVars = _log2(uint64(vm.parseJsonUint(json, ".trace_length")));
        d.logK = _log2(uint64(vm.parseJsonUint(json, ".ram_k")));
        d.phase1Rounds = vm.parseJsonUint(json, ".rw_config.ram_rw_phase1_num_rounds");
        d.phase2Rounds = vm.parseJsonUint(json, ".rw_config.ram_rw_phase2_num_rounds");

        d.tauHigh = t.challengeScalarMont();
        uint256[] memory uniSkipCoeffs = vm.parseJsonUintArray(json, ".uniskip_polys[1]");
        t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), uniSkipCoeffs);
        d.r0 = t.challengeScalarMont();
        uint256[] memory uniFlush = vm.parseJsonUintArray(json, ".flush_history[2]");
        for (uint256 i = 0; i < uniFlush.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniFlush[i]);
        }
        d.ramRwGamma = t.challengeScalar();
        d.instrGamma = t.challengeScalar();
        d.rAddressStage2 = t.challengeVectorMont(d.logK);

        d.inputClaims = vm.parseJsonUintArray(json, ".sumcheck_input_claims[1]");
        d.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[1]");
        d.flushedClaims = vm.parseJsonUintArray(json, ".flush_history[3]");
        d.instanceNumRounds = vm.parseJsonUintArray(json, ".stage_instance_configs[1].num_rounds");

        string memory base = ".stage_intermediate_values[1].";
        d.unmapEval = vm.parseJsonUint(json, string(abi.encodePacked(base, "unmapEval")));
        d.ioMaskEval = vm.parseJsonUint(json, string(abi.encodePacked(base, "ioMaskEval")));
        d.valIoEval = vm.parseJsonUint(json, string(abi.encodePacked(base, "valIoEval")));

        // rCycleStage1 = reversed(stage1_challenges[1:])
        uint256[] memory s1c = vm.parseJsonUintArray(json, ".stage_challenges[0]");
        d.rCycleStage1 = new uint256[](d.nCycleVars);
        for (uint256 i = 0; i < d.nCycleVars; i++) {
            d.rCycleStage1[i] = s1c[s1c.length - 1 - i];
        }
        d.rSpartan = _parseIndexedPoints(json, ".stage_intermediate_values[2]", "rOuter_", d.nCycleVars);
    }

    function _stage2ExpectedOutput(
        Stage2TestData memory d,
        uint256[] memory challenges,
        uint256[] memory bc
    ) internal view returns (uint256 batchedExpected) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256[] memory fc = d.flushedClaims;

        // Instance [0]: RamReadWriteChecking
        {
            uint256[] memory rCycleOutput = _extractCyclePoint3Phase(challenges, d.phase1Rounds, d.phase2Rounds, d.nCycleVars);
            uint256 eqCycle = EqPolynomial.mle(d.rCycleStage1, rCycleOutput);
            uint256 inner = addmod(fc[0], mulmod(d.ramRwGamma, addmod(fc[0], fc[2], R_), R_), R_);
            batchedExpected = mulmod(mulmod(eqCycle, mulmod(fc[1], inner, R_), R_), bc[0], R_);
        }

        // Instance [1]: ProductVirtualRemainder
        batchedExpected = addmod(batchedExpected,
            _stage2ProductVirtExpected(d, challenges, bc[1]), R_);

        // Instance [2]: InstructionLookupsClaimReduction
        batchedExpected = addmod(batchedExpected,
            _stage2InstrCRExpected(d, challenges, bc[2]), R_);

        // Instance [3]: RamRafEvaluation
        batchedExpected = addmod(batchedExpected,
            mulmod(mulmod(d.unmapEval, fc[13], R_), bc[3], R_), R_);

        // Instance [4]: OutputSumcheck
        batchedExpected = addmod(batchedExpected,
            _stage2OutputExpected(d, challenges, bc[4]), R_);
    }

    function _stage2ProductVirtExpected(
        Stage2TestData memory d,
        uint256[] memory challenges,
        uint256 bc1
    ) internal view returns (uint256) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256[] memory fc = d.flushedClaims;

        uint256 tauKernel = UniSkipVerifier.lagrangeKernel3(d.tauHigh, d.r0);
        uint256[3] memory w = UniSkipVerifier.lagrangeEvals3(d.r0);
        uint256 offset1 = challenges.length - d.nCycleVars;
        uint256 eqTauR = EqPolynomial.mleSliceReversed(d.rCycleStage1, challenges, offset1, d.nCycleVars);

        uint256 fusedLeft = addmod(addmod(mulmod(w[0], fc[3], R_), mulmod(w[1], fc[7], R_), R_), mulmod(w[2], fc[5], R_), R_);
        uint256 fusedRight = addmod(addmod(mulmod(w[0], fc[4], R_), mulmod(w[1], fc[8], R_), R_), mulmod(w[2], addmod(1, R_ - fc[9], R_), R_), R_);

        return mulmod(mulmod(mulmod(tauKernel, eqTauR, R_), mulmod(fusedLeft, fusedRight, R_), R_), bc1, R_);
    }

    function _stage2InstrCRExpected(
        Stage2TestData memory d,
        uint256[] memory challenges,
        uint256 bc2
    ) internal view returns (uint256) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256[] memory fc = d.flushedClaims;
        uint256 offset2 = challenges.length - d.nCycleVars;
        uint256 eqSpartan = EqPolynomial.mleSliceReversed(d.rSpartan, challenges, offset2, d.nCycleVars);

        uint256 g = d.instrGamma;
        uint256 bo = fc[7];
        bo = addmod(bo, mulmod(g, fc[11], R_), R_); g = mulmod(g, d.instrGamma, R_);
        bo = addmod(bo, mulmod(g, fc[12], R_), R_); g = mulmod(g, d.instrGamma, R_);
        bo = addmod(bo, mulmod(g, fc[3], R_), R_); g = mulmod(g, d.instrGamma, R_);
        bo = addmod(bo, mulmod(g, fc[4], R_), R_);

        return mulmod(mulmod(eqSpartan, bo, R_), bc2, R_);
    }

    function _stage2OutputExpected(
        Stage2TestData memory d,
        uint256[] memory challenges,
        uint256 bc4
    ) internal view returns (uint256) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256 outputRounds = d.instanceNumRounds[4];
        uint256 offset4 = challenges.length - outputRounds;
        uint256 eqAddr = EqPolynomial.mleSliceReversed(d.rAddressStage2, challenges, offset4, outputRounds);
        uint256 valDiff = addmod(d.flushedClaims[14], R_ - d.valIoEval, R_);
        return mulmod(mulmod(eqAddr, mulmod(d.ioMaskEval, valDiff, R_), R_), bc4, R_);
    }


    /// @notice Helper: parse indexed points (e.g., "rOuter_0", "rOuter_1", ...) from JSON.
    function _parseIndexedPoints(
        string memory json,
        string memory basePath,
        string memory prefix,
        uint256 count
    ) internal view returns (uint256[] memory result) {
        result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            string memory key = string(abi.encodePacked(basePath, ".", prefix, vm.toString(i)));
            result[i] = vm.parseJsonUint(json, key);
        }
    }

    /// @notice Helper: reverse an array.
    function _reverse(uint256[] memory arr) internal pure returns (uint256[] memory result) {
        result = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            result[i] = arr[arr.length - 1 - i];
        }
    }

    // ================================================================
    //  Full Verify E2E Test
    // ================================================================

    /// @notice Compute r_address via shadow transcript at Stage 1 boundary.
    function _computeRAddressStage2(string memory json) internal view returns (uint256[] memory) {
        JoltTranscript.Transcript memory t;
        t.state = vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[1]"));
        t.nRounds = uint32(vm.parseJsonUint(json, ".transcript_n_rounds[1]"));
        t.challengeScalarMont(); // tauHigh
        t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), vm.parseJsonUintArray(json, ".uniskip_polys[1]"));
        t.challengeScalarMont(); // r0
        uint256[] memory uniFlush = vm.parseJsonUintArray(json, ".flush_history[2]");
        for (uint256 i = 0; i < uniFlush.length; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniFlush[i]);
        }
        t.challengeScalar(); // ramRwGamma
        t.challengeScalar(); // instrGamma
        return t.challengeVectorMont(_log2(uint64(vm.parseJsonUint(json, ".ram_k"))));
    }

    /// @notice Compute UniSkip domain sum over {-1, 0, 1} for product virtualization.
    function _productUniSkipDomainSum(uint256[] memory coeffs) internal pure returns (uint256) {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        return addmod(addmod(_evalPolyAtInt(coeffs, -1), _evalPolyAtInt(coeffs, 0), R_),
            _evalPolyAtInt(coeffs, 1), R_);
    }

    function _fillE2EStage1(
        JoltTypes.JoltOnChainProof memory proof, string memory json, uint256 nCycleVars
    ) internal view {
        proof.stage1Proof.uniSkipCoeffs = vm.parseJsonUintArray(json, ".uniskip_polys[0]");
        proof.stage1Proof.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[0]");
        {
            uint256[] memory fc = vm.parseJsonUintArray(json, ".flush_history[1]");
            for (uint256 i = 0; i < 35; i++) proof.stage1Proof.r1csInputEvals[i] = fc[i];
        }
        proof.stage1Inputs.numRowsBits = vm.parseJsonUint(json, ".num_rows_bits");
        proof.stage1Inputs.nCycleVars = nCycleVars;
    }

    function _fillE2EStage2(
        JoltTypes.JoltOnChainProof memory proof, string memory json, uint256 nCycleVars
    ) internal view {
        proof.stage2Proof.uniSkipCoeffs = vm.parseJsonUintArray(json, ".uniskip_polys[1]");
        proof.stage2Proof.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[1]");
        {
            uint256[] memory fc = vm.parseJsonUintArray(json, ".flush_history[3]");
            for (uint256 i = 0; i < 15; i++) proof.stage2Proof.flushedClaims[i] = fc[i];
        }
        proof.stage2Inputs.nCycleVars = nCycleVars;
        proof.stage2Inputs.logK = _log2(uint64(vm.parseJsonUint(json, ".ram_k")));
        proof.stage2Inputs.uniSkipInputClaim = _productUniSkipDomainSum(
            vm.parseJsonUintArray(json, ".uniskip_polys[1]"));
        {
            uint256[] memory ic = vm.parseJsonUintArray(json, ".sumcheck_input_claims[1]");
            uint256[] memory nr = vm.parseJsonUintArray(json, ".stage_instance_configs[1].num_rounds");
            for (uint256 i = 0; i < 5; i++) {
                proof.stage2Inputs.instanceInputClaims[i] = ic[i];
                proof.stage2Inputs.instanceNumRounds[i] = nr[i];
            }
        }
        proof.stage2Inputs.maxDegree = vm.parseJsonUint(json, ".stage_instance_configs[1].max_degree");
        {
            uint256[] memory s1c = vm.parseJsonUintArray(json, ".stage_challenges[0]");
            proof.stage2Inputs.rCycleStage1 = new uint256[](nCycleVars);
            for (uint256 i = 0; i < nCycleVars; i++) {
                proof.stage2Inputs.rCycleStage1[i] = s1c[s1c.length - 1 - i];
            }
        }
        proof.stage2Inputs.rSpartan = _parseIndexedPoints(json, ".stage_intermediate_values[2]", "rOuter_", nCycleVars);
        proof.stage2Inputs.ramRwPhase1Rounds = vm.parseJsonUint(json, ".rw_config.ram_rw_phase1_num_rounds");
        proof.stage2Inputs.ramRwPhase2Rounds = vm.parseJsonUint(json, ".rw_config.ram_rw_phase2_num_rounds");
        {
            string memory b = ".stage_intermediate_values[1].";
            proof.stage2Inputs.unmapEval = vm.parseJsonUint(json, string(abi.encodePacked(b, "unmapEval")));
            proof.stage2Inputs.ioMaskEval = vm.parseJsonUint(json, string(abi.encodePacked(b, "ioMaskEval")));
            proof.stage2Inputs.valIoEval = vm.parseJsonUint(json, string(abi.encodePacked(b, "valIoEval")));
        }
        proof.stage2Inputs.rAddressStage2 = _computeRAddressStage2(json);
    }

    function _fillE2EStage3(
        JoltTypes.JoltOnChainProof memory proof, string memory json, uint256 nCycleVars
    ) internal view {
        proof.stage3Proof.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[2]");
        {
            uint256[] memory fc = vm.parseJsonUintArray(json, ".flush_history[4]");
            for (uint256 i = 0; i < 13; i++) proof.stage3Proof.flushedClaims[i] = fc[i];
        }
        string memory b = ".stage_intermediate_values[2].";
        proof.stage3Inputs.nextUnexpandedPC = vm.parseJsonUint(json, string(abi.encodePacked(b, "nextUnexpandedPC")));
        proof.stage3Inputs.nextPC = vm.parseJsonUint(json, string(abi.encodePacked(b, "nextPC")));
        proof.stage3Inputs.nextIsVirtual = vm.parseJsonUint(json, string(abi.encodePacked(b, "nextIsVirtual")));
        proof.stage3Inputs.nextIsFirstInSeq = vm.parseJsonUint(json, string(abi.encodePacked(b, "nextIsFirstInSeq")));
        proof.stage3Inputs.nextIsNoop = vm.parseJsonUint(json, string(abi.encodePacked(b, "nextIsNoop")));
        proof.stage3Inputs.rightInstructionInput = vm.parseJsonUint(json, string(abi.encodePacked(b, "rightInstructionInput")));
        proof.stage3Inputs.leftInstructionInput = vm.parseJsonUint(json, string(abi.encodePacked(b, "leftInstructionInput")));
        proof.stage3Inputs.rdWriteValue = vm.parseJsonUint(json, string(abi.encodePacked(b, "rdWriteValue")));
        proof.stage3Inputs.rs1Value = vm.parseJsonUint(json, string(abi.encodePacked(b, "rs1Value")));
        proof.stage3Inputs.rs2Value = vm.parseJsonUint(json, string(abi.encodePacked(b, "rs2Value")));
        proof.stage3Inputs.rOuter = _parseIndexedPoints(json, ".stage_intermediate_values[2]", "rOuter_", nCycleVars);
        proof.stage3Inputs.rProduct = _parseIndexedPoints(json, ".stage_intermediate_values[2]", "rProduct_", nCycleVars);
        proof.stage3Inputs.rCycleStage2 = proof.stage3Inputs.rProduct;
        proof.stage3Inputs.rSpartan = proof.stage3Inputs.rOuter;
    }

    function _fillE2EStage4(
        JoltTypes.JoltOnChainProof memory proof, string memory json, uint256 nCycleVars
    ) internal view {
        proof.stage4Proof.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[3]");
        {
            uint256[] memory fc = vm.parseJsonUintArray(json, ".flush_history[5]");
            for (uint256 i = 0; i < 7; i++) proof.stage4Proof.flushedClaims[i] = fc[i];
        }
        string memory b = ".stage_intermediate_values[3].";
        proof.stage4Inputs.rdWriteValue = vm.parseJsonUint(json, string(abi.encodePacked(b, "rdWriteValue")));
        proof.stage4Inputs.rs1Value = vm.parseJsonUint(json, string(abi.encodePacked(b, "rs1Value")));
        proof.stage4Inputs.rs2Value = vm.parseJsonUint(json, string(abi.encodePacked(b, "rs2Value")));
        proof.stage4Inputs.ramVal = vm.parseJsonUint(json, string(abi.encodePacked(b, "ramVal")));
        proof.stage4Inputs.ramValFinal = vm.parseJsonUint(json, string(abi.encodePacked(b, "ramValFinal")));
        proof.stage4Inputs.initEval = vm.parseJsonUint(json, string(abi.encodePacked(b, "initEval")));
        proof.stage4Inputs.rCycleStage3 = _parseIndexedPoints(json, ".stage_intermediate_values[3]", "rCycleStage3_", nCycleVars);
        proof.stage4Inputs.rCycleStage2Ram = _parseIndexedPoints(json, ".stage_intermediate_values[3]", "rCycleStage2Ram_", nCycleVars);
        proof.stage4Inputs.regPhase1Rounds = vm.parseJsonUint(json, ".rw_config.registers_rw_phase1_num_rounds");
        proof.stage4Inputs.regPhase2Rounds = vm.parseJsonUint(json, ".rw_config.registers_rw_phase2_num_rounds");
    }

    function _fillE2EStage5(
        JoltTypes.JoltOnChainProof memory proof, string memory json, uint256 nCycleVars
    ) internal view {
        proof.stage5Proof.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[4]");
        proof.stage5Proof.flushedClaims = vm.parseJsonUintArray(json, ".flush_history[6]");
        string memory b = ".stage_intermediate_values[4]";
        proof.stage5Inputs.lookupOutput = vm.parseJsonUint(json, string(abi.encodePacked(b, ".lookupOutput")));
        proof.stage5Inputs.leftOperand = vm.parseJsonUint(json, string(abi.encodePacked(b, ".leftOperand")));
        proof.stage5Inputs.rightOperand = vm.parseJsonUint(json, string(abi.encodePacked(b, ".rightOperand")));
        proof.stage5Inputs.leftOperandEval = vm.parseJsonUint(json, string(abi.encodePacked(b, ".leftOperandEval")));
        proof.stage5Inputs.rightOperandEval = vm.parseJsonUint(json, string(abi.encodePacked(b, ".rightOperandEval")));
        proof.stage5Inputs.identityEval = vm.parseJsonUint(json, string(abi.encodePacked(b, ".identityEval")));
        proof.stage5Inputs.claimRaf = vm.parseJsonUint(json, string(abi.encodePacked(b, ".claimRaf")));
        proof.stage5Inputs.claimRw = vm.parseJsonUint(json, string(abi.encodePacked(b, ".claimRw")));
        proof.stage5Inputs.claimVal = vm.parseJsonUint(json, string(abi.encodePacked(b, ".claimVal")));
        proof.stage5Inputs.registersVal = vm.parseJsonUint(json, string(abi.encodePacked(b, ".registersVal")));
        proof.stage5Inputs.nTables = 40;
        proof.stage5Inputs.nRaChunks = 8;
        proof.stage5Inputs.logKInstr = 128;
        proof.stage5Inputs.valEvals = new uint256[](40);
        for (uint256 i = 0; i < 40; i++) {
            proof.stage5Inputs.valEvals[i] = vm.parseJsonUint(json,
                string(abi.encodePacked(b, ".valEval_", vm.toString(i))));
        }
        proof.stage5Inputs.rReduction = _parseIndexedPoints(json, b, "rReduction_", nCycleVars);
        proof.stage5Inputs.rCycleRaf = _parseIndexedPoints(json, b, "rCycleRaf_", nCycleVars);
        proof.stage5Inputs.rCycleRw = _parseIndexedPoints(json, b, "rCycleRw_", nCycleVars);
        proof.stage5Inputs.rCycleVal = _parseIndexedPoints(json, b, "rCycleVal_", nCycleVars);
        proof.stage5Inputs.rCycleStage4Reg = _parseIndexedPoints(json, b, "rCycleStage4Reg_", nCycleVars);
    }

    function _fillE2EStage6(
        JoltTypes.JoltOnChainProof memory proof, string memory json, uint256 nCycleVars
    ) internal view {
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        proof.stage6Proof.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[5]");
        proof.stage6Proof.flushedClaims = vm.parseJsonUintArray(json, ".flush_history[7]");
        string memory b = ".stage_intermediate_values[5]";

        // Config from one_hot_config
        proof.stage6Inputs.logKBytecode = _log2(uint64(vm.parseJsonUint(json, ".one_hot_config.bytecode_k")));
        proof.stage6Inputs.bytecodeD = vm.parseJsonUint(json, ".one_hot_config.bytecode_d");
        proof.stage6Inputs.ramD = vm.parseJsonUint(json, ".one_hot_config.ram_d");
        proof.stage6Inputs.logKChunk = vm.parseJsonUint(json, ".one_hot_config.log_k_chunk");
        proof.stage6Inputs.totalD = vm.parseJsonUint(json, ".one_hot_config.instruction_d")
            + proof.stage6Inputs.bytecodeD + proof.stage6Inputs.ramD;

        uint256 raVirtLogKChunk = vm.parseJsonUint(json, ".one_hot_config.lookups_ra_virtual_log_k_chunk");
        proof.stage6Inputs.nVirtualRaPolys = 128 / raVirtLogKChunk;
        proof.stage6Inputs.nCommittedPerVirtual = raVirtLogKChunk / proof.stage6Inputs.logKChunk;
        proof.stage6Inputs.nCommittedRaPolys = proof.stage6Inputs.nVirtualRaPolys
            * proof.stage6Inputs.nCommittedPerVirtual;

        // BytecodeReadRaf input claim
        {
            uint256[] memory s6ic = vm.parseJsonUintArray(json, ".sumcheck_input_claims[5]");
            proof.stage6Inputs.bytecodeInputClaim = s6ic[0];
        }
        for (uint256 i = 0; i < 5; i++) {
            proof.stage6Inputs.valPolyEvals[i] = vm.parseJsonUint(json,
                string(abi.encodePacked(b, ".valPolyEval_", vm.toString(i))));
        }
        proof.stage6Inputs.entryBytecodeIndex = vm.parseJsonUint(json,
            string(abi.encodePacked(b, ".entryBytecodeIndex")));

        // 5 cycle reference points (flattened: 5 * nCycleVars)
        proof.stage6Inputs.rCycles = new uint256[](5 * nCycleVars);
        for (uint256 s = 0; s < 5; s++) {
            string memory prefix = string(abi.encodePacked("rCycle", vm.toString(s + 1), "_"));
            for (uint256 j = 0; j < nCycleVars; j++) {
                proof.stage6Inputs.rCycles[s * nCycleVars + j] = vm.parseJsonUint(json,
                    string(abi.encodePacked(b, ".", prefix, vm.toString(j))));
            }
        }

        // Reference points
        proof.stage6Inputs.rCycleHamming = _parseIndexedPoints(json, b, "rCycleHamming_", nCycleVars);
        proof.stage6Inputs.rAddressBool = _parseIndexedPoints(json, b, "rAddressBool_", proof.stage6Inputs.logKChunk);
        proof.stage6Inputs.rCycleBool = _parseIndexedPoints(json, b, "rCycleBool_", nCycleVars);
        proof.stage6Inputs.rCycleRamRa = _parseIndexedPoints(json, b, "rCycleRamRa_", nCycleVars);
        proof.stage6Inputs.rCycleLookupsRa = _parseIndexedPoints(json, b, "rCycleLookupsRa_", nCycleVars);
        proof.stage6Inputs.ramRaInputClaim = vm.parseJsonUint(json, string(abi.encodePacked(b, ".ramRaInputClaim")));

        // LookupsRa input claims: virtual RA evaluations from Stage 5 flush
        // Stage 5 flushes: 40 table evals + 8 virtual RA evals + RAF + RamRa + 2 RegVal
        {
            uint256[] memory s5Flush = vm.parseJsonUintArray(json, ".flush_history[6]");
            uint256 nVirt = proof.stage6Inputs.nVirtualRaPolys;
            proof.stage6Inputs.lookupsRaInputClaims = new uint256[](nVirt);
            for (uint256 i = 0; i < nVirt; i++) {
                proof.stage6Inputs.lookupsRaInputClaims[i] = s5Flush[40 + i];
            }
        }

        // Inc values
        proof.stage6Inputs.incV1 = vm.parseJsonUint(json, string(abi.encodePacked(b, ".incV1")));
        proof.stage6Inputs.incV2 = vm.parseJsonUint(json, string(abi.encodePacked(b, ".incV2")));
        proof.stage6Inputs.incW1 = vm.parseJsonUint(json, string(abi.encodePacked(b, ".incW1")));
        proof.stage6Inputs.incW2 = vm.parseJsonUint(json, string(abi.encodePacked(b, ".incW2")));
        proof.stage6Inputs.rCycleIncStage2 = _parseIndexedPoints(json, b, "rCycleIncStage2_", nCycleVars);
        proof.stage6Inputs.rCycleIncStage4 = _parseIndexedPoints(json, b, "rCycleIncStage4_", nCycleVars);
        proof.stage6Inputs.sCycleIncStage4 = _parseIndexedPoints(json, b, "sCycleIncStage4_", nCycleVars);
        proof.stage6Inputs.sCycleIncStage5 = _parseIndexedPoints(json, b, "sCycleIncStage5_", nCycleVars);
    }

    function _fillE2EStage7(
        JoltTypes.JoltOnChainProof memory proof, string memory json
    ) internal view {
        proof.stage7Proof.compressedPolys = _parseNestedUintArray(json, ".stage_compressed_polys[6]");
        proof.stage7Proof.flushedClaims = vm.parseJsonUintArray(json, ".flush_history[8]");
        uint256 N = proof.stage7Proof.flushedClaims.length;
        proof.stage7Inputs.logKChunk = vm.parseJsonUint(json, ".one_hot_config.log_k_chunk");
        proof.stage7Inputs.nPolynomials = N;
        string memory b = ".stage_intermediate_values[6]";
        proof.stage7Inputs.hwClaims = new uint256[](N);
        proof.stage7Inputs.boolClaims = new uint256[](N);
        proof.stage7Inputs.virtClaims = new uint256[](N);
        for (uint256 i = 0; i < N; i++) {
            proof.stage7Inputs.hwClaims[i] = vm.parseJsonUint(json,
                string(abi.encodePacked(b, ".hwClaim_", vm.toString(i))));
            proof.stage7Inputs.boolClaims[i] = vm.parseJsonUint(json,
                string(abi.encodePacked(b, ".boolClaim_", vm.toString(i))));
            proof.stage7Inputs.virtClaims[i] = vm.parseJsonUint(json,
                string(abi.encodePacked(b, ".virtClaim_", vm.toString(i))));
        }
        proof.stage7Inputs.rAddrBool = _parseIndexedPoints(json, b, "rAddrBool_", proof.stage7Inputs.logKChunk);
        proof.stage7Inputs.rAddrVirt = new uint256[][](N);
        for (uint256 i = 0; i < N; i++) {
            proof.stage7Inputs.rAddrVirt[i] = _parseIndexedPoints(json, b,
                string(abi.encodePacked("rAddrVirt_", vm.toString(i), "_")),
                proof.stage7Inputs.logKChunk);
        }
    }

    /// @notice Full end-to-end test: construct JoltOnChainProof from JSON and call verify().
    /// Stages 1-7 are algebraically verified. Stage 8 (Dory/Groth16) is mocked.
    function _loadDoryCommitment(
        JoltTypes.JoltOnChainProof memory proof,
        string memory json
    ) internal pure {
        for (uint256 i = 0; i < 12; i++) {
            string memory path = string.concat(
                ".dory_witness.commitment_karabina[",
                vm.toString(i),
                "]"
            );
            proof.doryCommitment[i] = vm.parseJsonUint(json, path);
        }
    }

    function _packDoryMessages(string memory json) internal pure returns (bytes memory blob, bytes memory lengths) {
        bytes[] memory msgs = vm.parseJsonBytesArray(json, ".dory_witness.transcript_messages");
        uint256 totalLen = 0;
        for (uint256 i = 0; i < msgs.length; i++) {
            totalLen += msgs[i].length;
        }
        blob = new bytes(totalLen);
        lengths = new bytes(msgs.length * 2);
        uint256 offset = 0;
        for (uint256 i = 0; i < msgs.length; i++) {
            uint256 len = msgs[i].length;
            // Pack length as big-endian uint16
            lengths[i * 2] = bytes1(uint8(len >> 8));
            lengths[i * 2 + 1] = bytes1(uint8(len));
            // Copy message data
            for (uint256 j = 0; j < len; j++) {
                blob[offset + j] = msgs[i][j];
            }
            offset += len;
        }
    }

    function _fillStage8(
        JoltTypes.JoltOnChainProof memory proof,
        string memory json,
        string memory groth16Json
    ) internal pure {
        proof.committedClaims = vm.parseJsonUintArray(json, ".stage8_committed_claims");
        proof.scalingFactors = vm.parseJsonUintArray(json, ".stage8_scaling_factors");
        // Opening point for transcript operations (full point)
        proof.s1Coords = vm.parseJsonUintArray(json, ".stage8_opening_point");
        proof.s2Coords = new uint256[](0);
        // Dory-specific s1/s2 for verifyWithChallenges (sigma-length each)
        proof.dorys1Coords = vm.parseJsonUintArray(json, ".dory_witness.s1_coords");
        proof.dorys2Coords = vm.parseJsonUintArray(json, ".dory_witness.s2_coords");
        proof.doryNumRounds = vm.parseJsonUint(json, ".dory_witness.num_rounds");
        (proof.doryMessageBlob, proof.doryMessageLengths) = _packDoryMessages(json);

        proof.groth16Proof[0] = vm.parseJsonUint(groth16Json, ".proofA[0]");
        proof.groth16Proof[1] = vm.parseJsonUint(groth16Json, ".proofA[1]");
        proof.groth16Proof[2] = vm.parseJsonUint(groth16Json, ".proofB[0]");
        proof.groth16Proof[3] = vm.parseJsonUint(groth16Json, ".proofB[1]");
        proof.groth16Proof[4] = vm.parseJsonUint(groth16Json, ".proofB[2]");
        proof.groth16Proof[5] = vm.parseJsonUint(groth16Json, ".proofB[3]");
        proof.groth16Proof[6] = vm.parseJsonUint(groth16Json, ".proofC[0]");
        proof.groth16Proof[7] = vm.parseJsonUint(groth16Json, ".proofC[1]");

        proof.groth16Commitments[0] = vm.parseJsonUint(groth16Json, ".commitments[0]");
        proof.groth16Commitments[1] = vm.parseJsonUint(groth16Json, ".commitments[1]");

        proof.groth16CommitmentPok[0] = vm.parseJsonUint(groth16Json, ".commitmentPok[0]");
        proof.groth16CommitmentPok[1] = vm.parseJsonUint(groth16Json, ".commitmentPok[1]");
    }

    /// @notice Build a complete valid proof from JSON test data.
    function _buildValidProof() internal view returns (JoltTypes.JoltOnChainProof memory proof) {
        string memory json = vm.readFile(PROOF_PATH);
        string memory groth16Json = vm.readFile("testdata/jolt_groth16_proof.json");

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

    function _packCommitments(string memory json) internal pure returns (bytes memory blob, uint16 size) {
        bytes[] memory coms = vm.parseJsonBytesArray(json, ".commitment_bytes");
        if (coms.length == 0) return ("", 0);
        size = uint16(coms[0].length);
        blob = new bytes(coms.length * uint256(size));
        uint256 offset = 0;
        for (uint256 i = 0; i < coms.length; i++) {
            require(coms[i].length == uint256(size), "non-uniform commitment size");
            for (uint256 j = 0; j < uint256(size); j++) {
                blob[offset + j] = coms[i][j];
            }
            offset += uint256(size);
        }
    }

    /// @notice Full E2E: stages 1-7 algebraic + stage 8 Keccak transcript + Groth16 Dory.
    function test_e2e_fullVerifyWithGroth16() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();

        uint256 gasBefore = gasleft();
        verifier.verify(proof);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("verify() gas", gasUsed);
    }

    /// @notice Diagnostic: replay stages in-process, then call verifyStage6 with E2E data.
    function test_e2e_transcriptDiagnostic() public view {
        string memory json = vm.readFile(PROOF_PATH);
        uint256 nCycleVars = _log2(uint64(vm.parseJsonUint(json, ".trace_length")));

        // Build transcript from preamble+commitments (reuse existing helper)
        JoltTranscript.Transcript memory t = _replayPreambleAndCommitments(json);
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[0]")), "After preamble+commitments");

        // Stage 1 replay
        _replayStage1Transcript(t, json);
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[1]")), "After stage 1 replay");

        // Stage 2 replay
        _replayStage2Transcript(t, json);
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[2]")), "After stage 2 replay");

        // Stage 3: sample challenges + replay sumcheck
        {
            t.challengeScalarPowers(5);
            t.challengeScalar();
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[2]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[2]"),
                vm.parseJsonUintArray(json, ".flush_history[4]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[3]")), "After stage 3 replay");

        // Stage 4: sample challenges + replay sumcheck
        {
            t.challengeScalar();
            t.appendLabeledBytes(bytes24(bytes19("ram_val_check_gamma")), 0, "");
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[3]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[3]"),
                vm.parseJsonUintArray(json, ".flush_history[5]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[4]")), "After stage 4 replay");

        // Stage 5: sample challenges + replay sumcheck
        {
            t.challengeScalar();
            t.challengeScalar();
            _replaySumcheck(t, vm.parseJsonUintArray(json, ".sumcheck_input_claims[4]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[4]"),
                vm.parseJsonUintArray(json, ".flush_history[6]"));
        }
        assertEq(t.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[5]")), "After stage 5 replay");

        // Now try Stage 6 using verifyStage6 data loading path (from E2E fill helpers)
        // First parse Stage 6 inputs the same way the E2E test does
        JoltTypes.JoltOnChainProof memory proof;
        _fillE2EStage6(proof, json, nCycleVars);

        // Sample the 9 challenges that Stage 6 samples
        uint256 bytecodeGammaBase = t.challengeScalar();
        for (uint256 i = 0; i < 5; i++) t.challengeScalar();
        uint256 boolGamma = t.challengeScalarMont();
        uint256 lookupsRaGammaBase = t.challengeScalar();
        uint256 incGamma = t.challengeScalar();

        // Compute input claims (same as verifyStage6)
        uint256 R_ = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        uint256[] memory instanceClaims = new uint256[](6);
        instanceClaims[0] = proof.stage6Inputs.bytecodeInputClaim;
        instanceClaims[3] = proof.stage6Inputs.ramRaInputClaim;
        {
            uint256 claim = 0;
            uint256 gPow = 1;
            for (uint256 i = 0; i < proof.stage6Inputs.nVirtualRaPolys; i++) {
                claim = addmod(claim, mulmod(gPow, proof.stage6Inputs.lookupsRaInputClaims[i], R_), R_);
                gPow = mulmod(gPow, lookupsRaGammaBase, R_);
            }
            instanceClaims[4] = claim;
        }
        {
            uint256 incGammaSqr = mulmod(incGamma, incGamma, R_);
            uint256 incGammaCub = mulmod(incGammaSqr, incGamma, R_);
            instanceClaims[5] = addmod(
                addmod(proof.stage6Inputs.incV1, mulmod(incGamma, proof.stage6Inputs.incV2, R_), R_),
                addmod(mulmod(incGammaSqr, proof.stage6Inputs.incW1, R_), mulmod(incGammaCub, proof.stage6Inputs.incW2, R_), R_),
                R_
            );
        }

        // Compare with pre-computed input claims from JSON
        uint256[] memory expectedClaims = vm.parseJsonUintArray(json, ".sumcheck_input_claims[5]");
        for (uint256 i = 0; i < 6; i++) {
            assertEq(instanceClaims[i], expectedClaims[i], string(abi.encodePacked("Stage6 input claim ", vm.toString(i))));
        }

        // Now actually call verifyStage6 with the same data
        // Reset transcript to state before Stage 6 challenge sampling
        JoltTranscript.Transcript memory t2 = _replayPreambleAndCommitments(json);
        _replayStage1Transcript(t2, json);
        _replayStage2Transcript(t2, json);
        {
            t2.challengeScalarPowers(5);
            t2.challengeScalar();
            t2.challengeScalar();
            _replaySumcheck(t2, vm.parseJsonUintArray(json, ".sumcheck_input_claims[2]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[2]"),
                vm.parseJsonUintArray(json, ".flush_history[4]"));
        }
        {
            t2.challengeScalar();
            t2.appendLabeledBytes(bytes24(bytes19("ram_val_check_gamma")), 0, "");
            t2.challengeScalar();
            _replaySumcheck(t2, vm.parseJsonUintArray(json, ".sumcheck_input_claims[3]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[3]"),
                vm.parseJsonUintArray(json, ".flush_history[5]"));
        }
        {
            t2.challengeScalar();
            t2.challengeScalar();
            _replaySumcheck(t2, vm.parseJsonUintArray(json, ".sumcheck_input_claims[4]"),
                _parseNestedUintArray(json, ".stage_compressed_polys[4]"),
                vm.parseJsonUintArray(json, ".flush_history[6]"));
        }

        // Call verifyStage6 with the E2E-assembled data
        StageVerification.verifyStage6(t2, proof.stage6Proof, proof.stage6Inputs, nCycleVars);
        assertEq(t2.state, vm.parseBytes32(vm.parseJsonString(json, ".transcript_states[6]")), "After stage 6");
    }
}
