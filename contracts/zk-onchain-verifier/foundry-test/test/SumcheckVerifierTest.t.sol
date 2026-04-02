// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "contracts/JoltTranscript.sol";
import "contracts/SumcheckVerifier.sol";

contract SumcheckVerifierTest is Test {
    using JoltTranscript for JoltTranscript.Transcript;

    // ----------------------------------------------------------------
    //  Test: eval_from_hint matches Rust CompressedUniPoly::eval_from_hint
    // ----------------------------------------------------------------

    function test_evalFromHint_degree2() public pure {
        // Polynomial: p(x) = 5 + 3x + 2x^2
        // coeffs_except_linear = [5, 2]
        // hint = p(0) + p(1) = 5 + 10 = 15
        uint256[] memory coeffs = new uint256[](2);
        coeffs[0] = 5;
        coeffs[1] = 2;

        // Evaluate at x = 3
        // linear = 15 - 2*5 - 2 = 3
        // p(3) = 5 + 3*3 + 2*9 = 5 + 9 + 18 = 32
        uint256 result = SumcheckVerifier.evalFromHint(coeffs, 15, 3);
        assertEq(result, 32);
    }

    function test_evalFromHint_degree3() public pure {
        // Polynomial: p(x) = 1 + 2x + 3x^2 + 4x^3
        // coeffs_except_linear = [1, 3, 4]
        // hint = p(0) + p(1) = 1 + (1+2+3+4) = 11
        uint256[] memory coeffs = new uint256[](3);
        coeffs[0] = 1;
        coeffs[1] = 3;
        coeffs[2] = 4;

        // Evaluate at x = 2
        // linear = 11 - 2*1 - 3 - 4 = 2
        // p(2) = 1 + 2*2 + 3*4 + 4*8 = 1 + 4 + 12 + 32 = 49
        uint256 result = SumcheckVerifier.evalFromHint(coeffs, 11, 2);
        assertEq(result, 49);
    }

    // ----------------------------------------------------------------
    //  Test: Full 3-round sumcheck verification matches Rust test vectors
    // ----------------------------------------------------------------

    function test_sumcheckVerify() public pure {
        // 3-round sumcheck with degree-2 polynomials
        // From Rust test_sumcheck_verify_vectors:
        //   Round 0: coeffs = [5, 2]
        //   Round 1: coeffs = [7, 4]
        //   Round 2: coeffs = [3, 1]
        //   initial_claim = 15

        uint256[][] memory compressedPolys = new uint256[][](3);

        compressedPolys[0] = new uint256[](2);
        compressedPolys[0][0] = 5;
        compressedPolys[0][1] = 2;

        compressedPolys[1] = new uint256[](2);
        compressedPolys[1][0] = 7;
        compressedPolys[1][1] = 4;

        compressedPolys[2] = new uint256[](2);
        compressedPolys[2][0] = 3;
        compressedPolys[2][1] = 1;

        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("sumcheck_test");

        (uint256 finalClaim, uint256[] memory challenges) =
            SumcheckVerifier.verify(compressedPolys, 15, 3, 2, t);

        // Expected from Rust (challenge_scalar_optimized / MontU128Challenge):
        assertEq(
            challenges[0],
            0x282aff3e8e3dccf38fe8593296bff6ea23c77aac427d3938555fe7a8c3ee30f5,
            "challenge[0] mismatch"
        );
        assertEq(
            challenges[1],
            0x1459b42397c5bfc159730ac8bd9cee7bb53cda4ebcd6e056f8e84b5be78247da,
            "challenge[1] mismatch"
        );
        assertEq(
            challenges[2],
            0x1b355a22293fd576400111969e7df598485956dc3edd793f6cba4283b7694d3d,
            "challenge[2] mismatch"
        );

        assertEq(
            finalClaim,
            0x2b3bea281250cb07af7c855f0a43c9f7d394430c6d1c3f9e8be7d7a300462ff6,
            "final claim mismatch"
        );

        // Verify transcript state matches Rust
        assertEq(
            t.state,
            bytes32(0x294fb16e5c15ffdfe17b17d1d681cb68d95cbf19458d4053f8308af0b1f13c1e),
            "transcript state mismatch"
        );
        assertEq(t.nRounds, 12, "transcript nRounds mismatch");
    }

    // ----------------------------------------------------------------
    //  Test: Montgomery challenge scalar matches Rust
    // ----------------------------------------------------------------

    function test_challengeScalarMont() public pure {
        // From Rust test: transcript "sumcheck_test", after init
        // The verify function's first challenge (from round 0's appendScalars + challengeScalarMont)
        // should match challenges_fr[0]
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("sumcheck_test");

        // Append the first round's compressed poly coefficients
        uint256[] memory coeffs = new uint256[](2);
        coeffs[0] = 5;
        coeffs[1] = 2;

        // Label "sumcheck_poly" with count 2
        t.appendLabeledScalars(bytes24(bytes13("sumcheck_poly")), coeffs);

        // Derive Montgomery challenge
        uint256 challenge = t.challengeScalarMont();

        // Should match challenges_fr[0] from Rust
        assertEq(
            challenge,
            0x282aff3e8e3dccf38fe8593296bff6ea23c77aac427d3938555fe7a8c3ee30f5,
            "Montgomery challenge mismatch"
        );
    }

    // ----------------------------------------------------------------
    //  Test: Gas usage for sumcheck verification
    // ----------------------------------------------------------------

    function test_sumcheckGas() public {
        uint256[][] memory compressedPolys = new uint256[][](3);
        compressedPolys[0] = new uint256[](2);
        compressedPolys[0][0] = 5;
        compressedPolys[0][1] = 2;
        compressedPolys[1] = new uint256[](2);
        compressedPolys[1][0] = 7;
        compressedPolys[1][1] = 4;
        compressedPolys[2] = new uint256[](2);
        compressedPolys[2][0] = 3;
        compressedPolys[2][1] = 1;

        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("sumcheck_test");

        uint256 gasBefore = gasleft();
        SumcheckVerifier.verify(compressedPolys, 15, 3, 2, t);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("Gas for 3-round sumcheck verify", gasUsed);
        // Should be reasonable — a few thousand gas per round
        assertLt(gasUsed, 100000);
    }
}
