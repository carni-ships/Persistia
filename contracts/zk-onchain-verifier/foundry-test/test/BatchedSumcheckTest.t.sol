// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "contracts/JoltTranscript.sol";
import "contracts/SumcheckVerifier.sol";
import "contracts/BatchedSumcheckVerifier.sol";

contract BatchedSumcheckTest is Test {
    using JoltTranscript for JoltTranscript.Transcript;

    // ----------------------------------------------------------------
    //  Test: Batched sumcheck verification matches Rust test vectors
    // ----------------------------------------------------------------

    function test_batchedSumcheckVerify() public view {
        // 2 instances, both 3 rounds, degree 2
        // Instance A: claim_a = 15, Instance B: claim_b = 20
        // Compressed polys for the combined proof:
        //   Round 0: [8, 3]
        //   Round 1: [11, 5]
        //   Round 2: [4, 2]

        uint256[] memory instanceClaims = new uint256[](2);
        instanceClaims[0] = 15; // claim_a
        instanceClaims[1] = 20; // claim_b

        uint256[] memory instanceNumRounds = new uint256[](2);
        instanceNumRounds[0] = 3;
        instanceNumRounds[1] = 3;

        uint256[][] memory compressedPolys = new uint256[][](3);
        compressedPolys[0] = new uint256[](2);
        compressedPolys[0][0] = 8;
        compressedPolys[0][1] = 3;

        compressedPolys[1] = new uint256[](2);
        compressedPolys[1][0] = 11;
        compressedPolys[1][1] = 5;

        compressedPolys[2] = new uint256[](2);
        compressedPolys[2][0] = 4;
        compressedPolys[2][1] = 2;

        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("batched_sc_test");

        (
            uint256 finalClaim,
            uint256[] memory challenges,
            uint256[] memory batchingCoeffs
        ) = BatchedSumcheckVerifier.verify(
            compressedPolys,
            instanceClaims,
            instanceNumRounds,
            2, // maxDegree
            t
        );

        // Verify batching coefficients (non-Montgomery 128-bit challenge_scalar)
        assertEq(
            batchingCoeffs[0],
            0x00000000000000000000000000000000ef909505c0e5148febafa343129778a6,
            "gamma[0] mismatch"
        );
        assertEq(
            batchingCoeffs[1],
            0x00000000000000000000000000000000108c3480f7eab7399b1cb7c0b8a421e1,
            "gamma[1] mismatch"
        );

        // Verify sumcheck challenges (Montgomery challengeScalarMont)
        assertEq(
            challenges[0],
            0x2da2a47d4d71d803292e70a8d1e626223799c58928d8a2f7851df49da867f574,
            "challenges[0] mismatch"
        );
        assertEq(
            challenges[1],
            0x2b2a2a6c6d85302e2c64752c8c9fffc85dc599d7d335a617f567b0ba86bc357a,
            "challenges[1] mismatch"
        );
        assertEq(
            challenges[2],
            0x1f255eb8ba9a103166d271d6528ce6fb7115d092abf8e4f21d848fb212dfc137,
            "challenges[2] mismatch"
        );

        // Verify final claim
        assertEq(
            finalClaim,
            0x1a8d5393592616da33da61382413c16568e391d79b71fb7c5f1d38b521cb5df0,
            "final claim mismatch"
        );

        // Verify transcript state
        assertEq(
            t.state,
            bytes32(0x4a894fb99f9f5f38366f740384630681e30a4a5b88d9bd3a2be11ea489bb1855),
            "transcript state mismatch"
        );
        assertEq(t.nRounds, 18, "nRounds mismatch");
    }

    // ----------------------------------------------------------------
    //  Test: Instance challenge slice extraction
    // ----------------------------------------------------------------

    function test_instanceChallengeSlice() public pure {
        // 5 challenges, instance with 3 rounds starting at offset 2
        uint256[] memory challenges = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) {
            challenges[i] = i + 100;
        }

        uint256[] memory slice = BatchedSumcheckVerifier.instanceChallengeSlice(
            challenges, 5, 3
        );

        assertEq(slice.length, 3);
        assertEq(slice[0], 102); // offset = 5-3 = 2
        assertEq(slice[1], 103);
        assertEq(slice[2], 104);
    }

    // ----------------------------------------------------------------
    //  Test: Gas usage for batched sumcheck
    // ----------------------------------------------------------------

    function test_batchedSumcheckGas() public {
        uint256[] memory instanceClaims = new uint256[](2);
        instanceClaims[0] = 15;
        instanceClaims[1] = 20;

        uint256[] memory instanceNumRounds = new uint256[](2);
        instanceNumRounds[0] = 3;
        instanceNumRounds[1] = 3;

        uint256[][] memory compressedPolys = new uint256[][](3);
        compressedPolys[0] = new uint256[](2);
        compressedPolys[0][0] = 8;
        compressedPolys[0][1] = 3;
        compressedPolys[1] = new uint256[](2);
        compressedPolys[1][0] = 11;
        compressedPolys[1][1] = 5;
        compressedPolys[2] = new uint256[](2);
        compressedPolys[2][0] = 4;
        compressedPolys[2][1] = 2;

        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("batched_sc_test");

        uint256 gasBefore = gasleft();
        BatchedSumcheckVerifier.verify(
            compressedPolys,
            instanceClaims,
            instanceNumRounds,
            2,
            t
        );
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("Gas for 2-instance 3-round batched sumcheck", gasUsed);
        assertLt(gasUsed, 200000);
    }
}
