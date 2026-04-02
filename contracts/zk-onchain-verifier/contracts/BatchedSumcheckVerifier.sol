// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./JoltTranscript.sol";
import "./SumcheckVerifier.sol";

/// @title Batched Sumcheck Verifier
/// @notice Solidity port of jolt-core's BatchedSumcheck::verify.
///
/// Handles multiple sumcheck instances batched together with random
/// linear combination coefficients. Supports instances with different
/// numbers of rounds via front-loaded batching with power-of-2 scaling.
library BatchedSumcheckVerifier {
    using JoltTranscript for JoltTranscript.Transcript;

    uint256 internal constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @notice Verify a batched sumcheck proof.
    /// @param compressedPolys The compressed univariate polynomials for all rounds.
    /// @param instanceClaims Input claims for each sumcheck instance.
    /// @param instanceNumRounds Number of rounds for each instance.
    /// @param maxDegree Maximum polynomial degree across all instances.
    /// @param t The Fiat-Shamir transcript (mutated in place).
    /// @return finalClaim The final evaluation claim after all rounds.
    /// @return challenges The challenge vector r = (r_0, ..., r_{maxRounds-1}).
    /// @return batchingCoeffs The batching coefficients (one per instance).
    function verify(
        uint256[][] memory compressedPolys,
        uint256[] memory instanceClaims,
        uint256[] memory instanceNumRounds,
        uint256 maxDegree,
        JoltTranscript.Transcript memory t
    )
        internal
        pure
        returns (
            uint256 finalClaim,
            uint256[] memory challenges,
            uint256[] memory batchingCoeffs
        )
    {
        uint256 numInstances = instanceClaims.length;
        require(instanceNumRounds.length == numInstances, "round count mismatch");

        // Determine max number of rounds
        uint256 maxRounds = 0;
        for (uint256 i = 0; i < numInstances; i++) {
            if (instanceNumRounds[i] > maxRounds) {
                maxRounds = instanceNumRounds[i];
            }
        }
        require(compressedPolys.length == maxRounds, "wrong poly count");

        // Append each instance's input claim to transcript (non-ZK mode)
        for (uint256 i = 0; i < numInstances; i++) {
            t.appendLabeledScalar(
                bytes32(bytes14("sumcheck_claim")),
                instanceClaims[i]
            );
        }

        // Derive batching coefficients: one per instance
        // Uses challenge_vector (non-Montgomery challengeScalar)
        batchingCoeffs = t.challengeVector(numInstances);

        // Compute combined initial claim with power-of-2 scaling
        uint256 combinedClaim = 0;
        for (uint256 i = 0; i < numInstances; i++) {
            uint256 scaledClaim = instanceClaims[i];
            uint256 roundDiff = maxRounds - instanceNumRounds[i];
            if (roundDiff > 0) {
                scaledClaim = SumcheckVerifier.mulPow2(scaledClaim, roundDiff);
            }
            combinedClaim = addmod(
                combinedClaim,
                mulmod(scaledClaim, batchingCoeffs[i], R),
                R
            );
        }

        // Run single sumcheck verification with combined claim
        (finalClaim, challenges) = SumcheckVerifier.verify(
            compressedPolys,
            combinedClaim,
            maxRounds,
            maxDegree,
            t
        );
    }

    /// @notice Extract the challenge slice for a specific instance.
    /// Front-loaded batching: shorter instances use the suffix of challenges.
    /// @param challenges Full challenge vector from batched sumcheck.
    /// @param maxRounds Total number of rounds in the batched sumcheck.
    /// @param numRounds Number of rounds for this specific instance.
    /// @return slice The instance-specific challenge subarray.
    function instanceChallengeSlice(
        uint256[] memory challenges,
        uint256 maxRounds,
        uint256 numRounds
    ) internal pure returns (uint256[] memory slice) {
        uint256 offset = maxRounds - numRounds;
        slice = new uint256[](numRounds);
        for (uint256 i = 0; i < numRounds; i++) {
            slice[i] = challenges[offset + i];
        }
    }
}
