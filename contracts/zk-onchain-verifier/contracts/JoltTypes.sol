// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./StageVerification.sol";

/// @title Shared type definitions for the Jolt on-chain verifier.
library JoltTypes {
    /// @notice Fiat-Shamir preamble data.
    struct Preamble {
        uint64 maxInputSize;
        uint64 maxOutputSize;
        uint64 heapSize;
        bytes inputs;
        bytes outputs;
        uint64 panic;
        uint64 ramK;
        uint64 traceLength;
        uint64 entryAddress;
    }

    /// @notice Full on-chain proof.
    struct JoltOnChainProof {
        Preamble preamble;
        bytes commitmentBlob;
        uint16 commitmentSize;
        bytes untrustedAdviceCommitment;
        bytes trustedAdviceCommitment;
        /// Stage 1 proof: Spartan outer (UniSkip + remaining sumcheck)
        StageVerification.Stage1Proof stage1Proof;
        StageVerification.Stage1Inputs stage1Inputs;
        /// Stage 2 proof: Product virtualization (UniSkip + 5 instances)
        StageVerification.Stage2Proof stage2Proof;
        StageVerification.Stage2Inputs stage2Inputs;
        /// Stage 3 proof with algebraic verification.
        StageVerification.Stage3Proof stage3Proof;
        StageVerification.Stage3Inputs stage3Inputs;
        /// Stage 4 proof with algebraic verification.
        StageVerification.Stage4Proof stage4Proof;
        StageVerification.Stage4Inputs stage4Inputs;
        /// Stage 5 proof with algebraic verification.
        StageVerification.Stage5Proof stage5Proof;
        StageVerification.Stage5Inputs stage5Inputs;
        /// Stage 6 proof with algebraic verification.
        StageVerification.Stage6Proof stage6Proof;
        StageVerification.Stage6Inputs stage6Inputs;
        /// Stage 7 proof with algebraic verification.
        StageVerification.Stage7Proof stage7Proof;
        StageVerification.Stage7Inputs stage7Inputs;
        /// Stage 8: Dory opening verification via Groth16.
        uint256[] committedClaims;
        uint256[] scalingFactors;
        bytes doryMessageBlob;
        bytes doryMessageLengths;
        uint256[12] doryCommitment;
        uint256[] s1Coords;
        uint256[] s2Coords;
        uint256[] dorys1Coords;
        uint256[] dorys2Coords;
        uint256 doryNumRounds;
        uint256[8] groth16Proof;
        uint256[2] groth16Commitments;
        uint256[2] groth16CommitmentPok;
    }
}
