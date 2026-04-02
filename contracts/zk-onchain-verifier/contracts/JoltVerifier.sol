// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./JoltTranscript.sol";
import "./StageVerification.sol";
import "./DoryOnChainVerifier.sol";
import "./JoltTypes.sol";
import "./JoltVerifierPhase1.sol";

/// @title Jolt On-Chain Verifier
/// @notice Verifies Jolt proofs on-chain by replaying Fiat-Shamir transcript
/// through stages 1-7 (sumcheck verification) and stage 8 (Dory opening via Groth16).
///
/// Split into two contracts to fit within EIP-170 contract size limit (24,576 bytes):
///   Phase 1 (JoltVerifierPhase1): Preamble + commitments + stages 1-4
///   Phase 2 (this contract): Stages 5-7 + stage 8 (Dory/Groth16)
contract JoltVerifier {
    using JoltTranscript for JoltTranscript.Transcript;

    uint256 internal constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    JoltVerifierPhase1 public immutable phase1;
    DoryOnChainVerifier public immutable doryVerifier;

    constructor(address _phase1, address _doryVerifier) {
        phase1 = JoltVerifierPhase1(_phase1);
        doryVerifier = DoryOnChainVerifier(_doryVerifier);
    }

    /// @notice Full Jolt proof verification.
    function verify(JoltTypes.JoltOnChainProof calldata proof) external view {
        // Phase 1: preamble + commitments + stages 1-4
        (bytes32 tState, uint32 tNRounds, uint256 nCycleVars) = phase1.verifyPhase1(proof);

        // Restore transcript state
        JoltTranscript.Transcript memory t;
        t.state = tState;
        t.nRounds = tNRounds;

        // Phase 2: stages 5-7
        StageVerification.verifyStage5(t, proof.stage5Proof, proof.stage5Inputs, nCycleVars);
        StageVerification.verifyStage6(t, proof.stage6Proof, proof.stage6Inputs, nCycleVars);
        StageVerification.verifyStage7(t, proof.stage7Proof, proof.stage7Inputs);

        // Stage 8: Dory opening verification via Groth16
        _verifyStage8(t, proof);
    }

    function _verifyStage8(
        JoltTranscript.Transcript memory t,
        JoltTypes.JoltOnChainProof calldata proof
    ) internal view {
        uint256 numClaims = proof.committedClaims.length;
        require(proof.scalingFactors.length == numClaims, "stage8: scaling/claims length mismatch");

        // 1. Append committed claims to transcript
        t.appendLabeledScalars(bytes24(bytes10("rlc_claims")), proof.committedClaims);

        // 2. Sample gamma powers from transcript
        uint256[] memory gammaPowers = t.challengeScalarPowers(numClaims);

        // 3. Compute joint_claim = sum gamma^i * scaling_i * claim_i
        uint256 jointClaim = 0;
        for (uint256 i = 0; i < numClaims; i++) {
            uint256 term = mulmod(
                mulmod(gammaPowers[i], proof.scalingFactors[i], R),
                proof.committedClaims[i],
                R
            );
            jointClaim = addmod(jointClaim, term, R);
        }

        // 4. Append opening point and evaluation to transcript
        {
            uint256[] memory openingPointScalars = new uint256[](proof.s1Coords.length + proof.s2Coords.length);
            for (uint256 i = 0; i < proof.s1Coords.length; i++) {
                openingPointScalars[i] = proof.s1Coords[i];
            }
            for (uint256 i = 0; i < proof.s2Coords.length; i++) {
                openingPointScalars[proof.s1Coords.length + i] = proof.s2Coords[i];
            }
            t.appendLabeledScalars(bytes24(bytes19("dory_opening_point")), openingPointScalars);
        }
        t.appendLabeledScalar(bytes32(bytes17("dory_opening_eval")), jointClaim);

        // 5. Derive Dory challenges from Keccak transcript
        uint256 numRounds = proof.doryNumRounds;
        uint256 expectedMsgs = 5 + 12 * numRounds;
        require(
            proof.doryMessageLengths.length == expectedMsgs * 2,
            "stage8: dory message lengths mismatch"
        );

        uint256[] memory alphas = new uint256[](numRounds);
        uint256[] memory betas = new uint256[](numRounds);

        bytes24 dorySerdeLabel = bytes24(bytes10("dory_serde"));
        uint256 blobOffset = 0;
        uint256 msgIdx = 0;

        // VMV messages (3)
        for (uint256 i = 0; i < 3; i++) {
            uint256 len = _readMsgLen(proof.doryMessageLengths, msgIdx++);
            t.appendLabeledBytes(dorySerdeLabel, uint64(len), _sliceBlob(proof.doryMessageBlob, blobOffset, len));
            blobOffset += len;
        }

        // Per-round: 6 first-message fields -> beta, 6 second-message fields -> alpha
        for (uint256 round = 0; round < numRounds; round++) {
            for (uint256 j = 0; j < 6; j++) {
                uint256 len = _readMsgLen(proof.doryMessageLengths, msgIdx++);
                t.appendLabeledBytes(dorySerdeLabel, uint64(len), _sliceBlob(proof.doryMessageBlob, blobOffset, len));
                blobOffset += len;
            }
            betas[round] = t.challengeScalar();

            for (uint256 j = 0; j < 6; j++) {
                uint256 len = _readMsgLen(proof.doryMessageLengths, msgIdx++);
                t.appendLabeledBytes(dorySerdeLabel, uint64(len), _sliceBlob(proof.doryMessageBlob, blobOffset, len));
                blobOffset += len;
            }
            alphas[round] = t.challengeScalar();
        }

        // gamma challenge
        uint256 doryGamma = t.challengeScalar();

        // Final messages (2)
        for (uint256 i = 0; i < 2; i++) {
            uint256 len = _readMsgLen(proof.doryMessageLengths, msgIdx++);
            t.appendLabeledBytes(dorySerdeLabel, uint64(len), _sliceBlob(proof.doryMessageBlob, blobOffset, len));
            blobOffset += len;
        }

        // d challenge
        uint256 doryD = t.challengeScalar();

        // 6. Verify Dory opening via Groth16 with derived challenges
        doryVerifier.verifyWithChallenges(
            alphas,
            betas,
            doryGamma,
            doryD,
            proof.groth16Proof,
            proof.groth16Commitments,
            proof.groth16CommitmentPok,
            proof.doryCommitment,
            jointClaim,
            proof.dorys1Coords,
            proof.dorys2Coords,
            numRounds
        );
    }

    function _readMsgLen(bytes calldata packed, uint256 idx) internal pure returns (uint256) {
        uint256 off = idx * 2;
        return (uint256(uint8(packed[off])) << 8) | uint256(uint8(packed[off + 1]));
    }

    function _sliceBlob(bytes calldata blob, uint256 offset, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        // SAFETY: copies calldata slice into freshly allocated memory
        assembly {
            calldatacopy(add(out, 0x20), add(blob.offset, offset), len)
        }
    }
}
