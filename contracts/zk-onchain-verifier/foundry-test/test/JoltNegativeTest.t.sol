// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./JoltE2ETest.t.sol";

/// @title Jolt Negative Tests
/// @notice Verifies that corrupted proofs are rejected by the verifier.
/// Each test takes a valid proof, mutates exactly one field, and asserts revert.
///
/// Stages 1-7: Verified via algebraic output claim checks in Solidity.
/// Stage 8: Verified via Groth16 (mocked here — see DoryVerifier7Test for real Groth16 tests).
/// The full Groth16 integration through JoltVerifier requires InputHash alignment with the
/// gnark circuit, which is tracked separately.
contract JoltNegativeTest is JoltE2ETest {
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // ================================================================
    //  Preamble mutations — corrupt Fiat-Shamir transcript state
    // ================================================================

    function test_reject_wrongTraceLength() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.preamble.traceLength = proof.preamble.traceLength * 2;
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_wrongInputs() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.preamble.inputs = hex"deadbeef";
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_wrongEntryAddress() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.preamble.entryAddress = 0x12345678;
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_wrongPanic() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.preamble.panic = 1;
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_wrongOutputs() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.preamble.outputs = hex"ff";
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Commitment mutations — corrupt transcript before stages
    // ================================================================

    function test_reject_corruptedCommitment() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.commitmentBlob.length > 0) {
            proof.commitmentBlob[0] = bytes1(uint8(proof.commitmentBlob[0]) ^ 0xff);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_corruptedLastCommitment() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.commitmentBlob.length > 0) {
            uint256 lastStart = proof.commitmentBlob.length - uint256(proof.commitmentSize);
            proof.commitmentBlob[lastStart] = bytes1(uint8(proof.commitmentBlob[lastStart]) ^ 0xff);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Stage 1 mutations — Spartan outer sumcheck
    // ================================================================

    function test_reject_stage1_corruptedUniSkipCoeffs() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage1Proof.uniSkipCoeffs[0] = addmod(proof.stage1Proof.uniSkipCoeffs[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage1_corruptedCompressedPoly() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage1Proof.compressedPolys.length > 0 && proof.stage1Proof.compressedPolys[0].length > 0) {
            proof.stage1Proof.compressedPolys[0][0] = addmod(proof.stage1Proof.compressedPolys[0][0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage1_corruptedLastCompressedPoly() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        uint256 last = proof.stage1Proof.compressedPolys.length - 1;
        if (proof.stage1Proof.compressedPolys[last].length > 0) {
            proof.stage1Proof.compressedPolys[last][0] = addmod(proof.stage1Proof.compressedPolys[last][0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage1_corruptedR1csEvals() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage1Proof.r1csInputEvals[0] = addmod(proof.stage1Proof.r1csInputEvals[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage1_corruptedR1csEvalsMiddle() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage1Proof.r1csInputEvals[17] = addmod(proof.stage1Proof.r1csInputEvals[17], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Stage 2 mutations — Product virtualization
    // ================================================================

    function test_reject_stage2_corruptedUniSkipCoeffs() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage2Proof.uniSkipCoeffs[0] = addmod(proof.stage2Proof.uniSkipCoeffs[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage2_corruptedFlushedClaims() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage2Proof.flushedClaims[0] = addmod(proof.stage2Proof.flushedClaims[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage2_corruptedInputClaim() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage2Inputs.instanceInputClaims[0] = addmod(proof.stage2Inputs.instanceInputClaims[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage2_corruptedRCycleStage1() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage2Inputs.rCycleStage1[0] = addmod(proof.stage2Inputs.rCycleStage1[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Stage 3 mutations — ShiftSumcheck + InstructionInput + RegistersCR
    // ================================================================

    function test_reject_stage3_corruptedCompressedPoly() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage3Proof.compressedPolys.length > 0 && proof.stage3Proof.compressedPolys[0].length > 0) {
            proof.stage3Proof.compressedPolys[0][0] = addmod(proof.stage3Proof.compressedPolys[0][0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage3_corruptedFlushedClaims() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage3Proof.flushedClaims[0] = addmod(proof.stage3Proof.flushedClaims[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage3_corruptedIntermediateValue() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage3Inputs.nextPC = addmod(proof.stage3Inputs.nextPC, 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage3_corruptedRdWriteValue() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage3Inputs.rdWriteValue = addmod(proof.stage3Inputs.rdWriteValue, 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Stage 4 mutations — RegistersRW + RamValCheck
    // ================================================================

    function test_reject_stage4_corruptedCompressedPoly() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage4Proof.compressedPolys.length > 0 && proof.stage4Proof.compressedPolys[0].length > 0) {
            proof.stage4Proof.compressedPolys[0][0] = addmod(proof.stage4Proof.compressedPolys[0][0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage4_corruptedFlushedClaims() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage4Proof.flushedClaims[0] = addmod(proof.stage4Proof.flushedClaims[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage4_corruptedInitEval() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage4Inputs.initEval = addmod(proof.stage4Inputs.initEval, 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage4_corruptedRamVal() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage4Inputs.ramVal = addmod(proof.stage4Inputs.ramVal, 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Stage 5 mutations — InstrReadRaf + RamRaCR + RegistersValEval
    // ================================================================

    function test_reject_stage5_corruptedCompressedPoly() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage5Proof.compressedPolys.length > 0 && proof.stage5Proof.compressedPolys[0].length > 0) {
            proof.stage5Proof.compressedPolys[0][0] = addmod(proof.stage5Proof.compressedPolys[0][0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage5_corruptedFlushedClaims() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage5Proof.flushedClaims[0] = addmod(proof.stage5Proof.flushedClaims[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage5_corruptedLookupOutput() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage5Inputs.lookupOutput = addmod(proof.stage5Inputs.lookupOutput, 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage5_corruptedRegistersVal() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage5Inputs.registersVal = addmod(proof.stage5Inputs.registersVal, 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Stage 6 mutations — BytecodeReadRaf + Booleanity + IncCR + ...
    // ================================================================

    function test_reject_stage6_corruptedCompressedPoly() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage6Proof.compressedPolys.length > 0 && proof.stage6Proof.compressedPolys[0].length > 0) {
            proof.stage6Proof.compressedPolys[0][0] = addmod(proof.stage6Proof.compressedPolys[0][0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage6_corruptedFlushedClaims() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage6Proof.flushedClaims[0] = addmod(proof.stage6Proof.flushedClaims[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage6_corruptedBytecodeInputClaim() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage6Inputs.bytecodeInputClaim = addmod(proof.stage6Inputs.bytecodeInputClaim, 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage6_corruptedIncV1() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage6Inputs.incV1 = addmod(proof.stage6Inputs.incV1, 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage6_corruptedRamRaInputClaim() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage6Inputs.ramRaInputClaim = addmod(proof.stage6Inputs.ramRaInputClaim, 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Stage 7 mutations — HammingWeightCR
    // ================================================================

    function test_reject_stage7_corruptedCompressedPoly() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage7Proof.compressedPolys.length > 0 && proof.stage7Proof.compressedPolys[0].length > 0) {
            proof.stage7Proof.compressedPolys[0][0] = addmod(proof.stage7Proof.compressedPolys[0][0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage7_corruptedFlushedClaims() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage7Proof.flushedClaims[0] = addmod(proof.stage7Proof.flushedClaims[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage7_corruptedHwClaim() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage7Inputs.hwClaims[0] = addmod(proof.stage7Inputs.hwClaims[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_stage7_corruptedBoolClaim() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage7Inputs.boolClaims[0] = addmod(proof.stage7Inputs.boolClaims[0], 1, R);
        vm.expectRevert();
        verifier.verify(proof);
    }

    // ================================================================
    //  Cross-stage mutations — intermediate values that flow between stages
    // ================================================================

    function test_reject_crossStage_corruptedRCycle() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage3Inputs.rOuter.length > 0) {
            proof.stage3Inputs.rOuter[0] = addmod(proof.stage3Inputs.rOuter[0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_crossStage_wrongNumRowsBits() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        proof.stage1Inputs.numRowsBits = proof.stage1Inputs.numRowsBits + 1;
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_crossStage_corruptedStage4RCycle() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage4Inputs.rCycleStage3.length > 0) {
            proof.stage4Inputs.rCycleStage3[0] = addmod(proof.stage4Inputs.rCycleStage3[0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_crossStage_corruptedStage5RReduction() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage5Inputs.rReduction.length > 0) {
            proof.stage5Inputs.rReduction[0] = addmod(proof.stage5Inputs.rReduction[0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }

    function test_reject_crossStage_corruptedStage6RCycles() public {
        JoltTypes.JoltOnChainProof memory proof = _buildValidProof();
        if (proof.stage6Inputs.rCycles.length > 0) {
            proof.stage6Inputs.rCycles[0] = addmod(proof.stage6Inputs.rCycles[0], 1, R);
        }
        vm.expectRevert();
        verifier.verify(proof);
    }
}
