// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./JoltTranscript.sol";
import "./BatchedSumcheckVerifier.sol";
import "./EqPolynomial.sol";
import "./UniSkipVerifier.sol";
import "./R1CSEvaluator.sol";

/// @title Stage Verification Library
/// @notice Per-stage sumcheck verification for Jolt's 7-stage pipeline.
///
/// Each stage:
///   1. Samples instance-specific challenges from the transcript.
///   2. Computes input_claim() for each instance from prior-stage evaluation values.
///   3. Runs BatchedSumcheck::verify (which appends claims, samples batching coeffs, runs rounds).
///   4. Computes expected_output_claim() for each instance using new evaluation values.
///   5. Verifies batched expected output == sumcheck final claim.
///   6. Flushes new opening claims to transcript (excluding aliased duplicates).
///
/// Value Aliasing:
///   When two sumcheck instances in the same stage open the same polynomial at the same point,
///   the second opening aliases to the first. Aliased openings are NOT flushed to transcript.
///   This is deterministic and hardcoded per stage.
library StageVerification {
    using JoltTranscript for JoltTranscript.Transcript;

    uint256 internal constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // ================================================================
    //  Helper: reverse an array (LE ↔ BE endianness conversion)
    // ================================================================

    function _reverse(uint256[] memory arr) internal pure returns (uint256[] memory) {
        uint256 n = arr.length;
        uint256[] memory rev = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            rev[i] = arr[n - 1 - i];
        }
        return rev;
    }

    // ================================================================
    //  Helper: extract cycle-only portion from 3-phase normalized point
    // ================================================================
    //
    // The Jolt RegistersRW and RamRW sumchecks use a 3-phase binding order:
    //   Phase 1: first `p1` challenges → cycle variables (low-to-high, reversed to BE)
    //   Phase 2: next `p2` challenges → address variables (low-to-high, reversed to BE)
    //   Phase 3: remaining challenges split into cycle (logT - p1) then address (logK - p2)
    //
    // Result: r_cycle = [phase3_cycle reversed] ++ [phase1 reversed]  (logT elements, BE)

    function _extractCyclePoint3Phase(
        uint256[] memory challenges,
        uint256 phase1Rounds,
        uint256 phase2Rounds,
        uint256 logT
    ) internal pure returns (uint256[] memory rCycle) {
        uint256 remainingCycle = logT - phase1Rounds;
        rCycle = new uint256[](logT);

        // Phase 3 cycle: challenges[phase1+phase2..phase1+phase2+remainingCycle] reversed
        uint256 phase3Start = phase1Rounds + phase2Rounds;
        for (uint256 i = 0; i < remainingCycle; i++) {
            rCycle[i] = challenges[phase3Start + remainingCycle - 1 - i];
        }
        // Phase 1: challenges[0..phase1] reversed
        for (uint256 i = 0; i < phase1Rounds; i++) {
            rCycle[remainingCycle + i] = challenges[phase1Rounds - 1 - i];
        }
    }

    // ================================================================
    //  Stage 1: Spartan Outer (UniSkip first round + remaining sumcheck)
    // ================================================================
    //
    // Stage 1 verifies the Spartan outer sumcheck which proves R1CS satisfaction.
    //
    // UniSkip first round:
    //   - Sample tau = challenge_vector(numRowsBits) from transcript
    //   - Verify uniskip polynomial: Σ_{t in domain} s(t) == 0
    //   - Derive challenge r0, evaluate s(r0) as next claim
    //   - Flush 1 opening: s(r0) at point [r0]
    //
    // Remaining sumcheck (1 instance: OuterRemaining):
    //   - degree 3, rounds = 1 + logT
    //   - input_claim = s(r0) (from uniskip)
    //   - expected_output = tau_kernel * Az(r) * Bz(r)
    //   - cache_openings: 35 R1CS input evaluations + 3 product virtual claims
    //
    // The 38 flushed claims from Stage 1 are: s(r0), then 35 R1CS inputs, then
    // 3 product virtual claims (Instruction, ShouldBranch, ShouldJump).

    struct Stage1Proof {
        uint256[] uniSkipCoeffs;       // UniSkip polynomial coefficients (up to 28)
        uint256[][] compressedPolys;    // Remaining sumcheck round polynomials
        uint256[35] r1csInputEvals;    // 35 R1CS input evaluations at r_cycle (includes Product, ShouldBranch, ShouldJump)
    }

    struct Stage1Inputs {
        uint256 numRowsBits;           // log2(num_constraints) for tau vector length
        uint256 nCycleVars;            // log2(trace_length)
    }

    function verifyStage1(
        JoltTranscript.Transcript memory t,
        Stage1Proof calldata proof,
        Stage1Inputs calldata inputs
    ) internal pure {
        // 1. Sample tau vector
        uint256[] memory tau = t.challengeVectorMont(inputs.numRowsBits);

        // 2. Verify UniSkip first round
        (uint256 r0, uint256 uniSkipClaim) = UniSkipVerifier.verifyOuterUniSkip(
            t,
            proof.uniSkipCoeffs
        );

        // 3. Flush UniSkip opening to transcript
        t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniSkipClaim);

        // 4. Run remaining sumcheck (1 instance: OuterRemaining)
        uint256 outerRemainingRounds = 1 + inputs.nCycleVars;
        uint256[] memory instanceClaims = new uint256[](1);
        instanceClaims[0] = uniSkipClaim;
        uint256[] memory instanceNumRounds = new uint256[](1);
        instanceNumRounds[0] = outerRemainingRounds;

        (uint256 finalClaim, uint256[] memory challenges, uint256[] memory batchingCoeffs) =
            BatchedSumcheckVerifier.verify(
                proof.compressedPolys,
                instanceClaims,
                instanceNumRounds,
                3, // degree bound
                t
            );

        // 5. Compute expected output claim
        // tau_kernel = L(tau_high, r0) * Eq(tau_low, r_tail_reversed)
        // where tau_high = tau[tau.length-1], tau_low = tau[0..tau.length-1]
        // r_tail = challenges[1..], reversed for LE→BE conversion
        uint256 tauHigh = tau[tau.length - 1];
        uint256 tauHighBoundR0 = _lagrangeKernel10(tauHigh, r0);

        uint256[] memory tauLow = new uint256[](tau.length - 1);
        for (uint256 i = 0; i < tau.length - 1; i++) {
            tauLow[i] = tau[i];
        }

        uint256 tauKernel = mulmod(
            tauHighBoundR0,
            EqPolynomial.mleSliceReversed(tauLow, challenges, 0, challenges.length),
            R
        );

        // Compute Az * Bz using hardcoded R1CS constraints
        uint256[10] memory lagrangeW = R1CSEvaluator.lagrangeWeights10(r0);
        uint256 rStream = challenges[0]; // first challenge of remaining rounds
        uint256 azBz = R1CSEvaluator.evaluateAzBz(proof.r1csInputEvals, lagrangeW, rStream);

        uint256 expectedOutput = mulmod(tauKernel, azBz, R);

        // Single instance → batching coeff is just 1 (but multiply for correctness)
        expectedOutput = mulmod(expectedOutput, batchingCoeffs[0], R);
        require(finalClaim == expectedOutput, "stage1: output claim mismatch");

        // 6. Flush opening claims: 35 R1CS input evaluations
        for (uint256 i = 0; i < 35; i++) {
            t.appendLabeledScalar(
                bytes32(bytes13("opening_claim")),
                proof.r1csInputEvals[i]
            );
        }
    }

    /// @notice Lagrange kernel for domain {-4,...,5} at (tau, r).
    /// L(tau, r) = Σ_i L_i(tau) * L_i(r)
    function _lagrangeKernel10(uint256 tau, uint256 r) internal pure returns (uint256) {
        uint256[10] memory wTau = R1CSEvaluator.lagrangeWeights10(tau);
        uint256[10] memory wR = R1CSEvaluator.lagrangeWeights10(r);
        uint256 result = 0;
        for (uint256 i = 0; i < 10; i++) {
            result = addmod(result, mulmod(wTau[i], wR[i], R), R);
        }
        return result;
    }

    // ================================================================
    //  Stage 2: Product Virtualization (UniSkip + 5 batched instances)
    // ================================================================
    //
    // UniSkip first round (product virtual):
    //   - Reuse r_cycle from Stage 1 for tau_low
    //   - Sample tau_high from transcript
    //   - Verify uniskip polynomial: Σ_{t in domain} s(t) == input_claim
    //     where input_claim = Σ_i L_i(tau_high) * base_evals[i]
    //   - Flush 1 opening: s(r0) at point [r0]
    //
    // 5 batched instances:
    //   [0] RamReadWriteChecking: degree 3, logK+logT rounds
    //   [1] ProductVirtualRemainder: degree 3, logT rounds
    //   [2] InstructionLookupsClaimReduction: degree 2, logT rounds
    //   [3] RamRafEvaluation: degree 2, variable rounds
    //   [4] OutputSumcheck: degree 3, variable rounds

    struct Stage2Proof {
        uint256[] uniSkipCoeffs;       // UniSkip polynomial coefficients (up to 7)
        uint256[][] compressedPolys;    // Batched sumcheck round polynomials
        /// 15 opening claims flushed to transcript (3 aliased openings excluded):
        ///   Instance 0 (RamRW): [0]=RamVal, [1]=RamRa, [2]=RamInc
        ///   Instance 1 (ProductVirtRemainder):
        ///     [3]=LeftInstructionInput, [4]=RightInstructionInput,
        ///     [5]=Jump, [6]=WriteLookupOutputToRD, [7]=LookupOutput,
        ///     [8]=Branch, [9]=NextIsNoop, [10]=VirtualInstruction
        ///   Instance 2 (InstrClaimReduction):
        ///     LookupOutput aliased to [7], LeftInstructionInput aliased to [3],
        ///     RightInstructionInput aliased to [4]:
        ///     [11]=LeftLookupOperand, [12]=RightLookupOperand
        ///   Instance 3 (RamRafEval): [13]=RamRa
        ///   Instance 4 (OutputSumcheck): [14]=RamValFinal
        uint256[15] flushedClaims;
    }

    struct Stage2Inputs {
        uint256 nCycleVars;
        uint256 logK;                  // RAM address bits
        uint256 uniSkipInputClaim;     // Precomputed: Σ_i L_i(tau_high) * base_evals[i]
        uint256[5] instanceInputClaims; // Input claims for each of the 5 instances
        uint256[5] instanceNumRounds;  // Number of rounds for each instance
        uint256 maxDegree;             // Max degree across all instances
        // Reference points (BE) from Stage 1:
        uint256[] rCycleStage1;        // Cycle point from Stage 1 (for RamRW eq)
        uint256[] rSpartan;            // Stage 1 opening point for LookupOutput (for InstrCR eq)
        // For Instance 0 (RamRW): 3-phase binding configuration
        uint256 ramRwPhase1Rounds;
        uint256 ramRwPhase2Rounds;
        // For Instance 3 (RamRafEval): precomputed evaluation of UnmapRamAddressPolynomial
        uint256 unmapEval;
        // For Instance 4 (OutputSumcheck):
        uint256 ioMaskEval;            // RangeMaskPolynomial evaluation
        uint256 valIoEval;             // IO memory MLE evaluation
        // Reference point for OutputSumcheck eq:
        uint256[] rAddressStage2;      // Address point from RamRW (for output eq)
    }

    struct Stage2Mid {
        uint256 tauHigh;
        uint256 r0;
        uint256 ramRwGamma;
        uint256 instrGamma;
    }

    function verifyStage2(
        JoltTranscript.Transcript memory t,
        Stage2Proof calldata proof,
        Stage2Inputs calldata inputs
    ) internal pure {
        Stage2Mid memory mid;
        mid.tauHigh = t.challengeScalarMont();
        uint256 uniSkipClaim;
        (mid.r0, uniSkipClaim) = UniSkipVerifier.verifyProductUniSkip(t, proof.uniSkipCoeffs, inputs.uniSkipInputClaim);
        t.appendLabeledScalar(bytes32(bytes13("opening_claim")), uniSkipClaim);
        mid.ramRwGamma = t.challengeScalar();
        mid.instrGamma = t.challengeScalar();
        t.challengeVector(inputs.logK);

        uint256 finalClaim;
        uint256[] memory challenges;
        uint256[] memory batchingCoeffs;
        {
            uint256[] memory ic = new uint256[](5);
            uint256[] memory nr = new uint256[](5);
            for (uint256 i = 0; i < 5; i++) { ic[i] = inputs.instanceInputClaims[i]; nr[i] = inputs.instanceNumRounds[i]; }
            (finalClaim, challenges, batchingCoeffs) = BatchedSumcheckVerifier.verify(proof.compressedPolys, ic, nr, inputs.maxDegree, t);
        }

        uint256 batchedExpected = _stage2Expected(mid, challenges, batchingCoeffs, proof, inputs);
        require(finalClaim == batchedExpected, "stage2: output claim mismatch");

        for (uint256 i = 0; i < 15; i++) {
            t.appendLabeledScalar(bytes32(bytes13("opening_claim")), proof.flushedClaims[i]);
        }
    }

    function _stage2Expected(
        Stage2Mid memory mid, uint256[] memory challenges, uint256[] memory batchingCoeffs,
        Stage2Proof calldata proof, Stage2Inputs calldata inputs
    ) internal pure returns (uint256 batchedExpected) {
        // Copy flushed claims to memory to reduce calldata stack pressure
        uint256[15] memory fc;
        for (uint256 i = 0; i < 15; i++) { fc[i] = proof.flushedClaims[i]; }

        batchedExpected = _stage2Instances01(mid, challenges, batchingCoeffs, fc, inputs);
        batchedExpected = addmod(batchedExpected, _stage2Instances234(mid, challenges, batchingCoeffs, fc, inputs), R);
    }

    function _stage2Instances01(
        Stage2Mid memory mid, uint256[] memory challenges, uint256[] memory batchingCoeffs,
        uint256[15] memory fc, Stage2Inputs calldata inputs
    ) private pure returns (uint256 result) {
        // Instance [0]: RamReadWriteChecking
        {
            uint256[] memory rCycleOutput = _extractCyclePoint3Phase(challenges, inputs.ramRwPhase1Rounds, inputs.ramRwPhase2Rounds, inputs.nCycleVars);
            uint256 eqCycle = EqPolynomial.mle(inputs.rCycleStage1, rCycleOutput);
            uint256 inner = addmod(fc[0], mulmod(mid.ramRwGamma, addmod(fc[0], fc[2], R), R), R);
            result = mulmod(mulmod(eqCycle, mulmod(fc[1], inner, R), R), batchingCoeffs[0], R);
        }

        // Instance [1]: ProductVirtualRemainder
        {
            uint256 tauKernel = UniSkipVerifier.lagrangeKernel3(mid.tauHigh, mid.r0);
            uint256[3] memory w = UniSkipVerifier.lagrangeEvals3(mid.r0);
            uint256 offset1 = challenges.length - inputs.nCycleVars;
            uint256 eqTauR = EqPolynomial.mleSliceReversed(inputs.rCycleStage1, challenges, offset1, inputs.nCycleVars);

            uint256 fusedLeft = addmod(addmod(mulmod(w[0], fc[3], R), mulmod(w[1], fc[7], R), R), mulmod(w[2], fc[5], R), R);
            uint256 fusedRight = addmod(addmod(mulmod(w[0], fc[4], R), mulmod(w[1], fc[8], R), R), mulmod(w[2], addmod(1, R - fc[9], R), R), R);

            result = addmod(result, mulmod(mulmod(mulmod(tauKernel, eqTauR, R), mulmod(fusedLeft, fusedRight, R), R), batchingCoeffs[1], R), R);
        }
    }

    function _stage2Instances234(
        Stage2Mid memory mid, uint256[] memory challenges, uint256[] memory batchingCoeffs,
        uint256[15] memory fc, Stage2Inputs calldata inputs
    ) private pure returns (uint256 result) {
        // Instance [2]: InstructionLookupsClaimReduction
        {
            uint256 offset2 = challenges.length - inputs.nCycleVars;
            uint256 eqSpartan = EqPolynomial.mleSliceReversed(inputs.rSpartan, challenges, offset2, inputs.nCycleVars);

            uint256 g = mid.instrGamma;
            uint256 bo = fc[7]; // LookupOutput (aliased)
            bo = addmod(bo, mulmod(g, fc[11], R), R); g = mulmod(g, mid.instrGamma, R);
            bo = addmod(bo, mulmod(g, fc[12], R), R); g = mulmod(g, mid.instrGamma, R);
            bo = addmod(bo, mulmod(g, fc[3], R), R); g = mulmod(g, mid.instrGamma, R);
            bo = addmod(bo, mulmod(g, fc[4], R), R);

            result = mulmod(mulmod(eqSpartan, bo, R), batchingCoeffs[2], R);
        }

        // Instance [3]: RamRafEvaluation
        result = addmod(result, mulmod(mulmod(inputs.unmapEval, fc[13], R), batchingCoeffs[3], R), R);

        // Instance [4]: OutputSumcheck
        {
            uint256 outputRounds = inputs.instanceNumRounds[4];
            uint256 offset4 = challenges.length - outputRounds;
            uint256 eqAddr = EqPolynomial.mleSliceReversed(inputs.rAddressStage2, challenges, offset4, outputRounds);
            uint256 valDiff = addmod(fc[14], R - inputs.valIoEval, R);
            result = addmod(result, mulmod(mulmod(eqAddr, mulmod(inputs.ioMaskEval, valDiff, R), R), batchingCoeffs[4], R), R);
        }
    }

    // ================================================================
    //  Stage 3: ShiftSumcheck + InstructionInput + RegistersClaimReduction
    // ================================================================
    //
    // Three instances, all with num_rounds = nCycleVars:
    //   [0] ShiftSumcheckVerifier (degree 2)
    //   [1] InstructionInputSumcheckVerifier (degree 3)
    //   [2] RegistersClaimReductionSumcheckVerifier (degree 2)
    //
    // cache_openings produces 16 openings, but 3 are aliased:
    //   InstructionInput.UnexpandedPC → ShiftSumcheck.UnexpandedPC
    //   RegistersClaimReduction.Rs1Value → InstructionInput.Rs1Value
    //   RegistersClaimReduction.Rs2Value → InstructionInput.Rs2Value
    // So 13 claims are flushed to transcript.

    /// @notice Stage 3 proof data.
    struct Stage3Proof {
        uint256[][] compressedPolys;
        /// 13 opening claim values flushed to transcript.
        /// Order matches Rust verifier's cache_openings call order, minus aliases:
        ///   [0] UnexpandedPC (SpartanShift)
        ///   [1] PC (SpartanShift)
        ///   [2] IsVirtualInstruction (SpartanShift)
        ///   [3] IsFirstInSequence (SpartanShift)
        ///   [4] IsNoop (SpartanShift)
        ///   [5] LeftIsRs1 (InstructionInputVirt)
        ///   [6] Rs1Value (InstructionInputVirt)
        ///   [7] LeftIsPc (InstructionInputVirt)
        ///   -- UnexpandedPC aliased to [0] --
        ///   [8] RightIsRs2 (InstructionInputVirt)
        ///   [9] Rs2Value (InstructionInputVirt)
        ///   [10] RightIsImm (InstructionInputVirt)
        ///   [11] Imm (InstructionInputVirt)
        ///   [12] RdWriteValue (RegistersClaimReduction)
        ///   -- Rs1Value aliased to [6] --
        ///   -- Rs2Value aliased to [9] --
        uint256[13] flushedClaims;
    }

    /// @notice Stage 3 input values from prior stages' accumulator.
    struct Stage3Inputs {
        /// ShiftSumcheck input_claim values (from SpartanOuter + ProductVirt):
        uint256 nextUnexpandedPC;  // SpartanOuter
        uint256 nextPC;            // SpartanOuter
        uint256 nextIsVirtual;     // SpartanOuter
        uint256 nextIsFirstInSeq;  // SpartanOuter
        uint256 nextIsNoop;        // SpartanProductVirt
        /// InstructionInput input_claim values:
        uint256 rightInstructionInput;  // SpartanProductVirt
        uint256 leftInstructionInput;   // SpartanProductVirt
        /// RegistersClaimReduction input_claim values (from SpartanOuter):
        uint256 rdWriteValue;      // SpartanOuter
        uint256 rs1Value;          // SpartanOuter
        uint256 rs2Value;          // SpartanOuter
        /// Reference points (big-endian) from prior stages:
        uint256[] rOuter;         // first nCycleVars of Stage 1 opening point
        uint256[] rProduct;       // first nCycleVars of Stage 2 opening point
        uint256[] rCycleStage2;   // Stage 2 opening point (LeftInstructionInput)
        uint256[] rSpartan;       // Stage 1 opening point (LookupOutput prefix)
    }

    /// @notice Verify Stage 3 sumcheck and flush opening claims.
    function verifyStage3(
        JoltTranscript.Transcript memory t,
        Stage3Proof memory proof,
        Stage3Inputs memory inputs,
        uint256 nCycleVars
    ) internal pure returns (uint256[] memory challenges) {
        // 1. Sample challenges from transcript (same order as Rust verifier)
        uint256[5] memory gammaPowers;
        {
            uint256[] memory powers = t.challengeScalarPowers(5);
            for (uint256 i = 0; i < 5; i++) gammaPowers[i] = powers[i];
        }
        uint256 instrGamma = t.challengeScalar();
        uint256 regGamma = t.challengeScalar();
        uint256 regGammaSqr = mulmod(regGamma, regGamma, R);

        // 2. Compute input claims
        uint256[] memory instanceClaims = new uint256[](3);

        // Instance 0: ShiftSumcheck input_claim
        // nextUnexpandedPC + gamma^1*nextPC + gamma^2*nextIsVirt + gamma^3*nextIsFirstInSeq + gamma^4*(1 - nextIsNoop)
        {
            uint256 c = inputs.nextUnexpandedPC;
            c = addmod(c, mulmod(gammaPowers[1], inputs.nextPC, R), R);
            c = addmod(c, mulmod(gammaPowers[2], inputs.nextIsVirtual, R), R);
            c = addmod(c, mulmod(gammaPowers[3], inputs.nextIsFirstInSeq, R), R);
            c = addmod(c, mulmod(gammaPowers[4], addmod(1, R - inputs.nextIsNoop, R), R), R);
            instanceClaims[0] = c;
        }

        // Instance 1: InstructionInput input_claim
        // rightInstructionInput + gamma * leftInstructionInput
        instanceClaims[1] = addmod(
            inputs.rightInstructionInput,
            mulmod(instrGamma, inputs.leftInstructionInput, R),
            R
        );

        // Instance 2: RegistersClaimReduction input_claim
        // rdWriteValue + gamma * rs1Value + gamma^2 * rs2Value
        instanceClaims[2] = addmod(
            inputs.rdWriteValue,
            addmod(
                mulmod(regGamma, inputs.rs1Value, R),
                mulmod(regGammaSqr, inputs.rs2Value, R),
                R
            ),
            R
        );

        // 3. Run batched sumcheck
        uint256[] memory instanceNumRounds = new uint256[](3);
        instanceNumRounds[0] = nCycleVars;
        instanceNumRounds[1] = nCycleVars;
        instanceNumRounds[2] = nCycleVars;

        uint256 finalClaim;
        uint256[] memory batchingCoeffs;
        (finalClaim, challenges, batchingCoeffs) = BatchedSumcheckVerifier.verify(
            proof.compressedPolys,
            instanceClaims,
            instanceNumRounds,
            3, // maxDegree = max(2, 3, 2)
            t
        );

        // 4. Compute expected output claims
        // Use sliceReversed to avoid allocating reversed array
        uint256 batchedExpected = 0;

        // Instance 0: ShiftSumcheck expected_output_claim
        // (gamma^0*unexpandedPC + gamma^1*pc + gamma^2*isVirt + gamma^3*isFirstInSeq) * eqPlusOne(rOuter, r)
        // + gamma^4 * (1 - isNoop) * eqPlusOne(rProduct, r)
        {
            uint256 eqPlusOneOuter = EqPolynomial.eqPlusOneSliceReversed(inputs.rOuter, challenges, 0, nCycleVars);
            uint256 eqPlusOneProduct = EqPolynomial.eqPlusOneSliceReversed(inputs.rProduct, challenges, 0, nCycleVars);

            uint256 batched = mulmod(gammaPowers[0], proof.flushedClaims[0], R);
            batched = addmod(batched, mulmod(gammaPowers[1], proof.flushedClaims[1], R), R);
            batched = addmod(batched, mulmod(gammaPowers[2], proof.flushedClaims[2], R), R);
            batched = addmod(batched, mulmod(gammaPowers[3], proof.flushedClaims[3], R), R);
            uint256 shiftClaim = mulmod(batched, eqPlusOneOuter, R);
            shiftClaim = addmod(
                shiftClaim,
                mulmod(
                    gammaPowers[4],
                    mulmod(addmod(1, R - proof.flushedClaims[4], R), eqPlusOneProduct, R),
                    R
                ),
                R
            );
            batchedExpected = mulmod(shiftClaim, batchingCoeffs[0], R);
        }

        // Instance 1: InstructionInput expected_output_claim
        // eq(r, rCycleStage2) * (rightInput + gamma * leftInput)
        // leftInput = leftIsRs1 * rs1Value + leftIsPc * unexpandedPc
        // rightInput = rightIsRs2 * rs2Value + rightIsImm * imm
        // Note: unexpandedPc is aliased to flushedClaims[0]
        {
            uint256 eqCycle = EqPolynomial.mleSliceReversed(inputs.rCycleStage2, challenges, 0, nCycleVars);

            uint256 leftInput = addmod(
                mulmod(proof.flushedClaims[5], proof.flushedClaims[6], R),   // leftIsRs1 * rs1Value
                mulmod(proof.flushedClaims[7], proof.flushedClaims[0], R),   // leftIsPc * unexpandedPC (aliased)
                R
            );
            uint256 rightInput = addmod(
                mulmod(proof.flushedClaims[8], proof.flushedClaims[9], R),   // rightIsRs2 * rs2Value
                mulmod(proof.flushedClaims[10], proof.flushedClaims[11], R), // rightIsImm * imm
                R
            );
            uint256 instrClaim = mulmod(
                eqCycle,
                addmod(rightInput, mulmod(instrGamma, leftInput, R), R),
                R
            );
            batchedExpected = addmod(batchedExpected, mulmod(instrClaim, batchingCoeffs[1], R), R);
        }

        // Instance 2: RegistersClaimReduction expected_output_claim
        // eq(r, rSpartan) * (rdWriteValue + gamma * rs1Value + gamma^2 * rs2Value)
        // Note: rs1Value aliased to flushedClaims[6], rs2Value aliased to flushedClaims[9]
        {
            uint256 eqSpartan = EqPolynomial.mleSliceReversed(inputs.rSpartan, challenges, 0, nCycleVars);

            uint256 batchedReg = proof.flushedClaims[12]; // rdWriteValue
            batchedReg = addmod(batchedReg, mulmod(regGamma, proof.flushedClaims[6], R), R);  // aliased rs1
            batchedReg = addmod(batchedReg, mulmod(regGammaSqr, proof.flushedClaims[9], R), R); // aliased rs2

            uint256 regClaim = mulmod(eqSpartan, batchedReg, R);
            batchedExpected = addmod(batchedExpected, mulmod(regClaim, batchingCoeffs[2], R), R);
        }

        // 5. Verify output claim
        require(finalClaim == batchedExpected, "stage3: output claim mismatch");

        // 6. Flush opening claims to transcript (13 non-aliased values)
        for (uint256 i = 0; i < 13; i++) {
            t.appendLabeledScalar(
                bytes32(bytes13("opening_claim")),
                proof.flushedClaims[i]
            );
        }
    }

    // ================================================================
    //  Stage 4: RegistersReadWriteChecking + RamValCheck
    // ================================================================
    //
    // Two instances:
    //   [0] RegistersReadWriteCheckingVerifier (degree 3)
    //       num_rounds = LOG_K + log_T = 6 + log_T
    //   [1] RamValCheckSumcheckVerifier (degree 3)
    //       num_rounds = log_T
    //
    // Transcript operations before sumcheck:
    //   1. challenge_scalar() → regRwGamma (RegistersRW)
    //   2. append_bytes("ram_val_check_gamma", []) → domain separator
    //   3. challenge_scalar() → ramValCheckGamma (RamValCheck)
    //
    // cache_openings produces 7 openings (no advice):
    //   [0] RegistersVal (RegistersReadWriteChecking)
    //   [1] Rs1Ra (RegistersReadWriteChecking)
    //   [2] Rs2Ra (RegistersReadWriteChecking)
    //   [3] RdWa (RegistersReadWriteChecking)
    //   [4] RdInc (RegistersReadWriteChecking)
    //   [5] RamRa (RamValCheck)
    //   [6] RamInc (RamValCheck)

    /// @notice Stage 4 proof data.
    struct Stage4Proof {
        uint256[][] compressedPolys;
        uint256[7] flushedClaims;
    }

    /// @notice Stage 4 input values from prior stages.
    struct Stage4Inputs {
        // From Stage 3 (RegistersRW input_claim):
        uint256 rdWriteValue;   // RdWriteValue @ RegistersClaimReduction = Stage3.flushed[12]
        uint256 rs1Value;       // Rs1Value @ RegistersClaimReduction = Stage3.flushed[6]
        uint256 rs2Value;       // Rs2Value @ RegistersClaimReduction = Stage3.flushed[9]
        // From Stage 2 (RamValCheck input_claim):
        uint256 ramVal;         // RamVal @ RamReadWriteChecking (flushed in Stage 2)
        uint256 ramValFinal;    // RamValFinal @ RamOutputCheck (flushed in Stage 2)
        // Preprocessing (verified through Dory in Stage 8):
        uint256 initEval;       // initial_ram_state MLE at random address point
        // Reference points (big-endian):
        uint256[] rCycleStage3; // = reverse(Stage 3 challenges)
        uint256[] rCycleStage2Ram; // cycle part from Stage 2 RamRW normalized point
        // 3-phase config for RegistersRW:
        uint256 regPhase1Rounds;
        uint256 regPhase2Rounds;
    }

    uint256 internal constant LOG_K_REGISTERS = 7;

    /// @notice Verify Stage 4 sumcheck and flush opening claims.
    function verifyStage4(
        JoltTranscript.Transcript memory t,
        Stage4Proof memory proof,
        Stage4Inputs memory inputs,
        uint256 nCycleVars
    ) internal pure returns (uint256[] memory challenges) {
        // 1. Sample challenges
        uint256 regGamma = t.challengeScalar();

        // Domain separator for RamValCheck
        t.appendLabeledBytes(
            bytes24(bytes19("ram_val_check_gamma")),
            0,
            ""
        );
        uint256 ramValCheckGamma = t.challengeScalar();

        // 2. Compute input claims
        uint256[] memory instanceClaims = new uint256[](2);

        // Instance 0: RegistersRW
        // rdWriteValue + gamma * (rs1Value + gamma * rs2Value)
        instanceClaims[0] = addmod(
            inputs.rdWriteValue,
            mulmod(
                regGamma,
                addmod(
                    inputs.rs1Value,
                    mulmod(regGamma, inputs.rs2Value, R),
                    R
                ),
                R
            ),
            R
        );

        // Instance 1: RamValCheck
        // (ramVal - initEval) + ramValCheckGamma * (ramValFinal - initEval)
        {
            uint256 diff1 = addmod(inputs.ramVal, R - inputs.initEval, R);
            uint256 diff2 = addmod(inputs.ramValFinal, R - inputs.initEval, R);
            instanceClaims[1] = addmod(
                diff1,
                mulmod(ramValCheckGamma, diff2, R),
                R
            );
        }

        // 3. Run batched sumcheck
        uint256 regRounds = LOG_K_REGISTERS + nCycleVars;
        uint256[] memory instanceNumRounds = new uint256[](2);
        instanceNumRounds[0] = regRounds;      // RegistersRW: LOG_K + log_T
        instanceNumRounds[1] = nCycleVars;     // RamValCheck: log_T

        uint256 finalClaim;
        uint256[] memory batchingCoeffs;
        (finalClaim, challenges, batchingCoeffs) = BatchedSumcheckVerifier.verify(
            proof.compressedPolys,
            instanceClaims,
            instanceNumRounds,
            3, // maxDegree = max(3, 3)
            t
        );

        // 4. Compute expected output claims
        uint256 batchedExpected = 0;

        // Instance 0: RegistersRW expected_output_claim
        // eq(rCycleStage3, rCycleOutput) * (rdWa*(inc+val) + gamma*(rs1Ra*val + gamma*rs2Ra*val))
        {
            // Extract cycle point from 3-phase normalization
            // RegistersRW uses all `regRounds` challenges (offset 0)
            uint256[] memory rCycleOutput = _extractCyclePoint3Phase(
                challenges,
                inputs.regPhase1Rounds,
                inputs.regPhase2Rounds,
                nCycleVars
            );

            uint256 eqEval = EqPolynomial.mle(inputs.rCycleStage3, rCycleOutput);

            // val = flushed[0], rs1Ra = flushed[1], rs2Ra = flushed[2]
            // rdWa = flushed[3], inc = flushed[4]
            uint256 val = proof.flushedClaims[0];
            uint256 rs1Ra = proof.flushedClaims[1];
            uint256 rs2Ra = proof.flushedClaims[2];
            uint256 rdWa = proof.flushedClaims[3];
            uint256 inc = proof.flushedClaims[4];

            // rd_write_value = rdWa * (inc + val)
            uint256 rdWriteVal = mulmod(rdWa, addmod(inc, val, R), R);
            // rs1_value = rs1Ra * val
            uint256 rs1Val = mulmod(rs1Ra, val, R);
            // rs2_value = rs2Ra * val
            uint256 rs2Val = mulmod(rs2Ra, val, R);

            // batched = rdWriteVal + gamma * (rs1Val + gamma * rs2Val)
            uint256 batchedReg = addmod(
                rdWriteVal,
                mulmod(regGamma, addmod(rs1Val, mulmod(regGamma, rs2Val, R), R), R),
                R
            );

            uint256 regClaim = mulmod(eqEval, batchedReg, R);
            batchedExpected = mulmod(regClaim, batchingCoeffs[0], R);
        }

        // Instance 1: RamValCheck expected_output_claim
        // inc * wa * (lt(rCyclePrime, rCycleStage2Ram) + gamma)
        {
            // RamValCheck challenges: suffix of length nCycleVars
            uint256 ltOffset = regRounds - nCycleVars; // = LOG_K_REGISTERS
            uint256 ltEval = EqPolynomial.ltSliceReversed(challenges, ltOffset, nCycleVars, inputs.rCycleStage2Ram);

            // wa = flushed[5], inc = flushed[6]
            uint256 wa = proof.flushedClaims[5];
            uint256 incRam = proof.flushedClaims[6];

            uint256 ramClaim = mulmod(
                mulmod(incRam, wa, R),
                addmod(ltEval, ramValCheckGamma, R),
                R
            );
            batchedExpected = addmod(batchedExpected, mulmod(ramClaim, batchingCoeffs[1], R), R);
        }

        // 5. Verify output claim
        require(finalClaim == batchedExpected, "stage4: output claim mismatch");

        // 6. Flush opening claims to transcript (7 values)
        for (uint256 i = 0; i < 7; i++) {
            t.appendLabeledScalar(
                bytes32(bytes13("opening_claim")),
                proof.flushedClaims[i]
            );
        }
    }

    // ================================================================
    //  Stage 5: InstructionReadRaf + RamRaClaimReduction + RegistersValEval
    // ================================================================
    //
    // Three instances:
    //   [0] InstructionReadRafSumcheckVerifier (degree variable)
    //       num_rounds = LOG_K_INSTR + log_T  (LOG_K_INSTR = XLEN * 2)
    //   [1] RamRaClaimReductionSumcheckVerifier (degree 2)
    //       num_rounds = log_T
    //   [2] RegistersValEvaluationSumcheckVerifier (degree 3)
    //       num_rounds = log_T
    //
    // Transcript operations:
    //   1. challenge_scalar() → instrRafGamma (InstructionReadRaf)
    //   2. challenge_scalar() → ramRaGamma (RamRaClaimReduction)
    //   3. (none) (RegistersValEvaluation)

    /// @notice Stage 5 proof data.
    struct Stage5Proof {
        uint256[][] compressedPolys;
        /// Flushed claims in cache_openings order:
        ///   InstructionReadRaf: [nTables table flags, nRaChunks RA claims, 1 RAF flag]
        ///   RamRaClaimReduction: [1 RamRa reduced]
        ///   RegistersValEval: [1 RdInc, 1 RdWa]
        /// Total = nTables + nRaChunks + 1 + 1 + 2
        uint256[] flushedClaims;
    }

    /// @notice Stage 5 input values from prior stages.
    struct Stage5Inputs {
        // InstructionReadRaf input_claim values:
        uint256 lookupOutput;      // LookupOutput @ InstructionClaimReduction
        uint256 leftOperand;       // LeftLookupOperand @ InstructionClaimReduction
        uint256 rightOperand;      // RightLookupOperand @ InstructionClaimReduction
        // InstructionReadRaf expected_output_claim helpers (preprocessing):
        uint256[] valEvals;        // table MLE evaluations at r_address
        uint256 leftOperandEval;   // OperandPolynomial(Left).evaluate(r_address)
        uint256 rightOperandEval;  // OperandPolynomial(Right).evaluate(r_address)
        uint256 identityEval;      // IdentityPolynomial.evaluate(r_address)
        uint256[] rReduction;      // r_reduction from LookupOutput@InstructionClaimReduction (BE)
        uint256 nTables;           // number of lookup tables
        uint256 nRaChunks;         // number of RA polynomial chunks
        uint256 logKInstr;         // LOG_K for instruction lookup (= XLEN * 2)
        // RamRaClaimReduction input_claim values:
        uint256 claimRaf;          // RamRa @ RamRafEvaluation
        uint256 claimRw;           // RamRa @ RamReadWriteChecking = Stage4.flushed[5]
        uint256 claimVal;          // RamRa @ RamValCheck = Stage4.flushed[6-related]
        uint256[] rCycleRaf;       // cycle part of RamRa@RamRafEvaluation (BE)
        uint256[] rCycleRw;        // cycle part of RamRa@RamReadWriteChecking (BE)
        uint256[] rCycleVal;       // cycle part of RamRa@RamValCheck (BE)
        // RegistersValEvaluation input_claim:
        uint256 registersVal;      // RegistersVal @ RegistersReadWriteChecking = Stage4.flushed[0]
        uint256[] rCycleStage4Reg; // cycle part from Stage4 RegistersRW point (BE)
    }

    /// @notice Stage 5 InstructionReadRaf expected_output_claim helper.
    function _instrReadRafOutput(
        uint256 instrRafGamma,
        Stage5Inputs memory inputs,
        Stage5Proof memory proof,
        uint256[] memory challenges,
        uint256 instrRafRounds,
        uint256 nCycleVars
    ) internal pure returns (uint256) {
        uint256 nT = inputs.nTables;
        uint256 nRA = inputs.nRaChunks;

        uint256 instrOffset = instrRafRounds - nCycleVars;
        uint256 eqEval = EqPolynomial.mleSliceReversed(inputs.rReduction, challenges, instrOffset, nCycleVars);

        uint256 raProduct = 1;
        for (uint256 i = 0; i < nRA; i++) {
            raProduct = mulmod(raProduct, proof.flushedClaims[nT + i], R);
        }

        uint256 valClaim = 0;
        for (uint256 i = 0; i < nT; i++) {
            valClaim = addmod(valClaim, mulmod(inputs.valEvals[i], proof.flushedClaims[i], R), R);
        }

        uint256 rafFlag = proof.flushedClaims[nT + nRA];
        uint256 rafClaim = addmod(
            mulmod(
                addmod(1, R - rafFlag, R),
                addmod(inputs.leftOperandEval, mulmod(instrRafGamma, inputs.rightOperandEval, R), R),
                R
            ),
            mulmod(rafFlag, mulmod(instrRafGamma, inputs.identityEval, R), R),
            R
        );

        return mulmod(
            eqEval,
            mulmod(raProduct, addmod(valClaim, mulmod(instrRafGamma, rafClaim, R), R), R),
            R
        );
    }

    /// @notice Verify Stage 5 sumcheck and flush opening claims.
    function verifyStage5(
        JoltTranscript.Transcript memory t,
        Stage5Proof memory proof,
        Stage5Inputs memory inputs,
        uint256 nCycleVars
    ) internal pure returns (uint256[] memory challenges) {
        // 1. Sample challenges
        uint256 instrRafGamma = t.challengeScalar();
        uint256 instrRafGammaSqr = mulmod(instrRafGamma, instrRafGamma, R);
        uint256 ramRaGamma = t.challengeScalar();
        uint256 ramRaGammaSqr = mulmod(ramRaGamma, ramRaGamma, R);
        // RegistersValEvaluation: no transcript operations

        // 2. Compute input claims
        uint256[] memory instanceClaims = new uint256[](3);

        // Instance 0: InstructionReadRaf
        // lookupOutput + gamma * leftOperand + gamma^2 * rightOperand
        instanceClaims[0] = addmod(
            inputs.lookupOutput,
            addmod(
                mulmod(instrRafGamma, inputs.leftOperand, R),
                mulmod(instrRafGammaSqr, inputs.rightOperand, R),
                R
            ),
            R
        );

        // Instance 1: RamRaClaimReduction
        // claimRaf + gamma * claimRw + gamma^2 * claimVal
        instanceClaims[1] = addmod(
            inputs.claimRaf,
            addmod(
                mulmod(ramRaGamma, inputs.claimRw, R),
                mulmod(ramRaGammaSqr, inputs.claimVal, R),
                R
            ),
            R
        );

        // Instance 2: RegistersValEvaluation
        // Direct claim value
        instanceClaims[2] = inputs.registersVal;

        // 3. Run batched sumcheck
        uint256 instrRafRounds = inputs.logKInstr + nCycleVars;
        uint256[] memory instanceNumRounds = new uint256[](3);
        instanceNumRounds[0] = instrRafRounds;  // InstructionReadRaf
        instanceNumRounds[1] = nCycleVars;      // RamRaClaimReduction
        instanceNumRounds[2] = nCycleVars;      // RegistersValEvaluation

        uint256 finalClaim;
        uint256[] memory batchingCoeffs;
        (finalClaim, challenges, batchingCoeffs) = BatchedSumcheckVerifier.verify(
            proof.compressedPolys,
            instanceClaims,
            instanceNumRounds,
            10, // maxDegree (InstructionReadRaf: eq * product(RA_chunks) * (valClaim + gamma*rafClaim))
            t
        );

        // 4. Compute expected output claims
        uint256 batchedExpected = 0;

        // Instance 0: InstructionReadRaf expected_output_claim
        {
            uint256 instrClaim = _instrReadRafOutput(
                instrRafGamma, inputs, proof, challenges, instrRafRounds, nCycleVars
            );
            batchedExpected = mulmod(instrClaim, batchingCoeffs[0], R);
        }

        // Instance 1: RamRaClaimReduction expected_output_claim
        // (eq_raf + gamma*eq_rw + gamma^2*eq_val) * ra_claim_reduced
        {
            // RamRaReduction challenges: suffix of length nCycleVars
            uint256 raOffset = instrRafRounds - nCycleVars;

            uint256 eqRaf = EqPolynomial.mleSliceReversed(inputs.rCycleRaf, challenges, raOffset, nCycleVars);
            uint256 eqRw = EqPolynomial.mleSliceReversed(inputs.rCycleRw, challenges, raOffset, nCycleVars);
            uint256 eqVal = EqPolynomial.mleSliceReversed(inputs.rCycleVal, challenges, raOffset, nCycleVars);
            uint256 eqCombined = addmod(eqRaf, addmod(mulmod(ramRaGamma, eqRw, R), mulmod(ramRaGammaSqr, eqVal, R), R), R);

            // ra_claim_reduced is the first claim after InstructionReadRaf's claims
            uint256 nT = inputs.nTables;
            uint256 nRA = inputs.nRaChunks;
            uint256 ramRaIdx = nT + nRA + 1; // after table flags + RA chunks + RAF flag
            uint256 raClaim = proof.flushedClaims[ramRaIdx];

            uint256 ramRaClaim = mulmod(eqCombined, raClaim, R);
            batchedExpected = addmod(batchedExpected, mulmod(ramRaClaim, batchingCoeffs[1], R), R);
        }

        // Instance 2: RegistersValEvaluation expected_output_claim
        // inc * wa * lt(rCyclePrime, rCycleStage4Reg)
        {
            uint256 regOffset = instrRafRounds - nCycleVars;
            uint256 ltEval = EqPolynomial.ltSliceReversed(challenges, regOffset, nCycleVars, inputs.rCycleStage4Reg);

            uint256 nT = inputs.nTables;
            uint256 nRA = inputs.nRaChunks;
            uint256 regValIdx = nT + nRA + 1 + 1; // after InstructionReadRaf + RamRaReduction
            uint256 incClaim = proof.flushedClaims[regValIdx];
            uint256 waClaim = proof.flushedClaims[regValIdx + 1];

            uint256 regValClaim = mulmod(mulmod(incClaim, waClaim, R), ltEval, R);
            batchedExpected = addmod(batchedExpected, mulmod(regValClaim, batchingCoeffs[2], R), R);
        }

        // 5. Verify output claim
        require(finalClaim == batchedExpected, "stage5: output claim mismatch");

        // 6. Flush all opening claims
        for (uint256 i = 0; i < proof.flushedClaims.length; i++) {
            t.appendLabeledScalar(
                bytes32(bytes13("opening_claim")),
                proof.flushedClaims[i]
            );
        }
    }

    // ================================================================
    //  Stage 6: BytecodeReadRaf + Booleanity + HammingBooleanity
    //         + RamRaVirtual + LookupsRaVirtual + IncClaimReduction
    // ================================================================
    //
    // Six mandatory instances (optional advice omitted):
    //   [0] BytecodeReadRafSumcheckVerifier (degree: bytecodeD+1)
    //       num_rounds = logKBytecode + logT
    //   [1] BooleanitySumcheckVerifier (degree: 3)
    //       num_rounds = logKChunk + logT
    //   [2] HammingBooleanitySumcheckVerifier (degree: 3)
    //       num_rounds = logT
    //   [3] RamRaVirtualSumcheckVerifier (degree: ramD+1)
    //       num_rounds = logT
    //   [4] LookupsRaSumcheckVerifier (degree: nCommittedPerVirtual+1)
    //       num_rounds = logT
    //   [5] IncClaimReductionSumcheckVerifier (degree: 2)
    //       num_rounds = logT
    //
    // Transcript operations before sumcheck (9 challenge scalars):
    //   1. challengeScalar() → bytecodeGammaBase (→ 8 powers)
    //   2. challengeScalar() → stage1GammaBase   (→ 16 powers for BytecodeRaf)
    //   3. challengeScalar() → stage2GammaBase   (→ 4 powers)
    //   4. challengeScalar() → stage3GammaBase   (→ 9 powers)
    //   5. challengeScalar() → stage4GammaBase   (→ 3 powers)
    //   6. challengeScalar() → stage5GammaBase   (→ 42 powers)
    //   7. challengeScalar() → boolGamma
    //   8. challengeScalar() → lookupsRaGammaBase (→ nVirtualRa powers)
    //   9. challengeScalar() → incGamma
    //
    // Flushed claims (in order):
    //   BytecodeReadRaf: bytecodeD claims
    //   Booleanity: totalD claims (instruction_d + bytecode_d + ram_d)
    //   HammingBooleanity: 1 claim
    //   RamRaVirtual: ramD claims
    //   LookupsRaVirtual: nCommittedRaPolys claims
    //   IncClaimReduction: 2 claims (RamInc, RdInc)

    struct Stage6Proof {
        uint256[][] compressedPolys;
        uint256[] flushedClaims;
    }

    struct Stage6Inputs {
        // --- BytecodeReadRaf ---
        uint256 bytecodeInputClaim;      // Pre-computed input claim RLC (verified via Dory)
        uint256[5] valPolyEvals;         // Val polynomial evaluations at r_address
        uint256[] rCycles;               // Flattened: 5 * nCycleVars r_cycle points (BE)
        uint256 logKBytecode;
        uint256 bytecodeD;
        uint256 entryBytecodeIndex;
        // --- HammingBooleanity ---
        uint256[] rCycleHamming;         // r_cycle from SpartanOuter (BE)
        // --- Booleanity ---
        uint256 totalD;                  // instruction_d + bytecode_d + ram_d
        uint256 logKChunk;
        uint256[] rAddressBool;          // r_address from Stage 5 (BE, logKChunk elements)
        uint256[] rCycleBool;            // r_cycle from Stage 5 (BE)
        // --- RamRaVirtual ---
        uint256 ramD;
        uint256 ramRaInputClaim;         // ra_claim_reduced from Stage 5
        uint256[] rCycleRamRa;           // r_cycle from RamRaClaimReduction (BE)
        // --- LookupsRaVirtual ---
        uint256 nVirtualRaPolys;
        uint256 nCommittedPerVirtual;
        uint256 nCommittedRaPolys;
        uint256[] lookupsRaInputClaims;  // Individual ra_i claims from Stage 5
        uint256[] rCycleLookupsRa;       // r_cycle from InstructionReadRaf (BE)
        // --- IncClaimReduction ---
        uint256 incV1;                   // RamInc @ RamReadWriteChecking
        uint256 incV2;                   // RamInc @ RamValCheck
        uint256 incW1;                   // RdInc @ RegistersReadWriteChecking
        uint256 incW2;                   // RdInc @ RegistersValEvaluation
        uint256[] rCycleIncStage2;       // cycle point of RamInc @ RamRW (BE)
        uint256[] rCycleIncStage4;       // cycle point of RamInc @ RamValCheck (BE)
        uint256[] sCycleIncStage4;       // cycle point of RdInc @ RegistersRW (BE)
        uint256[] sCycleIncStage5;       // cycle point of RdInc @ RegistersValEval (BE)
    }

    /// @notice Evaluate identity polynomial at r_address (BE, MSB-first).
    /// IdentityPolynomial(r) = Σ_i r[i] * 2^(n-1-i) for MSB-first BE input.
    function _identityPolyEval(
        uint256[] memory rAddr,
        uint256 logK
    ) internal pure returns (uint256 result) {
        result = 0;
        for (uint256 i = 0; i < logK; i++) {
            // r[0] is MSB → weight 2^(logK-1), r[logK-1] is LSB → weight 1
            // Use addmod/mulmod: result = result * 2 + r[i]
            result = addmod(mulmod(result, 2, R), rAddr[i], R);
        }
    }

    /// @notice Compute eq(0, r) = Π_i (1 - r_i) for zero-point evaluation.
    function _eqZero(uint256[] memory r) internal pure returns (uint256 result) {
        result = 1;
        for (uint256 i = 0; i < r.length; i++) {
            result = mulmod(result, addmod(1, R - r[i], R), R);
        }
    }

    /// @notice BytecodeReadRaf val+RAF+entry contribution.
    function _bytecodeValAndEntry(
        uint256[8] memory bcGP,
        Stage6Inputs memory inputs,
        uint256[] memory rAddrPrime,
        uint256[] memory rCyclePrime,
        uint256 nCycleVars
    ) internal pure returns (uint256) {
        uint256 intPolyEval = _identityPolyEval(rAddrPrime, inputs.logKBytecode);

        // Val + RAF: Σ_s γ^s * (val_s + raf_s*int) * eq(r_cycle_s, r_cycle_prime)
        uint256 valContrib = 0;
        for (uint256 s = 0; s < 5; s++) {
            uint256 rafWeight = 0;
            if (s == 0) rafWeight = bcGP[5];
            else if (s == 2) rafWeight = bcGP[4];

            uint256 valPlusRaf = addmod(inputs.valPolyEvals[s], mulmod(rafWeight, intPolyEval, R), R);

            uint256[] memory rCycleS = new uint256[](nCycleVars);
            for (uint256 j = 0; j < nCycleVars; j++) {
                rCycleS[j] = inputs.rCycles[s * nCycleVars + j];
            }

            valContrib = addmod(
                valContrib,
                mulmod(bcGP[s], mulmod(valPlusRaf, EqPolynomial.mle(rCycleS, rCyclePrime), R), R),
                R
            );
        }

        // Entry constraint: γ^7 * eq(entry_bits, r_addr) * eq_zero(r_cycle)
        uint256 logK = inputs.logKBytecode;
        uint256[] memory entryBits = new uint256[](logK);
        uint256 e = inputs.entryBytecodeIndex;
        for (uint256 i = 0; i < logK; i++) {
            entryBits[i] = (e >> (logK - 1 - i)) & 1;
        }

        return addmod(
            valContrib,
            mulmod(bcGP[7], mulmod(EqPolynomial.mle(entryBits, rAddrPrime), _eqZero(rCyclePrime), R), R),
            R
        );
    }

    /// @notice BytecodeReadRaf expected_output_claim = valAndEntry * Π ra_i.
    function _bytecodeReadRafOutput(
        uint256[8] memory bcGP,
        Stage6Inputs memory inputs,
        uint256[] memory challenges,
        uint256[] memory flushedClaims,
        uint256 nCycleVars
    ) internal pure returns (uint256) {
        uint256 logK = inputs.logKBytecode;
        uint256[] memory rAddrPrime = new uint256[](logK);
        for (uint256 i = 0; i < logK; i++) rAddrPrime[i] = challenges[logK - 1 - i];

        uint256[] memory rCyclePrime = _extractReversedCycleChallenges(challenges, logK, nCycleVars);

        uint256 valAndEntry = _bytecodeValAndEntry(bcGP, inputs, rAddrPrime, rCyclePrime, nCycleVars);

        uint256 raProduct = 1;
        for (uint256 i = 0; i < inputs.bytecodeD; i++) {
            raProduct = mulmod(raProduct, flushedClaims[i], R);
        }

        return mulmod(valAndEntry, raProduct, R);
    }

    /// @notice Packed gamma values for Stage 6 to avoid stack depth.
    struct Stage6Gammas {
        uint256[8] bcGP;
        uint256 boolGamma;
        uint256 lookupsRaGammaBase;
        uint256 incGamma;
        uint256 incGammaSqr;
    }

    /// @notice Compute Stage 6 instances [0]-[2] expected output.
    function _stage6Output012(
        Stage6Gammas memory g,
        Stage6Inputs memory inputs,
        uint256[] memory flushedClaims,
        uint256[] memory challenges,
        uint256[] memory batchingCoeffs,
        uint256 bytecodeRounds,
        uint256 nCycleVars
    ) internal pure returns (uint256 batchedExpected, uint256 claimIdx) {
        // [0] BytecodeReadRaf
        batchedExpected = mulmod(
            _bytecodeReadRafOutput(g.bcGP, inputs, challenges, flushedClaims, nCycleVars),
            batchingCoeffs[0],
            R
        );
        claimIdx = inputs.bytecodeD;

        // [1] Booleanity
        batchedExpected = addmod(
            batchedExpected,
            mulmod(
                _booleanityOutput(g.boolGamma, inputs, flushedClaims, claimIdx, challenges, bytecodeRounds, nCycleVars),
                batchingCoeffs[1],
                R
            ),
            R
        );
        claimIdx += inputs.totalD;

        // [2] HammingBooleanity
        {
            uint256 hammingOffset = bytecodeRounds - nCycleVars;
            uint256 h = flushedClaims[claimIdx];
            batchedExpected = addmod(
                batchedExpected,
                mulmod(
                    mulmod(addmod(mulmod(h, h, R), R - h, R), EqPolynomial.mleSliceReversed(inputs.rCycleHamming, challenges, hammingOffset, nCycleVars), R),
                    batchingCoeffs[2],
                    R
                ),
                R
            );
            claimIdx += 1;
        }
    }

    /// @notice Compute Stage 6 instances [3]-[5] expected output.
    function _stage6Output345(
        Stage6Gammas memory g,
        Stage6Inputs memory inputs,
        uint256[] memory flushedClaims,
        uint256 claimIdx,
        uint256[] memory challenges,
        uint256[] memory batchingCoeffs,
        uint256 bytecodeRounds,
        uint256 nCycleVars
    ) internal pure returns (uint256 result) {
        // [3] RamRaVirtual
        {
            uint256 ramRaOffset = bytecodeRounds - nCycleVars;
            uint256 raProduct = 1;
            for (uint256 i = 0; i < inputs.ramD; i++) {
                raProduct = mulmod(raProduct, flushedClaims[claimIdx + i], R);
            }
            result = mulmod(
                mulmod(EqPolynomial.mleSliceReversed(inputs.rCycleRamRa, challenges, ramRaOffset, nCycleVars), raProduct, R),
                batchingCoeffs[3],
                R
            );
            claimIdx += inputs.ramD;
        }

        // [4] LookupsRaVirtual
        result = addmod(
            result,
            mulmod(
                _lookupsRaOutput(g.lookupsRaGammaBase, inputs, flushedClaims, claimIdx, challenges, bytecodeRounds, nCycleVars),
                batchingCoeffs[4],
                R
            ),
            R
        );
        claimIdx += inputs.nCommittedRaPolys;

        // [5] IncClaimReduction
        result = addmod(
            result,
            mulmod(
                _incReductionOutput(g.incGamma, g.incGammaSqr, inputs, flushedClaims, claimIdx, challenges, bytecodeRounds, nCycleVars),
                batchingCoeffs[5],
                R
            ),
            R
        );
    }

    /// @notice Booleanity expected_output_claim helper.
    function _booleanityOutput(
        uint256 boolGamma,
        Stage6Inputs memory inputs,
        uint256[] memory flushedClaims,
        uint256 claimIdx,
        uint256[] memory challenges,
        uint256 bytecodeRounds,
        uint256 nCycleVars
    ) internal pure returns (uint256) {
        uint256 logKC = inputs.logKChunk;
        uint256 boolRounds = logKC + nCycleVars;
        uint256 boolOffset = bytecodeRounds - boolRounds;

        uint256 eqBool = mulmod(
            EqPolynomial.mleSlice(inputs.rAddressBool, challenges, boolOffset, logKC),
            EqPolynomial.mleSlice(inputs.rCycleBool, challenges, boolOffset + logKC, nCycleVars),
            R
        );

        uint256 boolGammaSq = mulmod(boolGamma, boolGamma, R);
        uint256 boolSum = 0;
        uint256 gamma2i = 1;
        for (uint256 i = 0; i < inputs.totalD; i++) {
            uint256 ra = flushedClaims[claimIdx + i];
            boolSum = addmod(boolSum, mulmod(gamma2i, addmod(mulmod(ra, ra, R), R - ra, R), R), R);
            gamma2i = mulmod(gamma2i, boolGammaSq, R);
        }

        return mulmod(eqBool, boolSum, R);
    }

    /// @notice LookupsRaVirtual expected_output_claim helper.
    function _lookupsRaOutput(
        uint256 lookupsRaGammaBase,
        Stage6Inputs memory inputs,
        uint256[] memory flushedClaims,
        uint256 claimIdx,
        uint256[] memory challenges,
        uint256 bytecodeRounds,
        uint256 nCycleVars
    ) internal pure returns (uint256) {
        uint256 lookupOffset = bytecodeRounds - nCycleVars;
        uint256 eqL = EqPolynomial.mleSliceReversed(inputs.rCycleLookupsRa, challenges, lookupOffset, nCycleVars);
        uint256 m = inputs.nCommittedPerVirtual;

        uint256 raAcc = 0;
        uint256 gPow = 1;
        for (uint256 i = 0; i < inputs.nVirtualRaPolys; i++) {
            uint256 prod = 1;
            for (uint256 j = 0; j < m; j++) {
                prod = mulmod(prod, flushedClaims[claimIdx + i * m + j], R);
            }
            raAcc = addmod(raAcc, mulmod(gPow, prod, R), R);
            gPow = mulmod(gPow, lookupsRaGammaBase, R);
        }

        return mulmod(eqL, raAcc, R);
    }

    /// @notice IncClaimReduction expected_output_claim helper.
    function _incReductionOutput(
        uint256 incGamma,
        uint256 incGammaSqr,
        Stage6Inputs memory inputs,
        uint256[] memory flushedClaims,
        uint256 claimIdx,
        uint256[] memory challenges,
        uint256 bytecodeRounds,
        uint256 nCycleVars
    ) internal pure returns (uint256) {
        uint256 incOffset = bytecodeRounds - nCycleVars;

        uint256 eqRam;
        uint256 eqRd;
        {
            uint256 eqInc2 = EqPolynomial.mleSliceReversed(inputs.rCycleIncStage2, challenges, incOffset, nCycleVars);
            uint256 eqInc4 = EqPolynomial.mleSliceReversed(inputs.rCycleIncStage4, challenges, incOffset, nCycleVars);
            eqRam = addmod(eqInc2, mulmod(incGamma, eqInc4, R), R);
        }
        {
            uint256 eqS4 = EqPolynomial.mleSliceReversed(inputs.sCycleIncStage4, challenges, incOffset, nCycleVars);
            uint256 eqS5 = EqPolynomial.mleSliceReversed(inputs.sCycleIncStage5, challenges, incOffset, nCycleVars);
            eqRd = addmod(eqS4, mulmod(incGamma, eqS5, R), R);
        }

        return addmod(
            mulmod(flushedClaims[claimIdx], eqRam, R),
            mulmod(incGammaSqr, mulmod(flushedClaims[claimIdx + 1], eqRd, R), R),
            R
        );
    }

    /// @notice Extract reversed cycle-only challenges at a given offset.
    function _extractReversedCycleChallenges(
        uint256[] memory challenges,
        uint256 offset,
        uint256 nCycleVars
    ) internal pure returns (uint256[] memory r) {
        r = new uint256[](nCycleVars);
        for (uint256 i = 0; i < nCycleVars; i++) {
            r[i] = challenges[offset + nCycleVars - 1 - i];
        }
    }

    /// @notice Verify Stage 6 sumcheck and flush opening claims.
    function verifyStage6(
        JoltTranscript.Transcript memory t,
        Stage6Proof memory proof,
        Stage6Inputs memory inputs,
        uint256 nCycleVars
    ) internal pure returns (uint256[] memory challenges) {
        // 1. Sample all challenges from transcript (exact order matters)
        uint256 bytecodeGammaBase = t.challengeScalar();
        t.challengeScalar(); // stage1GammaBase
        t.challengeScalar(); // stage2GammaBase
        t.challengeScalar(); // stage3GammaBase
        t.challengeScalar(); // stage4GammaBase
        t.challengeScalar(); // stage5GammaBase
        uint256 boolGamma = t.challengeScalarMont();
        uint256 lookupsRaGammaBase = t.challengeScalar();
        uint256 incGamma = t.challengeScalar();

        // Precompute bytecode gamma powers
        uint256[8] memory bcGP;
        bcGP[0] = 1;
        for (uint256 i = 1; i < 8; i++) bcGP[i] = mulmod(bcGP[i - 1], bytecodeGammaBase, R);

        uint256 incGammaSqr = mulmod(incGamma, incGamma, R);

        // 2. Compute input claims
        uint256[] memory instanceClaims = new uint256[](6);
        instanceClaims[0] = inputs.bytecodeInputClaim;
        // [1] Booleanity: 0, [2] HammingBooleanity: 0
        instanceClaims[3] = inputs.ramRaInputClaim;

        // [4] LookupsRaVirtual: Σ_i γ^i * ra_i_claim
        {
            uint256 claim = 0;
            uint256 gPow = 1;
            for (uint256 i = 0; i < inputs.nVirtualRaPolys; i++) {
                claim = addmod(claim, mulmod(gPow, inputs.lookupsRaInputClaims[i], R), R);
                gPow = mulmod(gPow, lookupsRaGammaBase, R);
            }
            instanceClaims[4] = claim;
        }

        // [5] IncClaimReduction: v1 + γ*v2 + γ²*w1 + γ³*w2
        {
            uint256 incGammaCub = mulmod(incGammaSqr, incGamma, R);
            instanceClaims[5] = addmod(
                addmod(inputs.incV1, mulmod(incGamma, inputs.incV2, R), R),
                addmod(mulmod(incGammaSqr, inputs.incW1, R), mulmod(incGammaCub, inputs.incW2, R), R),
                R
            );
        }

        // 3. Run batched sumcheck
        uint256 bytecodeRounds = inputs.logKBytecode + nCycleVars;

        uint256[] memory instanceNumRounds = new uint256[](6);
        instanceNumRounds[0] = bytecodeRounds;
        instanceNumRounds[1] = inputs.logKChunk + nCycleVars;
        instanceNumRounds[2] = nCycleVars;
        instanceNumRounds[3] = nCycleVars;
        instanceNumRounds[4] = nCycleVars;
        instanceNumRounds[5] = nCycleVars;

        uint256 maxDeg = inputs.bytecodeD + 1;
        if (inputs.ramD + 1 > maxDeg) maxDeg = inputs.ramD + 1;
        if (inputs.nCommittedPerVirtual + 1 > maxDeg) maxDeg = inputs.nCommittedPerVirtual + 1;
        if (3 > maxDeg) maxDeg = 3;

        uint256 finalClaim;
        uint256[] memory batchingCoeffs;
        (finalClaim, challenges, batchingCoeffs) = BatchedSumcheckVerifier.verify(
            proof.compressedPolys,
            instanceClaims,
            instanceNumRounds,
            maxDeg,
            t
        );

        // 4-5. Compute and verify expected output claims
        {
            Stage6Gammas memory g;
            g.bcGP = bcGP;
            g.boolGamma = boolGamma;
            g.lookupsRaGammaBase = lookupsRaGammaBase;
            g.incGamma = incGamma;
            g.incGammaSqr = incGammaSqr;

            (uint256 be012, uint256 claimIdx) = _stage6Output012(
                g, inputs, proof.flushedClaims, challenges, batchingCoeffs,
                bytecodeRounds, nCycleVars
            );
            uint256 be345 = _stage6Output345(
                g, inputs, proof.flushedClaims, claimIdx, challenges, batchingCoeffs,
                bytecodeRounds, nCycleVars
            );
            require(finalClaim == addmod(be012, be345, R), "stage6: output claim mismatch");
        }

        // 6. Flush all opening claims to transcript
        for (uint256 i = 0; i < proof.flushedClaims.length; i++) {
            t.appendLabeledScalar(
                bytes32(bytes13("opening_claim")),
                proof.flushedClaims[i]
            );
        }
    }

    // ================================================================
    //  Stage 7: HammingWeightClaimReduction (+ optional Advice address)
    // ================================================================
    //
    // One mandatory instance:
    //   [0] HammingWeightClaimReductionVerifier (degree: 2)
    //       num_rounds = logKChunk
    //
    // Transcript operations:
    //   1. challengeScalar() → hwGamma
    //
    // Flushed claims: N ra polynomial claims (one per polynomial type)
    //
    // input_claim: Σ_i (γ^{3i} * H_i + γ^{3i+1} * bool_i + γ^{3i+2} * virt_i)
    //   where H_i, bool_i, virt_i come from prior stage opening values
    //
    // expected_output_claim:
    //   Σ_i G_i * (γ^{3i} + γ^{3i+1} * eq(r_addr_bool, ρ_rev) + γ^{3i+2} * eq(r_addr_virt_i, ρ_rev))

    struct Stage7Proof {
        uint256[][] compressedPolys;
        uint256[] flushedClaims; // N ra polynomial claims
    }

    struct Stage7Inputs {
        uint256 logKChunk;
        uint256 nPolynomials;             // N = total number of ra polynomial types
        // Per-polynomial input claim components (3 * N values):
        uint256[] hwClaims;               // [N] Hamming weight claims H_i
        uint256[] boolClaims;             // [N] Booleanity claims bool_i
        uint256[] virtClaims;             // [N] Virtualization claims virt_i
        // Reference points for expected_output:
        uint256[] rAddrBool;              // r_addr_bool from Booleanity (BE, logKChunk)
        uint256[][] rAddrVirt;            // [N] per-polynomial r_addr_virt_i (BE, logKChunk)
    }

    /// @notice Verify Stage 7 sumcheck and flush opening claims.
    function verifyStage7(
        JoltTranscript.Transcript memory t,
        Stage7Proof memory proof,
        Stage7Inputs memory inputs
    ) internal pure returns (uint256[] memory challenges) {
        // 1. Sample challenge
        uint256 hwGamma = t.challengeScalar();
        uint256 N = inputs.nPolynomials;

        // Precompute 3N gamma powers: γ^0, γ^1, ..., γ^{3N-1}
        uint256[] memory gammaPowers = new uint256[](3 * N);
        {
            gammaPowers[0] = 1;
            for (uint256 i = 1; i < 3 * N; i++) {
                gammaPowers[i] = mulmod(gammaPowers[i - 1], hwGamma, R);
            }
        }

        // 2. Compute input claim
        // Σ_i (γ^{3i} * H_i + γ^{3i+1} * bool_i + γ^{3i+2} * virt_i)
        uint256[] memory instanceClaims = new uint256[](1);
        {
            uint256 claim = 0;
            for (uint256 i = 0; i < N; i++) {
                claim = addmod(claim, mulmod(gammaPowers[3 * i], inputs.hwClaims[i], R), R);
                claim = addmod(claim, mulmod(gammaPowers[3 * i + 1], inputs.boolClaims[i], R), R);
                claim = addmod(claim, mulmod(gammaPowers[3 * i + 2], inputs.virtClaims[i], R), R);
            }
            instanceClaims[0] = claim;
        }

        // 3. Run batched sumcheck
        uint256[] memory instanceNumRounds = new uint256[](1);
        instanceNumRounds[0] = inputs.logKChunk;

        uint256 finalClaim;
        uint256[] memory batchingCoeffs;
        (finalClaim, challenges, batchingCoeffs) = BatchedSumcheckVerifier.verify(
            proof.compressedPolys,
            instanceClaims,
            instanceNumRounds,
            2, // degree
            t
        );

        // 4. Compute expected output claim
        // Σ_i G_i * (γ^{3i} + γ^{3i+1} * eq_bool + γ^{3i+2} * eq_virt_i)
        // where G_i = flushedClaims[i], ρ_rev = challenges reversed
        uint256[] memory rhoRev = _reverse(challenges);

        uint256 eqBoolEval = EqPolynomial.mle(rhoRev, inputs.rAddrBool);

        uint256 batchedExpected = 0;
        for (uint256 i = 0; i < N; i++) {
            uint256 eqVirtEval = EqPolynomial.mle(rhoRev, inputs.rAddrVirt[i]);
            uint256 gi = proof.flushedClaims[i];

            uint256 weight = addmod(
                gammaPowers[3 * i],
                addmod(
                    mulmod(gammaPowers[3 * i + 1], eqBoolEval, R),
                    mulmod(gammaPowers[3 * i + 2], eqVirtEval, R),
                    R
                ),
                R
            );

            batchedExpected = addmod(batchedExpected, mulmod(gi, weight, R), R);
        }

        // With only 1 instance, batchingCoeffs[0] = 1 after normalization
        // but we still multiply for correctness
        batchedExpected = mulmod(batchedExpected, batchingCoeffs[0], R);

        // 5. Verify output claim
        require(finalClaim == batchedExpected, "stage7: output claim mismatch");

        // 6. Flush opening claims
        for (uint256 i = 0; i < N; i++) {
            t.appendLabeledScalar(
                bytes32(bytes13("opening_claim")),
                proof.flushedClaims[i]
            );
        }
    }
}
