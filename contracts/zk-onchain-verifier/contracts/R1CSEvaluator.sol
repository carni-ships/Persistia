// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title R1CS Evaluator
/// @notice Evaluates the Jolt R1CS Az·Bz product at a given point for the Spartan
/// outer sumcheck expected output claim.
///
/// The 19 uniform R1CS constraints are split into two groups:
///   Group 1 (10 constraints): boolean-guarded eq constraints
///   Group 2 (9 constraints): wider arithmetic
///
/// Each constraint is (A, B) where A=condition, B=left-right.
/// Az = Σ_i w[i] * A_i · z,  Bz = Σ_i w[i] * B_i · z
/// Blended: Az_final = Az_g0 + r_stream * (Az_g1 - Az_g0), same for Bz
/// Result: Az_final * Bz_final
///
/// z vector indices (JoltR1CSInputs canonical ordering):
///   0:  LeftInstructionInput    1:  RightInstructionInput
///   2:  Product                 3:  ShouldBranch
///   4:  PC                     5:  UnexpandedPC
///   6:  Imm                    7:  RamAddress
///   8:  Rs1Value               9:  Rs2Value
///   10: RdWriteValue           11: RamReadValue
///   12: RamWriteValue          13: LeftLookupOperand
///   14: RightLookupOperand     15: NextUnexpandedPC
///   16: NextPC                 17: NextIsVirtual
///   18: NextIsFirstInSequence  19: LookupOutput
///   20: ShouldJump             21: OpFlags(Add)
///   22: OpFlags(Sub)           23: OpFlags(Mul)
///   24: OpFlags(Load)          25: OpFlags(Store)
///   26: OpFlags(Jump)          27: OpFlags(WriteLookupOutputToRD)
///   28: OpFlags(VirtualInstr)  29: OpFlags(Assert)
///   30: OpFlags(IsLastInSeq)   31: OpFlags(DoNotUpdatePC)
///   32: OpFlags(IsCompressed)  33: OpFlags(Branch)
///   34: OpFlags(Advice)
library R1CSEvaluator {
    uint256 internal constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 internal constant NUM_R1CS_INPUTS = 35;

    /// @notice Evaluate Az·Bz for the Spartan outer R1CS at a given point.
    /// @param z The 35 R1CS input evaluations at the opening point
    /// @param w Lagrange weights at r0 over the 10-element domain (for both groups)
    /// @param rStream The r_stream challenge (first sumcheck challenge after uni-skip)
    /// @return The Az_final * Bz_final product
    function evaluateAzBz(
        uint256[35] memory z,
        uint256[10] memory w,
        uint256 rStream
    ) internal pure returns (uint256) {
        // Group 1: 10 constraints
        (uint256 azG0, uint256 bzG0) = _group1(z, w);

        // Group 2: 9 constraints (uses same w[0..8])
        (uint256 azG1, uint256 bzG1) = _group2(z, w);

        // Blend: Az = azG0 + rStream * (azG1 - azG0)
        uint256 azFinal = addmod(
            azG0,
            mulmod(rStream, addmod(azG1, R - azG0, R), R),
            R
        );
        uint256 bzFinal = addmod(
            bzG0,
            mulmod(rStream, addmod(bzG1, R - bzG0, R), R),
            R
        );

        return mulmod(azFinal, bzFinal, R);
    }

    /// @notice Group 1: 10 constraints (first-group, boolean-guarded eq)
    /// Order matches R1CS_CONSTRAINTS_FIRST_GROUP:
    ///   [0] RamAddrEqZeroIfNotLoadStore
    ///   [1] RamReadEqRamWriteIfLoad
    ///   [2] RamReadEqRdWriteIfLoad
    ///   [3] Rs2EqRamWriteIfStore
    ///   [4] LeftLookupZeroUnlessAddSubMul
    ///   [5] LeftLookupEqLeftInputOtherwise
    ///   [6] AssertLookupOne
    ///   [7] NextUnexpPCEqLookupIfShouldJump
    ///   [8] NextPCEqPCPlusOneIfInline
    ///   [9] MustStartSequenceFromBeginning
    function _group1(
        uint256[35] memory z,
        uint256[10] memory w
    ) internal pure returns (uint256 az, uint256 bz) {
        uint256 a; uint256 b;

        // [0] A = 1 - Load - Store, B = RamAddress
        a = addmod(addmod(1, R - z[24], R), R - z[25], R);
        b = z[7];
        az = addmod(az, mulmod(w[0], a, R), R);
        bz = addmod(bz, mulmod(w[0], b, R), R);

        // [1] A = Load, B = RamReadValue - RamWriteValue
        a = z[24];
        b = addmod(z[11], R - z[12], R);
        az = addmod(az, mulmod(w[1], a, R), R);
        bz = addmod(bz, mulmod(w[1], b, R), R);

        // [2] A = Load, B = RamReadValue - RdWriteValue
        a = z[24];
        b = addmod(z[11], R - z[10], R);
        az = addmod(az, mulmod(w[2], a, R), R);
        bz = addmod(bz, mulmod(w[2], b, R), R);

        // [3] A = Store, B = Rs2Value - RamWriteValue
        a = z[25];
        b = addmod(z[9], R - z[12], R);
        az = addmod(az, mulmod(w[3], a, R), R);
        bz = addmod(bz, mulmod(w[3], b, R), R);

        // [4] A = Add+Sub+Mul, B = LeftLookupOperand
        a = addmod(addmod(z[21], z[22], R), z[23], R);
        b = z[13];
        az = addmod(az, mulmod(w[4], a, R), R);
        bz = addmod(bz, mulmod(w[4], b, R), R);

        // [5] A = 1-Add-Sub-Mul, B = LeftLookupOperand - LeftInstructionInput
        a = addmod(addmod(addmod(1, R - z[21], R), R - z[22], R), R - z[23], R);
        b = addmod(z[13], R - z[0], R);
        az = addmod(az, mulmod(w[5], a, R), R);
        bz = addmod(bz, mulmod(w[5], b, R), R);

        // [6] A = Assert, B = LookupOutput - 1
        a = z[29];
        b = addmod(z[19], R - 1, R);
        az = addmod(az, mulmod(w[6], a, R), R);
        bz = addmod(bz, mulmod(w[6], b, R), R);

        // [7] A = ShouldJump, B = NextUnexpandedPC - LookupOutput
        a = z[20];
        b = addmod(z[15], R - z[19], R);
        az = addmod(az, mulmod(w[7], a, R), R);
        bz = addmod(bz, mulmod(w[7], b, R), R);

        // [8] A = VirtualInstruction - IsLastInSequence, B = NextPC - PC - 1
        a = addmod(z[28], R - z[34], R);
        b = addmod(addmod(z[16], R - z[4], R), R - 1, R);
        az = addmod(az, mulmod(w[8], a, R), R);
        bz = addmod(bz, mulmod(w[8], b, R), R);

        // [9] A = NextIsVirtual - NextIsFirstInSequence, B = 1 - DoNotUpdateUnexpandedPC
        a = addmod(z[17], R - z[18], R);
        b = addmod(1, R - z[30], R);
        az = addmod(az, mulmod(w[9], a, R), R);
        bz = addmod(bz, mulmod(w[9], b, R), R);
    }

    /// @notice Group 2: 9 constraints (second-group, wider arithmetic)
    /// Order matches R1CS_CONSTRAINTS_SECOND_GROUP:
    ///   [0] RamAddrEqRs1PlusImmIfLoadStore
    ///   [1] RightLookupAdd
    ///   [2] RightLookupSub
    ///   [3] RightLookupEqProductIfMul
    ///   [4] RightLookupEqRightInputOtherwise
    ///   [5] RdWriteEqLookupIfWriteLookupToRd
    ///   [6] RdWriteEqPCPlusConstIfWritePCtoRD
    ///   [7] NextUnexpPCEqPCPlusImmIfShouldBranch
    ///   [8] NextUnexpPCUpdateOtherwise
    function _group2(
        uint256[35] memory z,
        uint256[10] memory w
    ) internal pure returns (uint256 az, uint256 bz) {
        uint256 a; uint256 b;

        // 2^64 mod R
        uint256 TWO_POW_64 = 0x10000000000000000;

        // [0] A = Load+Store, B = RamAddress - Rs1Value - Imm
        a = addmod(z[24], z[25], R);
        b = addmod(addmod(z[7], R - z[8], R), R - z[6], R);
        az = addmod(az, mulmod(w[0], a, R), R);
        bz = addmod(bz, mulmod(w[0], b, R), R);

        // [1] A = AddOperands, B = RightLookupOperand - LeftInstructionInput - RightInstructionInput
        a = z[21];
        b = addmod(addmod(z[14], R - z[0], R), R - z[1], R);
        az = addmod(az, mulmod(w[1], a, R), R);
        bz = addmod(bz, mulmod(w[1], b, R), R);

        // [2] A = SubtractOperands, B = RightLookupOperand - (LeftInput - RightInput + 2^64)
        a = z[22];
        b = addmod(
            addmod(addmod(z[14], R - z[0], R), z[1], R),
            R - (TWO_POW_64 % R),
            R
        );
        az = addmod(az, mulmod(w[2], a, R), R);
        bz = addmod(bz, mulmod(w[2], b, R), R);

        // [3] A = MultiplyOperands, B = RightLookupOperand - Product
        a = z[23];
        b = addmod(z[14], R - z[2], R);
        az = addmod(az, mulmod(w[3], a, R), R);
        bz = addmod(bz, mulmod(w[3], b, R), R);

        // [4] A = 1-Add-Sub-Mul-Advice, B = RightLookupOperand - RightInstructionInput
        a = addmod(
            addmod(addmod(addmod(1, R - z[21], R), R - z[22], R), R - z[23], R),
            R - z[31],
            R
        );
        b = addmod(z[14], R - z[1], R);
        az = addmod(az, mulmod(w[4], a, R), R);
        bz = addmod(bz, mulmod(w[4], b, R), R);

        // [5] A = WriteLookupOutputToRD, B = RdWriteValue - LookupOutput
        a = z[27];
        b = addmod(z[10], R - z[19], R);
        az = addmod(az, mulmod(w[5], a, R), R);
        bz = addmod(bz, mulmod(w[5], b, R), R);

        // [6] A = Jump, B = RdWriteValue - UnexpandedPC - 4 + 2*IsCompressed
        a = z[26];
        b = addmod(
            addmod(addmod(z[10], R - z[5], R), R - 4, R),
            mulmod(2, z[32], R),
            R
        );
        az = addmod(az, mulmod(w[6], a, R), R);
        bz = addmod(bz, mulmod(w[6], b, R), R);

        // [7] A = ShouldBranch, B = NextUnexpandedPC - UnexpandedPC - Imm
        a = z[3];
        b = addmod(addmod(z[15], R - z[5], R), R - z[6], R);
        az = addmod(az, mulmod(w[7], a, R), R);
        bz = addmod(bz, mulmod(w[7], b, R), R);

        // [8] A = 1-ShouldBranch-Jump, B = NextUnexpPC - UnexpPC - 4 + 4*DoNotUpdateUnexpPC + 2*IsCompressed
        a = addmod(addmod(1, R - z[3], R), R - z[26], R);
        b = addmod(
            addmod(
                addmod(addmod(z[15], R - z[5], R), R - 4, R),
                mulmod(4, z[30], R),
                R
            ),
            mulmod(2, z[32], R),
            R
        );
        az = addmod(az, mulmod(w[8], a, R), R);
        bz = addmod(bz, mulmod(w[8], b, R), R);
    }

    /// @notice Compute Lagrange weights for domain {-4,-3,-2,-1,0,1,2,3,4,5} at point x.
    /// L_i(x) = Π_{j≠i} (x - t_j) / Π_{j≠i} (t_i - t_j)
    /// Denominators are precomputed: denom[k] = k! * (9-k)! * (-1)^(9-k)
    function lagrangeWeights10(uint256 x) internal pure returns (uint256[10] memory w) {
        // Domain points as field elements: [R-4, R-3, R-2, R-1, 0, 1, 2, 3, 4, 5]
        uint256[10] memory t;
        t[0] = R - 4; t[1] = R - 3; t[2] = R - 2; t[3] = R - 1; t[4] = 0;
        t[5] = 1; t[6] = 2; t[7] = 3; t[8] = 4; t[9] = 5;

        // Precomputed inverse denominators: invDenom[k] = (k! * (9-k)! * (-1)^(9-k))^{-1} mod R
        uint256[10] memory invDenom;
        invDenom[0] = 0x1fa597e0a11384dc18aa8ea0f0adb6f1956f8aab1737b5a796c749fb3df8958a;
        invDenom[1] = 0x05877fcb9d7a153d73e29e9e92eca3b0b04b91af096340834a4a27a27242be2c;
        invDenom[2] = 0x1a464f446b494b33e8c5cb3c35cec99a6705a18c542c6e841ab9570a26f50751;
        invDenom[3] = 0x033704f98741d0be81482d66d9c9f4be9a8d676e888f94381c277c583a6eeeef;
        invDenom[4] = 0x135f9fc325b616f71a3bdec0fa11bd10ac45d8fe700559f477b5c045a059999a;
        invDenom[5] = 0x1d04aeafbb7b89329e1466f5876f9b4c7bee0f4a09b4169ccc2c354e4fa66667;
        invDenom[6] = 0x2d2d497959efcf6b3708184fa7b7639e8da680d9f129dc5927ba793bb5911112;
        invDenom[7] = 0x161dff2e75e854f5cf8a7a7a4bb28ec2c12e46bc258d020d29289e89c90af8b0;
        invDenom[8] = 0x2adccea743b78aec446da717ee94b4ac77e856997056300df997cdf17dbd41d5;
        invDenom[9] = 0x10beb692401e1b4d9fa5b71590d3a16b92c45d9d6281bae9ad1aab98b2076a77;

        // Compute (x - t_j) for each domain point
        uint256[10] memory diff;
        for (uint256 i = 0; i < 10; i++) {
            diff[i] = addmod(x, R - t[i], R);
        }

        // Prefix/suffix products for numerators
        uint256[10] memory prefix;
        uint256[10] memory suffix;
        prefix[0] = 1;
        for (uint256 i = 1; i < 10; i++) {
            prefix[i] = mulmod(prefix[i-1], diff[i-1], R);
        }
        suffix[9] = 1;
        for (uint256 i = 9; i > 0; ) {
            unchecked { i--; }
            suffix[i] = mulmod(suffix[i+1], diff[i+1], R);
        }

        // w[i] = numerator[i] * invDenom[i]
        for (uint256 i = 0; i < 10; i++) {
            w[i] = mulmod(mulmod(prefix[i], suffix[i], R), invDenom[i], R);
        }
    }
}
