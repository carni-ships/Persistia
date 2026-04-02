// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./JoltTranscript.sol";

/// @title Sumcheck Verifier
/// @notice Solidity port of jolt-core's ClearSumcheckProof::verify and
/// CompressedUniPoly::eval_from_hint.
///
/// The sumcheck protocol reduces a multilinear polynomial claim to a
/// single-point evaluation via a sequence of univariate rounds.
/// Each round's polynomial is sent in "compressed" form (all coefficients
/// except the linear term, which is recoverable from the claim).
library SumcheckVerifier {
    using JoltTranscript for JoltTranscript.Transcript;

    // BN254 scalar field order
    uint256 internal constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @notice A compressed univariate polynomial.
    /// Stores [c0, c2, c3, ...] — all coefficients except the linear term c1.
    /// c1 is recovered from the hint (previous round's claim = f(0) + f(1)).
    struct CompressedUniPoly {
        uint256[] coeffsExceptLinear;
    }

    /// @notice Evaluate a compressed univariate polynomial at challenge point x.
    /// @param hint The claim from the previous round: hint = f(0) + f(1) = 2*c0 + c1 + c2 + c3 + ...
    /// @param x The challenge point (128-bit value in uint256)
    /// @return result The evaluation f(x)
    function evalFromHint(
        uint256[] memory coeffs,
        uint256 hint,
        uint256 x
    ) internal pure returns (uint256 result) {
        assembly {
            let r := R
            let len := mload(coeffs)
            // coeffs[0] is at coeffs + 0x20
            let dataPtr := add(coeffs, 0x20)
            let c0 := mload(dataPtr)

            // linearTerm = hint - 2*c0 - sum(coeffs[1..])
            let linearTerm := addmod(hint, sub(r, addmod(c0, c0, r)), r)
            for { let i := 1 } lt(i, len) { i := add(i, 1) } {
                linearTerm := addmod(linearTerm, sub(r, mload(add(dataPtr, mul(i, 0x20)))), r)
            }

            // result = c0 + x*linearTerm + x^2*coeffs[1] + x^3*coeffs[2] + ...
            let runPow := x
            result := addmod(c0, mulmod(x, linearTerm, r), r)
            for { let i := 1 } lt(i, len) { i := add(i, 1) } {
                runPow := mulmod(runPow, x, r)
                result := addmod(result, mulmod(mload(add(dataPtr, mul(i, 0x20))), runPow, r), r)
            }
        }
    }

    /// @notice Verify a single (non-batched) sumcheck proof.
    /// @param compressedPolys Array of compressed polynomial coefficients per round.
    ///        compressedPolys[i] contains [c0, c2, c3, ...] for round i.
    /// @param claim The initial claim value.
    /// @param numRounds Number of sumcheck rounds.
    /// @param degreeBound Maximum polynomial degree per round.
    /// @param t The Fiat-Shamir transcript (mutated in place).
    /// @return finalClaim The final evaluation claim.
    /// @return challenges The challenge vector r = (r_0, r_1, ..., r_{numRounds-1}).
    function verify(
        uint256[][] memory compressedPolys,
        uint256 claim,
        uint256 numRounds,
        uint256 degreeBound,
        JoltTranscript.Transcript memory t
    )
        internal
        pure
        returns (uint256 finalClaim, uint256[] memory challenges)
    {
        require(compressedPolys.length == numRounds, "wrong number of rounds");
        challenges = new uint256[](numRounds);
        uint256 e = claim;

        for (uint256 i = 0; i < numRounds; i++) {
            // Degree check: coeffs_except_linear.length == degree
            require(compressedPolys[i].length <= degreeBound, "degree exceeds bound");

            // Append compressed polynomial coefficients to transcript
            // Label: "sumcheck_poly" (13 bytes, fits in bytes24)
            t.appendLabeledScalars(
                bytes24(bytes13("sumcheck_poly")),
                compressedPolys[i]
            );

            // Derive Montgomery challenge (matches challenge_scalar_optimized in Rust)
            uint256 r_i = t.challengeScalarMont();
            challenges[i] = r_i;

            // Evaluate polynomial at challenge; claim becomes the hint
            e = evalFromHint(compressedPolys[i], e, r_i);
        }

        finalClaim = e;
    }

    /// @notice Multiply a field element by 2^pow (mod R).
    /// Uses repeated doubling (8 gas/iter) instead of modexp precompile (~200+ gas).
    function mulPow2(uint256 value, uint256 pow) internal pure returns (uint256) {
        for (uint256 i = 0; i < pow; i++) {
            value = addmod(value, value, R);
        }
        return value;
    }
}
