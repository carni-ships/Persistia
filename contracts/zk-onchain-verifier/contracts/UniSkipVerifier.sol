// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./JoltTranscript.sol";

/// @title Univariate Skip Verifier
/// @notice Verifies the univariate-skip first round of Spartan outer and
/// product virtualization sumchecks.
///
/// The univariate-skip optimization replaces the first round of a sumcheck
/// with a high-degree univariate polynomial evaluation. The prover sends
/// s1(Y) as coefficients; the verifier checks:
///   Σ_{t in symmetric_domain} s1(t) == input_claim
/// then derives challenge r0 and evaluates s1(r0) as the next claim.
library UniSkipVerifier {
    using JoltTranscript for JoltTranscript.Transcript;

    uint256 internal constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 internal constant OUTER_NUM_COEFFS = 28;
    uint256 internal constant PRODUCT_NUM_COEFFS = 7;

    /// @notice Verify the outer univariate-skip first round.
    /// Domain: {-4,-3,-2,-1,0,1,2,3,4,5} (symmetric 10-element window)
    /// input_claim = 0 (symmetric domain property)
    function verifyOuterUniSkip(
        JoltTranscript.Transcript memory t,
        uint256[] calldata uniPolyCoeffs
    ) internal pure returns (uint256 r0, uint256 claim) {
        require(uniPolyCoeffs.length <= OUTER_NUM_COEFFS, "outer uniskip degree too high");

        // Append polynomial to transcript (label = "uniskip_poly", 12 bytes)
        {
            uint256[] memory coeffsCopy = new uint256[](uniPolyCoeffs.length);
            for (uint256 i = 0; i < uniPolyCoeffs.length; i++) {
                coeffsCopy[i] = uniPolyCoeffs[i];
            }
            t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), coeffsCopy);
        }

        // Derive challenge r0 (Montgomery variant to match Rust challenge_scalar_optimized)
        r0 = t.challengeScalarMont();

        // Check: Σ_{t in domain} s1(t) == 0
        uint256 domainSum = _computeOuterDomainSum(uniPolyCoeffs);
        require(domainSum == 0, "outer uniskip sum check failed");

        // Evaluate s1(r0)
        claim = _evaluateUniPoly(uniPolyCoeffs, r0);
    }

    /// @notice Verify the product virtualization univariate-skip first round.
    /// Domain: {-1,0,1} (symmetric 3-element window)
    function verifyProductUniSkip(
        JoltTranscript.Transcript memory t,
        uint256[] calldata uniPolyCoeffs,
        uint256 inputClaim
    ) internal pure returns (uint256 r0, uint256 claim) {
        require(uniPolyCoeffs.length <= PRODUCT_NUM_COEFFS, "product uniskip degree too high");

        // Append polynomial to transcript
        {
            uint256[] memory coeffsCopy = new uint256[](uniPolyCoeffs.length);
            for (uint256 i = 0; i < uniPolyCoeffs.length; i++) {
                coeffsCopy[i] = uniPolyCoeffs[i];
            }
            t.appendLabeledScalars(bytes24(bytes12("uniskip_poly")), coeffsCopy);
        }

        // Derive challenge r0 (Montgomery variant to match Rust challenge_scalar_optimized)
        r0 = t.challengeScalarMont();

        // Check domain sum
        uint256 domainSum = _computeProductDomainSum(uniPolyCoeffs);
        require(domainSum == inputClaim, "product uniskip sum check failed");

        // Evaluate s1(r0)
        claim = _evaluateUniPoly(uniPolyCoeffs, r0);
    }

    // ================================================================
    //  Domain sum computation
    // ================================================================

    /// @notice Σ_{t=-4}^{5} s(t) for outer domain
    function _computeOuterDomainSum(uint256[] calldata coeffs) internal pure returns (uint256 sum) {
        // Evaluate at each of the 10 domain points and sum
        // Points: -4, -3, -2, -1, 0, 1, 2, 3, 4, 5
        sum = 0;
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, -4), R);
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, -3), R);
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, -2), R);
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, -1), R);
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, 0), R);
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, 1), R);
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, 2), R);
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, 3), R);
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, 4), R);
        sum = addmod(sum, _evaluateUniPolyAtInt(coeffs, 5), R);
    }

    /// @notice Σ_{t=-1}^{1} s(t) for product domain
    function _computeProductDomainSum(uint256[] calldata coeffs) internal pure returns (uint256 sum) {
        sum = addmod(
            addmod(
                _evaluateUniPolyAtInt(coeffs, -1),
                _evaluateUniPolyAtInt(coeffs, 0),
                R
            ),
            _evaluateUniPolyAtInt(coeffs, 1),
            R
        );
    }

    // ================================================================
    //  Polynomial evaluation
    // ================================================================

    /// @notice Evaluate polynomial at a field element using Horner's method.
    /// Coefficients in ascending order: p(x) = c0 + c1*x + c2*x^2 + ...
    function _evaluateUniPoly(uint256[] calldata coeffs, uint256 x) internal pure returns (uint256 result) {
        if (coeffs.length == 0) return 0;
        result = coeffs[coeffs.length - 1];
        for (uint256 i = coeffs.length - 1; i > 0; ) {
            unchecked { i--; }
            result = addmod(mulmod(result, x, R), coeffs[i], R);
        }
    }

    /// @notice Evaluate polynomial at a small signed integer.
    function _evaluateUniPolyAtInt(uint256[] calldata coeffs, int256 point) internal pure returns (uint256 result) {
        if (coeffs.length == 0) return 0;
        uint256 x;
        if (point >= 0) {
            x = uint256(point);
        } else {
            x = R - uint256(-point);
        }
        result = coeffs[coeffs.length - 1];
        for (uint256 i = coeffs.length - 1; i > 0; ) {
            unchecked { i--; }
            result = addmod(mulmod(result, x, R), coeffs[i], R);
        }
    }

    // ================================================================
    //  Lagrange helpers
    // ================================================================

    /// @notice Lagrange basis evaluation at x for domain {-1, 0, 1}.
    /// Returns [L_{-1}(x), L_0(x), L_1(x)]
    function lagrangeEvals3(uint256 x) internal pure returns (uint256[3] memory w) {
        uint256 inv2 = (R + 1) / 2;
        uint256 xSq = mulmod(x, x, R);
        // L_{-1}(x) = x*(x-1)/2
        w[0] = mulmod(mulmod(x, addmod(x, R - 1, R), R), inv2, R);
        // L_0(x) = 1 - x^2
        w[1] = addmod(1, R - xSq, R);
        // L_1(x) = x*(x+1)/2
        w[2] = mulmod(mulmod(x, addmod(x, 1, R), R), inv2, R);
    }

    /// @notice Lagrange kernel for domain {-1,0,1}: L(tau,r) = Σ_i L_i(tau)*L_i(r)
    function lagrangeKernel3(uint256 tau, uint256 r) internal pure returns (uint256 result) {
        uint256[3] memory wTau = lagrangeEvals3(tau);
        uint256[3] memory wR = lagrangeEvals3(r);
        result = 0;
        for (uint256 i = 0; i < 3; i++) {
            result = addmod(result, mulmod(wTau[i], wR[i], R), R);
        }
    }
}
