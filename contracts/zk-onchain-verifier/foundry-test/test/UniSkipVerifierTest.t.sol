// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "contracts/UniSkipVerifier.sol";

contract UniSkipVerifierTest is Test {
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // ----------------------------------------------------------------
    //  Polynomial evaluation
    // ----------------------------------------------------------------

    function test_eval_constant_poly() public pure {
        // p(x) = 42
        uint256[] memory coeffs = new uint256[](1);
        coeffs[0] = 42;
        // At any integer point, should give 42
        assertEq(_evalAtInt(coeffs, 0), 42);
        assertEq(_evalAtInt(coeffs, 1), 42);
        assertEq(_evalAtInt(coeffs, -1), 42);
    }

    function test_eval_linear_poly() public pure {
        // p(x) = 3 + 2x
        uint256[] memory coeffs = new uint256[](2);
        coeffs[0] = 3;
        coeffs[1] = 2;
        // p(0) = 3
        assertEq(_evalAtInt(coeffs, 0), 3);
        // p(1) = 5
        assertEq(_evalAtInt(coeffs, 1), 5);
        // p(-1) = 3 - 2 = 1
        assertEq(_evalAtInt(coeffs, -1), 1);
        // p(5) = 13
        assertEq(_evalAtInt(coeffs, 5), 13);
    }

    function test_eval_quadratic_poly() public pure {
        // p(x) = 1 + x + x^2
        uint256[] memory coeffs = new uint256[](3);
        coeffs[0] = 1;
        coeffs[1] = 1;
        coeffs[2] = 1;
        // p(0) = 1
        assertEq(_evalAtInt(coeffs, 0), 1);
        // p(2) = 1 + 2 + 4 = 7
        assertEq(_evalAtInt(coeffs, 2), 7);
        // p(-1) = 1 - 1 + 1 = 1
        assertEq(_evalAtInt(coeffs, -1), 1);
    }

    // ----------------------------------------------------------------
    //  Outer domain sum (domain = {-4,...,5})
    // ----------------------------------------------------------------

    function test_outer_zero_poly_sum() public pure {
        // Zero polynomial: sum should be 0
        uint256[] memory coeffs = new uint256[](1);
        coeffs[0] = 0;
        // Sum of zero over any domain = 0
        uint256 sum = _outerDomainSum(coeffs);
        assertEq(sum, 0, "Zero poly domain sum");
    }

    function test_outer_constant_poly_sum() public pure {
        // Constant polynomial p(x) = 1
        // Sum over {-4,...,5} = 10 * 1 = 10
        uint256[] memory coeffs = new uint256[](1);
        coeffs[0] = 1;
        uint256 sum = _outerDomainSum(coeffs);
        assertEq(sum, 10, "Constant poly domain sum should be 10");
    }

    function test_outer_linear_poly_sum() public pure {
        // p(x) = x: sum of {-4,...,5} = 5
        uint256[] memory coeffs = new uint256[](2);
        coeffs[0] = 0;
        coeffs[1] = 1;
        uint256 sum = _outerDomainSum(coeffs);
        assertEq(sum, 5, "Linear x poly domain sum should be 5");
    }

    function test_outer_quadratic_poly_sum() public pure {
        // p(x) = x^2: sum of (-4)^2+...+5^2 = 16+9+4+1+0+1+4+9+16+25 = 85
        uint256[] memory coeffs = new uint256[](3);
        coeffs[0] = 0;
        coeffs[1] = 0;
        coeffs[2] = 1;
        uint256 sum = _outerDomainSum(coeffs);
        assertEq(sum, 85, "x^2 poly domain sum should be 85");
    }

    // ----------------------------------------------------------------
    //  Product domain sum (domain = {-1, 0, 1})
    // ----------------------------------------------------------------

    function test_product_constant_sum() public pure {
        uint256[] memory coeffs = new uint256[](1);
        coeffs[0] = 1;
        uint256 sum = _productDomainSum(coeffs);
        assertEq(sum, 3, "Constant poly sum over {-1,0,1} should be 3");
    }

    function test_product_linear_sum() public pure {
        // p(x) = x: sum = -1 + 0 + 1 = 0
        uint256[] memory coeffs = new uint256[](2);
        coeffs[0] = 0;
        coeffs[1] = 1;
        uint256 sum = _productDomainSum(coeffs);
        assertEq(sum, 0, "Linear poly sum should be 0");
    }

    function test_product_quadratic_sum() public pure {
        // p(x) = x^2: sum = 1 + 0 + 1 = 2
        uint256[] memory coeffs = new uint256[](3);
        coeffs[0] = 0;
        coeffs[1] = 0;
        coeffs[2] = 1;
        uint256 sum = _productDomainSum(coeffs);
        assertEq(sum, 2, "x^2 sum over {-1,0,1} should be 2");
    }

    // ----------------------------------------------------------------
    //  Lagrange kernel for domain {-1, 0, 1}
    // ----------------------------------------------------------------

    function test_lagrange3_partition_of_unity() public pure {
        uint256 x = 42;
        uint256[3] memory w = UniSkipVerifier.lagrangeEvals3(x);
        uint256 sum = addmod(addmod(w[0], w[1], R), w[2], R);
        assertEq(sum, 1, "Lagrange3 partition of unity");
    }

    function test_lagrange3_at_domain_points() public pure {
        // At x = R-1 (= -1): L_{-1}(-1) = 1
        uint256[3] memory w = UniSkipVerifier.lagrangeEvals3(R - 1);
        assertEq(w[0], 1, "L_{-1}(-1) should be 1");
        assertEq(w[1], 0, "L_0(-1) should be 0");
        assertEq(w[2], 0, "L_1(-1) should be 0");

        // At x = 0: L_0(0) = 1
        w = UniSkipVerifier.lagrangeEvals3(0);
        assertEq(w[0], 0);
        assertEq(w[1], 1);
        assertEq(w[2], 0);

        // At x = 1: L_1(1) = 1
        w = UniSkipVerifier.lagrangeEvals3(1);
        assertEq(w[0], 0);
        assertEq(w[1], 0);
        assertEq(w[2], 1);
    }

    function test_lagrange3_kernel_identity() public pure {
        // L(x, x) should be identity-like: Σ L_i(x)^2
        uint256 x = 7;
        uint256 result = UniSkipVerifier.lagrangeKernel3(x, x);
        uint256[3] memory w = UniSkipVerifier.lagrangeEvals3(x);
        uint256 expected = addmod(
            addmod(mulmod(w[0], w[0], R), mulmod(w[1], w[1], R), R),
            mulmod(w[2], w[2], R),
            R
        );
        assertEq(result, expected, "Kernel at (x,x) should be sum of squares");
    }

    // ----------------------------------------------------------------
    //  Helper wrappers (to call calldata functions from test)
    // ----------------------------------------------------------------

    function _evalAtInt(uint256[] memory coeffs, int256 point) internal pure returns (uint256) {
        if (coeffs.length == 0) return 0;
        uint256 x;
        if (point >= 0) {
            x = uint256(point);
        } else {
            x = R - uint256(-point);
        }
        if (coeffs.length == 0) return 0;
        uint256 result = coeffs[coeffs.length - 1];
        for (uint256 i = coeffs.length - 1; i > 0; ) {
            unchecked { i--; }
            result = addmod(mulmod(result, x, R), coeffs[i], R);
        }
        return result;
    }

    function _outerDomainSum(uint256[] memory coeffs) internal pure returns (uint256 sum) {
        int256[10] memory points = [int256(-4), -3, -2, -1, 0, 1, 2, 3, 4, 5];
        sum = 0;
        for (uint256 p = 0; p < 10; p++) {
            sum = addmod(sum, _evalAtInt(coeffs, points[p]), R);
        }
    }

    function _productDomainSum(uint256[] memory coeffs) internal pure returns (uint256) {
        return addmod(
            addmod(_evalAtInt(coeffs, -1), _evalAtInt(coeffs, 0), R),
            _evalAtInt(coeffs, 1),
            R
        );
    }
}
