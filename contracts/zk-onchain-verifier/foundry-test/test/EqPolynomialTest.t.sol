// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "contracts/EqPolynomial.sol";

contract EqPolynomialTest is Test {
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // ----------------------------------------------------------------
    //  EqPolynomial.mle tests
    // ----------------------------------------------------------------

    function test_eq_identical_points() public pure {
        // eq(x, x) = prod_i (x_i^2 + (1-x_i)^2)
        // For x = (0, 0, ..., 0), eq = 1
        uint256[] memory x = new uint256[](3);
        x[0] = 0;
        x[1] = 0;
        x[2] = 0;
        uint256 result = EqPolynomial.mle(x, x);
        assertEq(result, 1, "eq(0,0) should be 1");
    }

    function test_eq_boolean_same() public pure {
        // eq((1,0,1), (1,0,1)) = 1
        uint256[] memory x = new uint256[](3);
        x[0] = 1;
        x[1] = 0;
        x[2] = 1;
        uint256 result = EqPolynomial.mle(x, x);
        assertEq(result, 1, "eq of identical boolean points should be 1");
    }

    function test_eq_boolean_different() public pure {
        // eq((1,0,1), (0,1,0)) = 0
        uint256[] memory x = new uint256[](3);
        x[0] = 1;
        x[1] = 0;
        x[2] = 1;
        uint256[] memory y = new uint256[](3);
        y[0] = 0;
        y[1] = 1;
        y[2] = 0;
        uint256 result = EqPolynomial.mle(x, y);
        assertEq(result, 0, "eq of orthogonal boolean points should be 0");
    }

    function test_eq_single_var() public pure {
        // eq([a], [b]) = a*b + (1-a)*(1-b) = 2*a*b - a - b + 1
        // For a = 3, b = 5 (mod R):
        // eq = 2*3*5 - 3 - 5 + 1 = 30 - 8 + 1 = 23
        uint256[] memory x = new uint256[](1);
        x[0] = 3;
        uint256[] memory y = new uint256[](1);
        y[0] = 5;
        uint256 result = EqPolynomial.mle(x, y);
        assertEq(result, 23, "eq([3],[5]) should be 23");
    }

    function test_eq_rust_vector_2var() public pure {
        // eq([3,7], [11,13]) = 8639 (verified against Rust)
        uint256[] memory x = new uint256[](2);
        x[0] = 3;
        x[1] = 7;
        uint256[] memory y = new uint256[](2);
        y[0] = 11;
        y[1] = 13;
        uint256 result = EqPolynomial.mle(x, y);
        assertEq(result, 0x21bf, "eq([3,7],[11,13]) Rust vector mismatch");
    }

    function test_eq_rust_vector_1var() public pure {
        // eq([100], [200]) = 39701 (verified against Rust)
        uint256[] memory x = new uint256[](1);
        x[0] = 100;
        uint256[] memory y = new uint256[](1);
        y[0] = 200;
        uint256 result = EqPolynomial.mle(x, y);
        assertEq(result, 0x9b15, "eq([100],[200]) Rust vector mismatch");
    }

    function test_eqPlusOne_rust_vector_mont() public pure {
        // eqPlusOne with Montgomery challenge values from KeccakTranscript
        // Verified against Rust EqPlusOnePolynomial::evaluate
        uint256[] memory x = new uint256[](2);
        x[0] = 0x095b68e1e75a0580c4e0cc869e3c26c7ddc6920a01eb79afd75103aad7dc96ca;
        x[1] = 0x1669a2a567fa21702d248e5aca912572f7dd713acefb671f42969cd8771fdb72;
        uint256[] memory y = new uint256[](2);
        y[0] = 0x2c70d44345e0982c2f3c66f5d823f53eb6edb8e49964bf976f0b886c11e234cc;
        y[1] = 0x1ff7d6aeab2ffda103024cbe0ae8c4f0bd8aa1960a926550bc4cf5b678341b6a;
        uint256 result = EqPolynomial.eqPlusOne(x, y);
        assertEq(
            result,
            0x19f3db4c2fbe2264309bdf18f1bb76ebb326634f9bd9de2750bfaf6a516bd84b,
            "eqPlusOne mont Rust vector mismatch"
        );
    }

    // ----------------------------------------------------------------
    //  EqPlusOnePolynomial tests
    // ----------------------------------------------------------------

    function test_eqPlusOne_boolean_successor() public pure {
        // eqPlusOne((0,1,0), (0,1,1)) should be 1
        // Binary: 2 + 1 = 3 → (0,1,0) + 1 = (0,1,1) ✓
        uint256[] memory x = new uint256[](3);
        x[0] = 0;
        x[1] = 1;
        x[2] = 0;
        uint256[] memory y = new uint256[](3);
        y[0] = 0;
        y[1] = 1;
        y[2] = 1;
        uint256 result = EqPolynomial.eqPlusOne(x, y);
        assertEq(result, 1, "eqPlusOne(2, 3) should be 1");
    }

    function test_eqPlusOne_boolean_carry() public pure {
        // eqPlusOne((0,1,1), (1,0,0)) should be 1
        // Binary: 3 + 1 = 4 → (0,1,1) + 1 = (1,0,0) ✓
        uint256[] memory x = new uint256[](3);
        x[0] = 0;
        x[1] = 1;
        x[2] = 1;
        uint256[] memory y = new uint256[](3);
        y[0] = 1;
        y[1] = 0;
        y[2] = 0;
        uint256 result = EqPolynomial.eqPlusOne(x, y);
        assertEq(result, 1, "eqPlusOne(3, 4) should be 1");
    }

    function test_eqPlusOne_not_successor() public pure {
        // eqPlusOne((0,0,0), (0,1,0)) should be 0
        // 0 + 1 = 1 ≠ 2
        uint256[] memory x = new uint256[](3);
        x[0] = 0;
        x[1] = 0;
        x[2] = 0;
        uint256[] memory y = new uint256[](3);
        y[0] = 0;
        y[1] = 1;
        y[2] = 0;
        uint256 result = EqPolynomial.eqPlusOne(x, y);
        assertEq(result, 0, "eqPlusOne(0, 2) should be 0");
    }

    function test_eqPlusOne_zero_to_one() public pure {
        // eqPlusOne((0,0), (0,1)) should be 1
        // 0 + 1 = 1
        uint256[] memory x = new uint256[](2);
        x[0] = 0;
        x[1] = 0;
        uint256[] memory y = new uint256[](2);
        y[0] = 0;
        y[1] = 1;
        uint256 result = EqPolynomial.eqPlusOne(x, y);
        assertEq(result, 1, "eqPlusOne(0, 1) should be 1");
    }

    // ----------------------------------------------------------------
    //  LT polynomial tests
    // ----------------------------------------------------------------

    function test_lt_boolean_less_than() public pure {
        // lt((0,0,1), (0,1,0)) = 1, since 1 < 2
        uint256[] memory x = new uint256[](3);
        x[0] = 0; x[1] = 0; x[2] = 1;
        uint256[] memory y = new uint256[](3);
        y[0] = 0; y[1] = 1; y[2] = 0;
        assertEq(EqPolynomial.lt(x, y), 1, "lt(1,2) should be 1");
    }

    function test_lt_boolean_not_less_than() public pure {
        // lt((0,1,0), (0,0,1)) = 0, since 2 > 1
        uint256[] memory x = new uint256[](3);
        x[0] = 0; x[1] = 1; x[2] = 0;
        uint256[] memory y = new uint256[](3);
        y[0] = 0; y[1] = 0; y[2] = 1;
        assertEq(EqPolynomial.lt(x, y), 0, "lt(2,1) should be 0");
    }

    function test_lt_boolean_equal() public pure {
        // lt((1,0,1), (1,0,1)) = 0, since 5 is not < 5
        uint256[] memory x = new uint256[](3);
        x[0] = 1; x[1] = 0; x[2] = 1;
        assertEq(EqPolynomial.lt(x, x), 0, "lt(5,5) should be 0");
    }

    function test_lt_boolean_zero_less_than_one() public pure {
        // lt((0,0), (0,1)) = 1, since 0 < 1
        uint256[] memory x = new uint256[](2);
        uint256[] memory y = new uint256[](2);
        y[1] = 1;
        assertEq(EqPolynomial.lt(x, y), 1, "lt(0,1) should be 1");
    }

    function test_lt_single_var() public pure {
        // lt([a], [b]) = (1-a)*b
        // For a=3, b=5: lt = (1-3)*5 = -10 mod R
        uint256[] memory x = new uint256[](1);
        x[0] = 3;
        uint256[] memory y = new uint256[](1);
        y[0] = 5;
        uint256 expected = mulmod(R - 2, 5, R); // (1-3)*5 = -10 mod R
        assertEq(EqPolynomial.lt(x, y), expected, "lt([3],[5]) mismatch");
    }

    function test_lt_rust_vector_2var() public pure {
        // Verified against Rust lt_eval with KeccakTranscript-derived Montgomery challenges
        uint256[] memory x = new uint256[](2);
        x[0] = 0x05475133688f9f63648c0b46e0541b1111ab4997530eac9af689827edcd3904e;
        x[1] = 0x090e355b89ff9213685a6baa3a9166d3e8a4ba0bd5eb55cdc315a0cb8ac8e0a2;
        uint256[] memory y = new uint256[](2);
        y[0] = 0x0e4545c39a5897df894b539c98caa7f6ad374db8047bce67b7b48ac05de05677;
        y[1] = 0x1a826a3e61e3a52519d98de9c8f5bc06980a914d1dc7136ec131008b49fbfdc2;
        uint256 result = EqPolynomial.lt(x, y);
        assertEq(
            result,
            0x284ea9fe1fc519cf319757e6982f5b90e10c348188a28679222f82751f190d46,
            "LT 2-var Rust vector mismatch"
        );
    }

    function test_lt_rust_vector_1var() public pure {
        // Verified against Rust lt_eval with KeccakTranscript-derived Montgomery challenges
        uint256[] memory x = new uint256[](1);
        x[0] = 0x216b6d8d051b923f7256f419812db9371e69c54ca971e702152327acfcf0d5ef;
        uint256[] memory y = new uint256[](1);
        y[0] = 0x208cc03e481f611baad7cd2b54505fa56cb09ef52bc547b00832ad5af15cb1ed;
        uint256 result = EqPolynomial.lt(x, y);
        assertEq(
            result,
            0x251183474f78dd13ca2beade0a82c57e51101b4e1e8026fa8b21739594a13ba9,
            "LT 1-var Rust vector mismatch"
        );
    }

    function test_eqPlusOne_all_ones_wraps_to_zero() public pure {
        // eqPlusOne((1,1,1), (0,0,0)) should be 0
        // All 1s is the max value, wrapping is excluded by spec
        uint256[] memory x = new uint256[](3);
        x[0] = 1;
        x[1] = 1;
        x[2] = 1;
        uint256[] memory y = new uint256[](3);
        y[0] = 0;
        y[1] = 0;
        y[2] = 0;
        uint256 result = EqPolynomial.eqPlusOne(x, y);
        assertEq(result, 0, "eqPlusOne(7, 0) should be 0 (no wrap)");
    }
}
