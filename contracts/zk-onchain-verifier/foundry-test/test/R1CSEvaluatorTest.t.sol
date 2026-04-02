// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "contracts/R1CSEvaluator.sol";

contract R1CSEvaluatorTest is Test {
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // ----------------------------------------------------------------
    //  Lagrange weights at domain points
    // ----------------------------------------------------------------

    function test_lagrange_at_domain_point_0() public pure {
        uint256[10] memory w = R1CSEvaluator.lagrangeWeights10(R - 4);
        assertEq(w[0], 1, "L_0(-4) should be 1");
        for (uint256 i = 1; i < 10; i++) {
            assertEq(w[i], 0, "L_i(-4) should be 0 for i != 0");
        }
    }

    function test_lagrange_at_domain_point_5() public pure {
        uint256[10] memory w = R1CSEvaluator.lagrangeWeights10(1);
        assertEq(w[5], 1, "L_5(1) should be 1");
        for (uint256 i = 0; i < 10; i++) {
            if (i != 5) assertEq(w[i], 0);
        }
    }

    function test_lagrange_at_domain_point_9() public pure {
        uint256[10] memory w = R1CSEvaluator.lagrangeWeights10(5);
        assertEq(w[9], 1, "L_9(5) should be 1");
        for (uint256 i = 0; i < 9; i++) {
            assertEq(w[i], 0);
        }
    }

    function test_lagrange_partition_of_unity() public pure {
        uint256 x = 42;
        uint256[10] memory w = R1CSEvaluator.lagrangeWeights10(x);
        uint256 sum = 0;
        for (uint256 i = 0; i < 10; i++) {
            sum = addmod(sum, w[i], R);
        }
        assertEq(sum, 1, "Lagrange partition of unity failed");
    }

    function test_lagrange_partition_of_unity_field() public pure {
        uint256 x = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef % R;
        uint256[10] memory w = R1CSEvaluator.lagrangeWeights10(x);
        uint256 sum = 0;
        for (uint256 i = 0; i < 10; i++) {
            sum = addmod(sum, w[i], R);
        }
        assertEq(sum, 1, "Lagrange partition of unity failed for large field element");
    }

    // ----------------------------------------------------------------
    //  AzBz evaluation
    // ----------------------------------------------------------------

    function test_azBz_doesnt_revert() public pure {
        uint256[35] memory z;
        uint256[10] memory w = R1CSEvaluator.lagrangeWeights10(0);
        uint256 result = R1CSEvaluator.evaluateAzBz(z, w, 0);
        assertTrue(result < R);
    }

    function test_azBz_satisfying_at_domain_point() public pure {
        // At domain point t=1 (index 5), only w[5]=1
        // Group 1 constraint [5]: A = 1-Add-Sub-Mul, B = LeftLookupOperand - LeftInstructionInput
        // Set z[13] = z[0] so B = 0, making Az*Bz = 0
        uint256[35] memory z;
        z[0] = 42; z[13] = 42;  // LeftLookupOperand = LeftInstructionInput
        z[1] = 7; z[14] = 7;    // RightLookupOperand = RightInstructionInput
        z[5] = 100; z[15] = 104; // NextUnexpPC = UnexpPC + 4

        uint256[10] memory w = R1CSEvaluator.lagrangeWeights10(1);
        // rStream = 0 → only group 1 matters
        uint256 result = R1CSEvaluator.evaluateAzBz(z, w, 0);
        assertEq(result, 0, "satisfying at domain point should give 0");
    }
}
