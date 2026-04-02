// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "contracts/JoltTranscript.sol";

contract JoltTranscriptTest is Test {
    using JoltTranscript for JoltTranscript.Transcript;

    // Padded label helpers — right-pad ASCII to bytes32
    function _pad(bytes memory s) internal pure returns (bytes32 result) {
        assembly {
            result := mload(add(s, 0x20))
        }
        if (s.length < 32) {
            uint256 mask = ~(type(uint256).max >> (s.length * 8));
            result = bytes32(uint256(result) & mask);
        }
    }

    // Padded label to bytes24 (for label-with-length operations)
    function _pad24(bytes memory s) internal pure returns (bytes24 result) {
        require(s.length <= 24, "label > 24 bytes");
        bytes32 full = _pad(s);
        result = bytes24(full);
    }

    function test_newTranscript() public pure {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("jolt_v1");
        assertEq(t.state, bytes32(0xc5afa15e52af5262ad9ca63e3493074147c7f30ec2064d09498bb0a69d485e8b));
        assertEq(t.nRounds, 0);
    }

    function test_appendLabel() public pure {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("jolt_v1");
        t.appendLabel(_pad("stage"));
        assertEq(t.state, bytes32(0x635778e4bb8b7b359d1acca28657a4c0a75dd0528237133b73db00732fe4ed51));
        assertEq(t.nRounds, 1);
    }

    function test_appendLabeledU64() public pure {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("jolt_v1");
        t.appendLabel(_pad("stage"));
        t.appendLabeledU64(_pad("trace_len"), 1024);
        assertEq(t.state, bytes32(0x4be8ffdaebfacb338c535903a8934196ffc98cdc2d4f241cef67f9bb059799a3));
        assertEq(t.nRounds, 3);
    }

    function test_appendLabeledScalar() public pure {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("jolt_v1");
        t.appendLabel(_pad("stage"));
        t.appendLabeledU64(_pad("trace_len"), 1024);
        // Scalar 42 in BN254 Fr big-endian
        uint256 scalar42 = 42;
        t.appendLabeledScalar(_pad("claim"), scalar42);
        assertEq(t.state, bytes32(0xf4655fc018c0404e2114c8bf7f7d26924e5fcf8bc30e3bfe2b5a17241e1e95d0));
        assertEq(t.nRounds, 5);
    }

    function test_challengeScalar() public pure {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("jolt_v1");
        t.appendLabel(_pad("stage"));
        t.appendLabeledU64(_pad("trace_len"), 1024);
        t.appendLabeledScalar(_pad("claim"), 42);

        uint256 challenge = t.challengeScalar();
        // Expected: 0x88a4d2d8bcd69fffd3dc6d60873da12b (128-bit value)
        assertEq(challenge, 0x88a4d2d8bcd69fffd3dc6d60873da12b);
        assertEq(t.state, bytes32(0x88a4d2d8bcd69fffd3dc6d60873da12bf16bfbb8564372dbe19d29bc3ea2c5dd));
        assertEq(t.nRounds, 6);
    }

    function test_appendLabeledScalars() public pure {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("jolt_v1");
        t.appendLabel(_pad("stage"));
        t.appendLabeledU64(_pad("trace_len"), 1024);
        t.appendLabeledScalar(_pad("claim"), 42);
        t.challengeScalar(); // consume challenge

        uint256[] memory scalars = new uint256[](3);
        scalars[0] = 100;
        scalars[1] = 200;
        scalars[2] = 300;
        t.appendLabeledScalars(_pad24("coeffs"), scalars);
        assertEq(t.state, bytes32(0x9a90918c9a2a9ee45028935ceaaba92c98bb4ae01aa20aefead98a254498330d));
        assertEq(t.nRounds, 10);
    }

    function test_challengeScalarPowers() public pure {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("jolt_v1");
        t.appendLabel(_pad("stage"));
        t.appendLabeledU64(_pad("trace_len"), 1024);
        t.appendLabeledScalar(_pad("claim"), 42);
        t.challengeScalar();

        uint256[] memory scalars = new uint256[](3);
        scalars[0] = 100;
        scalars[1] = 200;
        scalars[2] = 300;
        t.appendLabeledScalars(_pad24("coeffs"), scalars);

        uint256[] memory powers = t.challengeScalarPowers(3);
        assertEq(powers[0], 1);
        assertEq(powers[1], 0x1b40bbb8964ebfb8b2fd8d1a7c76b18e);
        assertEq(powers[2], 0x02e6b7f755a6f48047a6ca6fb20220ea35318fabab4e617caee1afe1ba0daac4);
        assertEq(t.state, bytes32(0x1b40bbb8964ebfb8b2fd8d1a7c76b18e3bc3d4e63ab6b69393d37d70245e2d50));
        assertEq(t.nRounds, 11);
    }

    function test_gasUsage() public {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("jolt_v1");
        uint256 gasBefore = gasleft();

        // Simulate a typical sumcheck round: append 4 coefficients, derive challenge
        for (uint256 round = 0; round < 10; round++) {
            uint256[] memory coeffs = new uint256[](4);
            coeffs[0] = round * 4 + 1;
            coeffs[1] = round * 4 + 2;
            coeffs[2] = round * 4 + 3;
            coeffs[3] = round * 4 + 4;
            t.appendLabeledScalars(_pad24("uni_poly"), coeffs);
            t.challengeScalar();
        }

        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("Gas for 10 sumcheck rounds (transcript only)", gasUsed);
        // ~10K gas per round (mostly memory allocation for dynamic arrays)
        assertLt(gasUsed, 150000);
    }
}
