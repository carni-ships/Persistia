// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "contracts/JoltTranscript.sol";
import "contracts/JoltVerifier.sol";

contract JoltVerifierTest is Test {
    using JoltTranscript for JoltTranscript.Transcript;

    // ----------------------------------------------------------------
    //  Test: Preamble replay matches Rust transcript state
    // ----------------------------------------------------------------

    function test_preambleReplay() public pure {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("jolt_v1");

        // Verify initial state matches Rust
        assertEq(
            t.state,
            bytes32(0xc5afa15e52af5262ad9ca63e3493074147c7f30ec2064d09498bb0a69d485e8b),
            "initial state mismatch"
        );

        // Replay the same preamble as Rust test_preamble_vectors
        t.appendLabeledU64(bytes32(bytes14("max_input_size")), 4096);
        t.appendLabeledU64(bytes32(bytes15("max_output_size")), 4096);
        t.appendLabeledU64(bytes32(bytes9("heap_size")), 65536);

        // inputs: [9, 0, 0, 0, 5, 0, 0, 0, 3, 0, 0, 0] (12 bytes)
        bytes memory inputs = hex"090000000500000003000000";
        t.appendLabeledBytes(bytes24(bytes6("inputs")), 12, inputs);

        // outputs: empty
        bytes memory outputs = "";
        t.appendLabeledBytes(bytes24(bytes7("outputs")), 0, outputs);

        t.appendLabeledU64(bytes32(bytes5("panic")), 0);
        t.appendLabeledU64(bytes32(bytes5("ram_K")), 65536);
        t.appendLabeledU64(bytes32(bytes12("trace_length")), 1024);
        t.appendLabeledU64(bytes32(bytes13("entry_address")), 0x80000000);

        // Verify final state matches Rust
        assertEq(
            t.state,
            bytes32(0x58e4a05677ec6a9c9ecd13c2c2bf235c7900f6b0937bf2162dff9a9b25df6841),
            "preamble state mismatch"
        );
        assertEq(t.nRounds, 18, "nRounds mismatch");
    }

    // ----------------------------------------------------------------
    //  Test: append_serializable compatibility with appendLabeledBytes
    // ----------------------------------------------------------------

    function test_appendSerializable() public pure {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("serial_test");

        // append_serializable(b"commitment", Fr(42)):
        // data_len = 32, serialized_be = 0x...002a
        bytes memory data = hex"000000000000000000000000000000000000000000000000000000000000002a";
        t.appendLabeledBytes(
            bytes24(bytes10("commitment")),
            32,
            data
        );

        assertEq(
            t.state,
            bytes32(0x071942711289e1449083878753a364c2c764a60f3c352f0141f75d5292a27d7a),
            "single scalar state mismatch"
        );
        assertEq(t.nRounds, 2, "single scalar nRounds mismatch");

        // append_serializable(b"commitment", (Fr(100), Fr(200))):
        // Note: (s1, s2) serialized as [s1_LE || s2_LE], reversed => [s2_BE || s1_BE]
        // pair_data_len = 64
        bytes memory pairData = hex"00000000000000000000000000000000000000000000000000000000000000c80000000000000000000000000000000000000000000000000000000000000064";
        t.appendLabeledBytes(
            bytes24(bytes10("commitment")),
            64,
            pairData
        );

        assertEq(
            t.state,
            bytes32(0x7da391c082e030ebc779dbe17b492a9d3076ba4ede414eba136799adbac01957),
            "pair state mismatch"
        );
        assertEq(t.nRounds, 4, "pair nRounds mismatch");
    }
}
