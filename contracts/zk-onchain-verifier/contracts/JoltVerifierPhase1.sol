// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./JoltTranscript.sol";
import "./StageVerification.sol";
import "./JoltTypes.sol";

/// @title Jolt Verifier Phase 1
/// @notice Verifies preamble, commitments, and stages 1-4.
/// Returns transcript state for Phase 2 continuation.
contract JoltVerifierPhase1 {
    using JoltTranscript for JoltTranscript.Transcript;

    function verifyPhase1(JoltTypes.JoltOnChainProof calldata proof)
        external
        pure
        returns (bytes32 tState, uint32 tNRounds, uint256 nCycleVars)
    {
        JoltTranscript.Transcript memory t = JoltTranscript.newTranscript("Jolt");

        _replayPreamble(t, proof.preamble);
        _appendCommitments(t, proof.commitmentBlob, proof.commitmentSize);

        if (proof.untrustedAdviceCommitment.length > 0) {
            t.appendLabeledBytes(
                bytes24(bytes16("untrusted_advice")),
                uint64(proof.untrustedAdviceCommitment.length),
                proof.untrustedAdviceCommitment
            );
        }
        if (proof.trustedAdviceCommitment.length > 0) {
            t.appendLabeledBytes(
                bytes24(bytes14("trusted_advice")),
                uint64(proof.trustedAdviceCommitment.length),
                proof.trustedAdviceCommitment
            );
        }

        nCycleVars = _log2(proof.preamble.traceLength);

        StageVerification.verifyStage1(t, proof.stage1Proof, proof.stage1Inputs);
        StageVerification.verifyStage2(t, proof.stage2Proof, proof.stage2Inputs);
        StageVerification.verifyStage3(t, proof.stage3Proof, proof.stage3Inputs, nCycleVars);
        StageVerification.verifyStage4(t, proof.stage4Proof, proof.stage4Inputs, nCycleVars);

        tState = t.state;
        tNRounds = t.nRounds;
    }

    function _replayPreamble(
        JoltTranscript.Transcript memory t,
        JoltTypes.Preamble calldata preamble
    ) internal pure {
        t.appendLabeledU64(bytes32(bytes14("max_input_size")), preamble.maxInputSize);
        t.appendLabeledU64(bytes32(bytes15("max_output_size")), preamble.maxOutputSize);
        t.appendLabeledU64(bytes32(bytes9("heap_size")), preamble.heapSize);
        t.appendLabeledBytes(
            bytes24(bytes6("inputs")),
            uint64(preamble.inputs.length),
            preamble.inputs
        );
        t.appendLabeledBytes(
            bytes24(bytes7("outputs")),
            uint64(preamble.outputs.length),
            preamble.outputs
        );
        t.appendLabeledU64(bytes32(bytes5("panic")), preamble.panic);
        t.appendLabeledU64(bytes32(bytes5("ram_K")), preamble.ramK);
        t.appendLabeledU64(bytes32(bytes12("trace_length")), preamble.traceLength);
        t.appendLabeledU64(bytes32(bytes13("entry_address")), preamble.entryAddress);
    }

    function _appendCommitments(
        JoltTranscript.Transcript memory t,
        bytes calldata blob,
        uint16 size
    ) internal pure {
        uint256 s = uint256(size);
        uint256 n = blob.length / s;
        for (uint256 i = 0; i < n; i++) {
            bytes calldata chunk = blob[i * s : (i + 1) * s];
            t.appendLabeledBytes(
                bytes24(bytes10("commitment")),
                uint64(size),
                _toMemory(chunk)
            );
        }
    }

    function _toMemory(bytes calldata data) internal pure returns (bytes memory out) {
        out = new bytes(data.length);
        // SAFETY: copies calldata slice into freshly allocated memory
        assembly {
            calldatacopy(add(out, 0x20), data.offset, data.length)
        }
    }

    function _log2(uint64 x) internal pure returns (uint256) {
        uint256 result = 0;
        uint256 v = uint256(x);
        require(v > 0, "log2(0)");
        while (v > 1) {
            v >>= 1;
            result++;
        }
        return result;
    }
}
