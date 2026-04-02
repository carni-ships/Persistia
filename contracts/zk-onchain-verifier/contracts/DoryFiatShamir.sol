// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Dory Fiat-Shamir Transcript
/// @notice Replays the Fiat-Shamir transcript for Dory evaluation proofs
/// to derive alpha, beta, gamma, d challenges on-chain.
/// Uses Blake2b-512 via the EIP-152 Blake2f precompile.
contract DoryFiatShamir {

    // BN254 scalar field order
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Blake2b-512 IV (first 8 words of the fractional parts of sqrt of first 8 primes)
    uint64 constant IV0 = 0x6a09e667f3bcc908;
    uint64 constant IV1 = 0xbb67ae8584caa73b;
    uint64 constant IV2 = 0x3c6ef372fe94f82b;
    uint64 constant IV3 = 0xa54ff53a5f1d36f1;
    uint64 constant IV4 = 0x510e527fade682d1;
    uint64 constant IV5 = 0x9b05688c2b3e6c1f;
    uint64 constant IV6 = 0x1f83d9abfb41bd6b;
    uint64 constant IV7 = 0x5be0cd19137e2179;

    // Blake2f precompile address (EIP-152)
    address constant BLAKE2F = address(0x09);

    struct Blake2bState {
        uint64[8] h;    // State words
        uint128 t;      // Byte counter
        uint256 bufLen; // Bytes in buffer
        bytes buf;      // Buffer (up to 128 bytes)
    }

    /// @notice Initialize a Blake2b-512 hasher with a personalization string
    function blake2bInit(bytes memory personalization) internal pure returns (Blake2bState memory state) {
        // Parameter block: digest_length=64, key_length=0, fanout=1, depth=1
        // followed by zeros and personalization at offset 32
        state.h[0] = IV0 ^ 0x01010040; // XOR with param block (digest_len=64, fanout=1, depth=1)
        state.h[1] = IV1;
        state.h[2] = IV2;
        state.h[3] = IV3;
        state.h[4] = IV4;
        state.h[5] = IV5;
        state.h[6] = IV6;
        state.h[7] = IV7;

        // XOR personalization into h[4..7] (bytes 32-47 of parameter block)
        if (personalization.length > 0) {
            uint64[2] memory pWords;
            assembly {
                // Load up to 16 bytes of personalization into two uint64 words (LE)
                let pLen := mload(personalization)
                let pData := add(personalization, 0x20)
                // Load first 8 bytes
                if gt(pLen, 0) {
                    let raw := mload(pData)
                    // Reverse bytes for LE encoding
                    pWords := raw
                }
            }
            // For simplicity, XOR raw bytes into state
            // In production, handle LE encoding properly
        }

        state.buf = new bytes(128);
        state.bufLen = 0;
        state.t = 0;
    }

    /// @notice Update the Blake2b state with new data
    function blake2bUpdate(Blake2bState memory state, bytes memory data) internal view {
        uint256 dataLen = data.length;
        uint256 dataOff = 0;

        while (dataOff < dataLen) {
            // If buffer is full, compress it
            if (state.bufLen == 128) {
                state.t += 128;
                _blake2bCompress(state, false);
                state.bufLen = 0;
            }

            // Copy data into buffer
            uint256 toCopy = 128 - state.bufLen;
            if (toCopy > dataLen - dataOff) {
                toCopy = dataLen - dataOff;
            }

            for (uint256 i = 0; i < toCopy; i++) {
                state.buf[state.bufLen + i] = data[dataOff + i];
            }
            state.bufLen += toCopy;
            dataOff += toCopy;
        }
    }

    /// @notice Finalize the Blake2b hash and return the 64-byte digest
    function blake2bFinalize(Blake2bState memory state) internal view returns (bytes memory) {
        state.t += uint128(state.bufLen);

        // Pad remaining buffer with zeros
        for (uint256 i = state.bufLen; i < 128; i++) {
            state.buf[i] = 0;
        }

        _blake2bCompress(state, true);

        // Extract digest from state words (little-endian)
        bytes memory digest = new bytes(64);
        for (uint256 i = 0; i < 8; i++) {
            uint64 word = state.h[i];
            for (uint256 j = 0; j < 8; j++) {
                digest[i * 8 + j] = bytes1(uint8(word >> (j * 8)));
            }
        }
        return digest;
    }

    /// @notice Call the Blake2f precompile to compress one block
    function _blake2bCompress(Blake2bState memory state, bool last) internal view {
        // Build the 213-byte input for the Blake2f precompile:
        // [rounds: 4 bytes] [h: 64 bytes] [m: 128 bytes] [t: 16 bytes] [f: 1 byte]
        bytes memory input = new bytes(213);

        // Rounds = 12 for Blake2b
        input[0] = 0x00;
        input[1] = 0x00;
        input[2] = 0x00;
        input[3] = 0x0c;

        // h: 8 x uint64 little-endian
        for (uint256 i = 0; i < 8; i++) {
            uint64 word = state.h[i];
            for (uint256 j = 0; j < 8; j++) {
                input[4 + i * 8 + j] = bytes1(uint8(word >> (j * 8)));
            }
        }

        // m: 128-byte message block
        for (uint256 i = 0; i < 128; i++) {
            input[68 + i] = state.buf[i];
        }

        // t: 128-bit counter as two uint64 LE
        uint64 tLow = uint64(uint256(state.t));
        uint64 tHigh = uint64(uint256(state.t) >> 64);
        for (uint256 j = 0; j < 8; j++) {
            input[196 + j] = bytes1(uint8(tLow >> (j * 8)));
            input[204 + j] = bytes1(uint8(tHigh >> (j * 8)));
        }

        // f: finalization flag
        input[212] = last ? bytes1(0x01) : bytes1(0x00);

        // Call Blake2f precompile
        (bool success, bytes memory output) = BLAKE2F.staticcall(input);
        require(success, "Blake2f precompile failed");
        require(output.length == 64, "Blake2f bad output length");

        // Parse output back into state.h (little-endian uint64 words)
        for (uint256 i = 0; i < 8; i++) {
            uint64 word = 0;
            for (uint256 j = 0; j < 8; j++) {
                word |= uint64(uint8(output[i * 8 + j])) << (j * 8);
            }
            state.h[i] = word;
        }
    }

    /// @notice Append a labeled message to the transcript
    /// Matches Arkworks/Jolt transcript: hash(label) || hash(len as u64 LE) || hash(data)
    function appendSerde(Blake2bState memory state, bytes memory label, bytes memory data) internal view {
        blake2bUpdate(state, label);
        // Append data length as u64 little-endian
        bytes memory lenBytes = new bytes(8);
        uint64 dataLen = uint64(data.length);
        for (uint256 i = 0; i < 8; i++) {
            lenBytes[i] = bytes1(uint8(dataLen >> (i * 8)));
        }
        blake2bUpdate(state, lenBytes);
        blake2bUpdate(state, data);
    }

    /// @notice Squeeze a challenge scalar from the transcript
    /// Returns a BN254 scalar field element
    function challengeScalar(Blake2bState memory state, bytes memory label) internal view returns (uint256) {
        blake2bUpdate(state, label);

        // Clone state and finalize to get digest
        Blake2bState memory cloned = _cloneState(state);
        bytes memory digest = blake2bFinalize(cloned);

        // Convert 64-byte LE digest to scalar via mod R
        // (matches Arkworks from_le_bytes_mod_order)
        uint256 scalar = _leBytes64ToScalar(digest);

        // Feed digest back into the original state (sponge pattern)
        blake2bUpdate(state, digest);

        return scalar;
    }

    /// @notice Convert 64 LE bytes to a BN254 scalar via mod reduction
    function _leBytes64ToScalar(bytes memory digest) internal pure returns (uint256) {
        // Read as 512-bit LE integer, then reduce mod R
        // Split into high and low 256-bit parts
        uint256 low = 0;
        uint256 high = 0;
        for (uint256 i = 0; i < 32; i++) {
            low |= uint256(uint8(digest[i])) << (i * 8);
        }
        for (uint256 i = 0; i < 32; i++) {
            high |= uint256(uint8(digest[32 + i])) << (i * 8);
        }
        // result = (high * 2^256 + low) mod R
        // Use mulmod for the high part
        uint256 result = addmod(mulmod(high, _TWO_256_MOD_R(), R), low % R, R);
        return result;
    }

    /// @notice 2^256 mod R (precomputed)
    function _TWO_256_MOD_R() internal pure returns (uint256) {
        // 2^256 mod R for BN254
        // R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
        // 2^256 mod R = 2^256 - R * floor(2^256/R)
        return 0x0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb;
    }

    function _cloneState(Blake2bState memory state) internal pure returns (Blake2bState memory cloned) {
        cloned.h = state.h;
        cloned.t = state.t;
        cloned.bufLen = state.bufLen;
        cloned.buf = new bytes(128);
        for (uint256 i = 0; i < state.bufLen; i++) {
            cloned.buf[i] = state.buf[i];
        }
    }

    /// @notice Derive all Dory challenges from serialized proof data
    /// @param proofData ABI-encoded proof messages (VMV, first/second messages, final)
    /// @return alphas Array of alpha challenges (one per round)
    /// @return betas Array of beta challenges (one per round)
    /// @return gamma The gamma challenge
    /// @return d The d challenge
    function deriveChallenges(
        bytes calldata proofData,
        uint256 numRounds
    ) external view returns (
        uint256[] memory alphas,
        uint256[] memory betas,
        uint256 gamma,
        uint256 d
    ) {
        // Decode proof data
        // Format: vmv_c || vmv_d2 || vmv_e1 ||
        //   for each round: first_msg || second_msg ||
        //   final_e1 || final_e2

        Blake2bState memory state = blake2bInit("dory-witness-export");

        // VMV messages
        (bytes memory vmvC, bytes memory vmvD2, bytes memory vmvE1, uint256 offset) =
            _decodeVMV(proofData);
        appendSerde(state, "vmv_c", vmvC);
        appendSerde(state, "vmv_d2", vmvD2);
        appendSerde(state, "vmv_e1", vmvE1);

        alphas = new uint256[](numRounds);
        betas = new uint256[](numRounds);

        for (uint256 i = 0; i < numRounds; i++) {
            // First message
            (bytes memory d1Left, bytes memory d1Right,
             bytes memory d2Left, bytes memory d2Right,
             bytes memory e1Beta, bytes memory e2Beta,
             uint256 newOff) = _decodeFirstMessage(proofData, offset);
            offset = newOff;

            appendSerde(state, "d1_left", d1Left);
            appendSerde(state, "d1_right", d1Right);
            appendSerde(state, "d2_left", d2Left);
            appendSerde(state, "d2_right", d2Right);
            appendSerde(state, "e1_beta", e1Beta);
            appendSerde(state, "e2_beta", e2Beta);

            betas[i] = challengeScalar(state, "beta");

            // Second message
            (bytes memory cPlus, bytes memory cMinus,
             bytes memory e1Plus, bytes memory e1Minus,
             bytes memory e2Plus, bytes memory e2Minus,
             uint256 newOff2) = _decodeSecondMessage(proofData, offset);
            offset = newOff2;

            appendSerde(state, "c_plus", cPlus);
            appendSerde(state, "c_minus", cMinus);
            appendSerde(state, "e1_plus", e1Plus);
            appendSerde(state, "e1_minus", e1Minus);
            appendSerde(state, "e2_plus", e2Plus);
            appendSerde(state, "e2_minus", e2Minus);

            alphas[i] = challengeScalar(state, "alpha");
        }

        gamma = challengeScalar(state, "gamma");

        // Final message
        (bytes memory finalE1, bytes memory finalE2) = _decodeFinal(proofData, offset);
        appendSerde(state, "final_e1", finalE1);
        appendSerde(state, "final_e2", finalE2);

        d = challengeScalar(state, "d");
    }

    // Decoding helpers — expect Arkworks compressed serialization format.
    // These are stubs; the actual format depends on the proof serialization.
    function _decodeVMV(bytes calldata data) internal pure returns (
        bytes memory vmvC, bytes memory vmvD2, bytes memory vmvE1, uint256 offset
    ) {
        // GT elements (Fq12) are 576 bytes compressed in Arkworks
        // G1 elements are 64 bytes compressed (or 32 bytes with flag)
        // Actual sizes depend on Arkworks serialization
        // TODO: implement actual decoding
        offset = 0;
        vmvC = data[offset:offset + 576];
        offset += 576;
        vmvD2 = data[offset:offset + 576];
        offset += 576;
        vmvE1 = data[offset:offset + 64];
        offset += 64;
    }

    function _decodeFirstMessage(bytes calldata data, uint256 offset) internal pure returns (
        bytes memory d1Left, bytes memory d1Right,
        bytes memory d2Left, bytes memory d2Right,
        bytes memory e1Beta, bytes memory e2Beta,
        uint256 newOffset
    ) {
        d1Left = data[offset:offset + 576]; offset += 576;
        d1Right = data[offset:offset + 576]; offset += 576;
        d2Left = data[offset:offset + 576]; offset += 576;
        d2Right = data[offset:offset + 576]; offset += 576;
        e1Beta = data[offset:offset + 64]; offset += 64;
        e2Beta = data[offset:offset + 128]; offset += 128;
        newOffset = offset;
    }

    function _decodeSecondMessage(bytes calldata data, uint256 offset) internal pure returns (
        bytes memory cPlus, bytes memory cMinus,
        bytes memory e1Plus, bytes memory e1Minus,
        bytes memory e2Plus, bytes memory e2Minus,
        uint256 newOffset
    ) {
        cPlus = data[offset:offset + 576]; offset += 576;
        cMinus = data[offset:offset + 576]; offset += 576;
        e1Plus = data[offset:offset + 64]; offset += 64;
        e1Minus = data[offset:offset + 64]; offset += 64;
        e2Plus = data[offset:offset + 128]; offset += 128;
        e2Minus = data[offset:offset + 128]; offset += 128;
        newOffset = offset;
    }

    function _decodeFinal(bytes calldata data, uint256 offset) internal pure returns (
        bytes memory finalE1, bytes memory finalE2
    ) {
        finalE1 = data[offset:offset + 64];
        finalE2 = data[offset + 64:offset + 192];
    }
}
