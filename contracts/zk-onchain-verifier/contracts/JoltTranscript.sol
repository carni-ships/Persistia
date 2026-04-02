// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Jolt Fiat-Shamir Transcript (Keccak)
/// @notice Solidity port of jolt-core's KeccakTranscript.
/// Byte-level compatible with the Rust implementation so that
/// challenges derived on-chain match those produced by the prover.
///
/// State model:
///   state   : bytes32  — running hash state
///   nRounds : uint32   — ordinal appended to every hash invocation
///
/// Every state transition is:
///   state' = keccak256(state || pad32(nRounds) || payload)
///   nRounds' = nRounds + 1
library JoltTranscript {

    // BN254 scalar field order
    uint256 internal constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    struct Transcript {
        bytes32 state;
        uint32 nRounds;
    }

    // ----------------------------------------------------------------
    //  Construction
    // ----------------------------------------------------------------

    /// @notice Initialize a transcript with a domain-separation label.
    /// Matches `KeccakTranscript::new(label)` in Rust.
    /// label must be <= 32 bytes; it is right-padded with zeros.
    function newTranscript(bytes memory label)
        internal
        pure
        returns (Transcript memory t)
    {
        require(label.length < 33, "label > 32 bytes");
        bytes32 padded;
        assembly {
            padded := mload(add(label, 0x20))
        }
        // Mask off any bytes beyond label.length (right-pad with zeros)
        if (label.length < 32) {
            uint256 mask = ~(type(uint256).max >> (label.length * 8));
            padded = bytes32(uint256(padded) & mask);
        }
        t.state = keccak256(abi.encodePacked(padded));
        t.nRounds = 0;
    }

    // ----------------------------------------------------------------
    //  Internal raw methods
    // ----------------------------------------------------------------

    /// @dev keccak256(state || pad32(nRounds)) — the "hasher seed"
    function _hasherSeed(Transcript memory t)
        private
        pure
        returns (bytes32, bytes32)
    {
        return (t.state, bytes32(uint256(t.nRounds)));
    }

    /// @dev Update state and increment round counter
    function _updateState(Transcript memory t, bytes32 newState) private pure {
        t.state = newState;
        t.nRounds += 1;
    }

    /// @notice Append a label (right-padded to 32 bytes).
    /// Matches `raw_append_label` in Rust.
    function appendLabel(Transcript memory t, bytes32 label) internal pure {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, mload(t))
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))
            mstore(add(ptr, 0x40), label)
            mstore(t, keccak256(ptr, 0x60))
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1))
        }
    }

    /// @notice Append arbitrary bytes.
    /// Matches `raw_append_bytes` in Rust.
    function appendBytes(Transcript memory t, bytes memory data) internal pure {
        (bytes32 s, bytes32 nr) = _hasherSeed(t);
        _updateState(t, keccak256(abi.encodePacked(s, nr, data)));
    }

    /// @notice Append a uint64 value (left-padded to 32 bytes, big-endian).
    /// Matches `raw_append_u64` in Rust.
    function appendU64(Transcript memory t, uint64 x) internal pure {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, mload(t))
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))
            mstore(add(ptr, 0x40), x)
            mstore(t, keccak256(ptr, 0x60))
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1))
        }
    }

    /// @notice Append a BN254 Fr scalar (32 bytes, big-endian).
    /// In Rust: serialize_uncompressed (LE) then reverse → BE.
    /// In Solidity uint256 is already BE, so we pass it directly.
    function appendScalar(Transcript memory t, uint256 scalar) internal pure {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, mload(t))                          // state
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))    // nRounds
            mstore(add(ptr, 0x40), scalar)                  // scalar
            mstore(t, keccak256(ptr, 0x60))                 // state = hash
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1)) // nRounds++
        }
    }

    // ----------------------------------------------------------------
    //  Public API — labeled operations
    // ----------------------------------------------------------------

    /// @notice Append a domain-separation label with no data.
    /// Matches `transcript.append_label(label)`.
    function appendDomainLabel(Transcript memory t, bytes32 label) internal pure {
        appendLabel(t, label);
    }

    /// @notice Append a labeled u64 value.
    /// Matches `transcript.append_u64(label, x)`.
    /// Two state transitions: label then value.
    function appendLabeledU64(
        Transcript memory t,
        bytes32 label,
        uint64 x
    ) internal pure {
        appendLabel(t, label);
        appendU64(t, x);
    }

    /// @notice Append a labeled scalar.
    /// Matches `transcript.append_scalar(label, scalar)`.
    /// Two state transitions: label then scalar.
    function appendLabeledScalar(
        Transcript memory t,
        bytes32 label,
        uint256 scalar
    ) internal pure {
        assembly {
            let ptr := mload(0x40)
            // First transition: label
            mstore(ptr, mload(t))
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))
            mstore(add(ptr, 0x40), label)
            mstore(t, keccak256(ptr, 0x60))
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1))
            // Second transition: scalar
            mstore(ptr, mload(t))
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))
            mstore(add(ptr, 0x40), scalar)
            mstore(t, keccak256(ptr, 0x60))
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1))
        }
    }

    /// @notice Append a labeled array of scalars.
    /// Matches `transcript.append_scalars(label, scalars)`.
    /// First transition: label+count packed into 32 bytes.
    /// Then one transition per scalar.
    function appendLabeledScalars(
        Transcript memory t,
        bytes24 label,
        uint256[] memory scalars
    ) internal pure {
        assembly {
            let ptr := mload(0x40)
            // First transition: append packed label+count (32 bytes)
            let packed := or(label, mload(scalars))
            mstore(ptr, mload(t))
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))
            mstore(add(ptr, 0x40), packed)
            mstore(t, keccak256(ptr, 0x60))
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1))

            // One transition per scalar
            let len := mload(scalars)
            let dataPtr := add(scalars, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                mstore(ptr, mload(t))
                mstore(add(ptr, 0x20), mload(add(t, 0x20)))
                mstore(add(ptr, 0x40), mload(add(dataPtr, mul(i, 0x20))))
                mstore(t, keccak256(ptr, 0x60))
                mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1))
            }
        }
    }

    /// @notice Append a label-with-length packed word, then raw bytes.
    /// Matches `raw_append_label_with_len(label, len)` + `raw_append_bytes(data)`.
    /// Assembly-optimized: eliminates abi.encodePacked allocations.
    function appendLabeledBytes(
        Transcript memory t,
        bytes24 label,
        uint64 dataLen,
        bytes memory data
    ) internal pure {
        assembly {
            let ptr := mload(0x40)
            // First transition: state = keccak256(state || nRounds || packed_label_len)
            let packed := or(label, dataLen)
            mstore(ptr, mload(t))                          // state
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))    // nRounds
            mstore(add(ptr, 0x40), packed)                  // packed (label | dataLen)
            mstore(t, keccak256(ptr, 0x60))
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1))

            // Second transition: state = keccak256(state || nRounds || data)
            let dataLen_ := mload(data)
            let dataPtr := add(data, 0x20)
            // Build: [state, nRounds, data...]
            mstore(ptr, mload(t))
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))
            // Copy data bytes after the 64-byte header
            let dst := add(ptr, 0x40)
            for { let i := 0 } lt(i, dataLen_) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(dataPtr, i)))
            }
            mstore(t, keccak256(ptr, add(0x40, dataLen_)))
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1))
        }
    }

    /// @notice Append a labeled commitment (compressed serialization).
    /// Matches `transcript.append_commitment(label, point)`.
    /// Two state transitions: label then compressed point bytes.
    function appendLabeledCommitment(
        Transcript memory t,
        bytes32 label,
        bytes memory compressedPoint
    ) internal pure {
        appendLabel(t, label);
        appendBytes(t, compressedPoint);
    }

    /// @notice Append labeled commitments array.
    /// Matches `transcript.append_commitments(label, points)`.
    /// First: label+count packed. Then one transition per compressed point.
    function appendLabeledCommitments(
        Transcript memory t,
        bytes24 label,
        bytes[] memory compressedPoints
    ) internal pure {
        bytes32 packed = bytes32(label) | bytes32(uint256(compressedPoints.length));
        appendBytes(t, abi.encodePacked(packed));
        for (uint256 i = 0; i < compressedPoints.length; i++) {
            appendBytes(t, compressedPoints[i]);
        }
    }

    // ----------------------------------------------------------------
    //  Challenge generation
    // ----------------------------------------------------------------

    /// @notice Derive a 128-bit challenge scalar (BN254 Fr).
    /// Matches `challenge_scalar_128_bits` / `challenge_scalar` in Rust.
    ///
    /// Produces: keccak256(state || pad32(nRounds)), take top 128 bits as uint128.
    /// The Rust code takes first 16 bytes, reverses, interprets as BE u128,
    /// then calls from_le_bytes_mod_order — net effect is BE of first 16 bytes,
    /// which equals uint128(uint256(hash) >> 128) in Solidity.
    function challengeScalar(Transcript memory t)
        internal
        pure
        returns (uint256 result)
    {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, mload(t))
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))
            let hash := keccak256(ptr, 0x40)
            mstore(t, hash)
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1))
            result := shr(128, hash)
        }
    }

    // 2^(-128) mod R — precomputed constant for Montgomery challenge conversion.
    // MontU128Challenge stores raw_u128 in Montgomery form via from_bigint_unchecked,
    // making the actual field value = raw_u128 * 2^(-128) mod R.
    uint256 internal constant INV_TWO_128 =
        0x133100d71fdf35792b16366f4f7684df54ad7e14a329e70f18ee753c76f9dc6f;

    /// @notice Derive a Montgomery challenge scalar matching `challenge_scalar_optimized`.
    /// Used by the sumcheck verifier (the default challenge derivation in jolt-core).
    ///
    /// The Rust code:
    ///   1. Takes first 16 bytes of hash → reverses → u128::from_be_bytes → LE interpretation
    ///   2. Wraps in MontU128Challenge (masks top 3 bits of high limb)
    ///   3. from_bigint_unchecked stores [0,0,low,high] directly in Montgomery form
    ///   4. Actual field value = raw_u128 * 2^(-128) mod R
    function challengeScalarMont(Transcript memory t)
        internal
        pure
        returns (uint256 result)
    {
        uint256 inv128 = INV_TWO_128;
        uint256 r = R;
        assembly {
            // Inline _hasherSeed + keccak + _updateState
            let ptr := mload(0x40)
            mstore(ptr, mload(t))                          // state
            mstore(add(ptr, 0x20), mload(add(t, 0x20)))    // nRounds as bytes32
            let hash := keccak256(ptr, 0x40)
            mstore(t, hash)                                 // state = hash
            mstore(add(t, 0x20), add(mload(add(t, 0x20)), 1)) // nRounds++

            // Extract top 128 bits and byte-reverse to LE
            let v := shr(128, hash)
            // Swap bytes within 16-bit pairs
            v := or(
                shr(8, and(v, 0xFF00FF00FF00FF00FF00FF00FF00FF00)),
                shl(8, and(v, 0x00FF00FF00FF00FF00FF00FF00FF00FF))
            )
            // Swap 16-bit pairs within 32-bit groups
            v := or(
                shr(16, and(v, 0xFFFF0000FFFF0000FFFF0000FFFF0000)),
                shl(16, and(v, 0x0000FFFF0000FFFF0000FFFF0000FFFF))
            )
            // Swap 32-bit groups within 64-bit groups
            v := or(
                shr(32, and(v, 0xFFFFFFFF00000000FFFFFFFF00000000)),
                shl(32, and(v, 0x00000000FFFFFFFF00000000FFFFFFFF))
            )
            // Swap 64-bit halves
            v := or(shr(64, v), and(shl(64, v), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))

            // Mask top 3 bits of high limb + combine
            let low64 := and(v, 0xFFFFFFFFFFFFFFFF)
            let high64 := and(shr(64, v), sub(shl(61, 1), 1))
            let rawU128 := or(low64, shl(64, high64))

            result := mulmod(rawU128, inv128, r)
        }
    }

    /// @notice Derive a vector of challenge scalars.
    /// Matches `challenge_vector` in Rust.
    function challengeVector(Transcript memory t, uint256 len)
        internal
        pure
        returns (uint256[] memory challenges)
    {
        challenges = new uint256[](len);
        for (uint256 i = 0; i < len; i++) {
            challenges[i] = challengeScalar(t);
        }
    }

    /// @notice Derive a vector of Montgomery challenge scalars.
    /// Matches `challenge_vector_optimized` in Rust.
    function challengeVectorMont(Transcript memory t, uint256 len)
        internal
        pure
        returns (uint256[] memory challenges)
    {
        challenges = new uint256[](len);
        for (uint256 i = 0; i < len; i++) {
            challenges[i] = challengeScalarMont(t);
        }
    }

    /// @notice Derive powers of a challenge: (1, q, q^2, ..., q^(len-1)).
    /// Matches `challenge_scalar_powers` in Rust.
    function challengeScalarPowers(Transcript memory t, uint256 len)
        internal
        pure
        returns (uint256[] memory powers)
    {
        uint256 q = challengeScalar(t);
        powers = new uint256[](len);
        powers[0] = 1;
        for (uint256 i = 1; i < len; i++) {
            powers[i] = mulmod(powers[i - 1], q, R);
        }
    }

    /// @notice Derive Montgomery powers: (1, q, q^2, ..., q^(len-1)).
    /// Matches `challenge_scalar_powers_optimized` in Rust.
    function challengeScalarPowersMont(Transcript memory t, uint256 len)
        internal
        pure
        returns (uint256[] memory powers)
    {
        uint256 q = challengeScalarMont(t);
        powers = new uint256[](len);
        powers[0] = 1;
        for (uint256 i = 1; i < len; i++) {
            powers[i] = mulmod(powers[i - 1], q, R);
        }
    }
}
