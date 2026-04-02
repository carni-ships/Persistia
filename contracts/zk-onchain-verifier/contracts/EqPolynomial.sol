// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title EqPolynomial and EqPlusOnePolynomial
/// @notice Solidity port of jolt-core's eq_poly.rs and eq_plus_one_poly.rs.
///
/// EqPolynomial:     eq(x, y) = prod_i (x_i * y_i + (1 - x_i) * (1 - y_i))
/// EqPlusOnePolynomial: eq+1(x, y) = 1 iff y = x + 1 (big-endian binary addition)
library EqPolynomial {

    uint256 internal constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @notice Evaluate eq(x, y) = prod_i (x_i * y_i + (1-x_i)*(1-y_i)).
    /// Both x and y are in the same endianness (both big-endian).
    function mle(
        uint256[] memory x,
        uint256[] memory y
    ) internal pure returns (uint256 result) {
        require(x.length == y.length, "eq: length mismatch");
        // eq(x,y) = prod_i (2*xi*yi - xi - yi + 1)
        assembly {
            let r := R
            let len := mload(x)
            let xPtr := add(x, 0x20)
            let yPtr := add(y, 0x20)
            result := 1
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let off := mul(i, 0x20)
                let xi := mload(add(xPtr, off))
                let yi := mload(add(yPtr, off))
                let xiyi := mulmod(xi, yi, r)
                // term = 2*xi*yi + 1 - xi - yi = xiyi + (1 + xiyi - xi - yi)
                let term := addmod(xiyi, addmod(addmod(1, xiyi, r), sub(r, addmod(xi, yi, r)), r), r)
                result := mulmod(result, term, r)
            }
        }
    }

    /// @notice Evaluate eq(x, y) where x is reversed relative to y.
    /// Used when x is big-endian and y is little-endian (or vice versa).
    function mleReversed(
        uint256[] memory x,
        uint256[] memory y
    ) internal pure returns (uint256 result) {
        require(x.length == y.length, "eq: length mismatch");
        assembly {
            let r := R
            let n := mload(x)
            let xPtr := add(x, 0x20)
            let yPtr := add(y, 0x20)
            result := 1
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let xi := mload(add(xPtr, mul(i, 0x20)))
                let yi := mload(add(yPtr, mul(sub(sub(n, 1), i), 0x20)))
                let xiyi := mulmod(xi, yi, r)
                let term := addmod(xiyi, addmod(addmod(1, xiyi, r), sub(r, addmod(xi, yi, r)), r), r)
                result := mulmod(result, term, r)
            }
        }
    }

    /// @notice Evaluate LT(x, y): "less than" polynomial over big-endian field vectors.
    /// For boolean inputs, returns 1 iff the integer represented by x < y.
    /// Over the field, interpolates the LT indicator function.
    ///
    /// Algorithm (MSB to LSB iteration):
    ///   lt = 0, eq_term = 1
    ///   for each position i from MSB (index 0) to LSB (index l-1):
    ///     lt += (1 - x[i]) * y[i] * eq_term
    ///     eq_term *= 1 - x[i] - y[i] + 2*x[i]*y[i]
    function lt(
        uint256[] memory x,
        uint256[] memory y
    ) internal pure returns (uint256 result) {
        require(x.length == y.length, "lt: length mismatch");
        assembly {
            let r := R
            let len := mload(x)
            let xPtr := add(x, 0x20)
            let yPtr := add(y, 0x20)
            result := 0
            let eqTerm := 1
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let off := mul(i, 0x20)
                let xi := mload(add(xPtr, off))
                let yi := mload(add(yPtr, off))
                // contrib = (1 - xi) * yi * eqTerm
                let contrib := mulmod(mulmod(addmod(1, sub(r, xi), r), yi, r), eqTerm, r)
                result := addmod(result, contrib, r)
                // eqTerm *= 1 + 2*xi*yi - xi - yi
                let xiyi := mulmod(xi, yi, r)
                eqTerm := mulmod(eqTerm, addmod(addmod(1, addmod(xiyi, xiyi, r), r), sub(r, addmod(xi, yi, r)), r), r)
            }
        }
    }

    /// @notice Evaluate EqPlusOne(x, y): returns 1 iff y = x + 1 in binary (big-endian).
    /// O(n) algorithm using prefix/suffix product precomputation.
    function eqPlusOne(
        uint256[] memory x,
        uint256[] memory y
    ) internal pure returns (uint256 result) {
        require(x.length == y.length, "eqPlusOne: length mismatch");
        uint256 l = x.length;
        if (l == 0) return 0;

        // Precompute suffix eq products: suffixEq[k] = prod_{i=k..l-1} eq_term(x[l-1-i], y[l-1-i])
        // But we index from LSB, so position k corresponds to bit index l-1-k in the arrays.
        // lowerPrefix[k] = prod_{i=0..k-1} x[l-1-i] * (1-y[l-1-i])
        // higherSuffix[k] = prod_{i=k+1..l-1} eq_term(x[l-1-i], y[l-1-i])

        // Build suffix eq products (from MSB to LSB direction)
        // suffixEq[k] = prod for positions k+1..l-1
        // We compute eqTerms for each position and build suffix products
        uint256[] memory eqTerms = new uint256[](l);
        for (uint256 i = 0; i < l; i++) {
            uint256 xv = x[l - 1 - i];
            uint256 yv = y[l - 1 - i];
            uint256 xvyv = mulmod(xv, yv, R);
            uint256 term = addmod(
                addmod(1, xvyv, R),
                R - addmod(xv, yv, R),
                R
            );
            eqTerms[i] = addmod(xvyv, term, R);
        }

        // suffixEq[k] = prod_{j=k+1}^{l-1} eqTerms[j]
        // Build from right to left
        // We'll compute on the fly using a running suffix product

        // Also build prefix lower products on the fly
        uint256 lowerProd = 1; // prod_{i=0..k-1} x[l-1-i]*(1-y[l-1-i])

        // Precompute full suffix product, then divide out as we go
        // Actually simpler: precompute suffix array
        // suffixProd[k] = prod_{j=k}^{l-1} eqTerms[j]
        // Then higherProd for position k = suffixProd[k+1] (or 1 if k==l-1)

        uint256[] memory suffixProd = new uint256[](l + 1);
        suffixProd[l] = 1;
        for (uint256 i = l; i > 0; i--) {
            suffixProd[i - 1] = mulmod(suffixProd[i], eqTerms[i - 1], R);
        }

        result = 0;
        for (uint256 k = 0; k < l; k++) {
            uint256 kthProd = mulmod(
                addmod(1, R - x[l - 1 - k], R),
                y[l - 1 - k],
                R
            );

            uint256 higherProd = suffixProd[k + 1];

            result = addmod(
                result,
                mulmod(mulmod(lowerProd, kthProd, R), higherProd, R),
                R
            );

            // Update prefix for next iteration
            lowerProd = mulmod(
                lowerProd,
                mulmod(x[l - 1 - k], addmod(1, R - y[l - 1 - k], R), R),
                R
            );
        }
    }

    /// @notice Evaluate eq(x, arr[offset..offset+len]) without allocating (non-reversed).
    function mleSlice(
        uint256[] memory x,
        uint256[] memory arr,
        uint256 offset,
        uint256 len
    ) internal pure returns (uint256 result) {
        require(x.length == len, "eq: length mismatch");
        assembly {
            let r := R
            let xPtr := add(x, 0x20)
            let arrPtr := add(arr, 0x20)
            result := 1
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let xi := mload(add(xPtr, mul(i, 0x20)))
                let yi := mload(add(arrPtr, mul(add(offset, i), 0x20)))
                let xiyi := mulmod(xi, yi, r)
                let term := addmod(xiyi, addmod(addmod(1, xiyi, r), sub(r, addmod(xi, yi, r)), r), r)
                result := mulmod(result, term, r)
            }
        }
    }

    /// @notice Evaluate eq(x, reversed_slice(arr, offset, len)) without allocating.
    /// Equivalent to mle(x, reverse(arr[offset..offset+len])).
    function mleSliceReversed(
        uint256[] memory x,
        uint256[] memory arr,
        uint256 offset,
        uint256 len
    ) internal pure returns (uint256 result) {
        require(x.length == len, "eq: length mismatch");
        assembly {
            let r := R
            let xPtr := add(x, 0x20)
            let arrPtr := add(arr, 0x20)
            result := 1
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let xi := mload(add(xPtr, mul(i, 0x20)))
                let yi := mload(add(arrPtr, mul(add(offset, sub(sub(len, 1), i)), 0x20)))
                let xiyi := mulmod(xi, yi, r)
                let term := addmod(xiyi, addmod(addmod(1, xiyi, r), sub(r, addmod(xi, yi, r)), r), r)
                result := mulmod(result, term, r)
            }
        }
    }

    /// @notice Evaluate 3 eq polynomials in a single pass over challenges.
    /// @notice Evaluate lt(reversed_slice(arr, offset, len), y) without allocating.
    /// Equivalent to lt(reverse(arr[offset..offset+len]), y).
    function ltSliceReversed(
        uint256[] memory arr,
        uint256 offset,
        uint256 len,
        uint256[] memory y
    ) internal pure returns (uint256 result) {
        require(len == y.length, "lt: length mismatch");
        assembly {
            let r := R
            let arrPtr := add(arr, 0x20)
            let yPtr := add(y, 0x20)
            result := 0
            let eqTerm := 1
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let xi := mload(add(arrPtr, mul(add(offset, sub(sub(len, 1), i)), 0x20)))
                let yi := mload(add(yPtr, mul(i, 0x20)))
                let contrib := mulmod(mulmod(addmod(1, sub(r, xi), r), yi, r), eqTerm, r)
                result := addmod(result, contrib, r)
                let xiyi := mulmod(xi, yi, r)
                eqTerm := mulmod(eqTerm, addmod(addmod(1, addmod(xiyi, xiyi, r), r), sub(r, addmod(xi, yi, r)), r), r)
            }
        }
    }

    /// @notice Evaluate eqPlusOne(x, reversed_slice(arr, offset, len)) without allocating.
    function eqPlusOneSliceReversed(
        uint256[] memory x,
        uint256[] memory arr,
        uint256 offset,
        uint256 len
    ) internal pure returns (uint256 result) {
        require(x.length == len, "eqPlusOne: length mismatch");
        if (len == 0) return 0;

        // Build eqTerms and suffix products using reversed indexing
        uint256[] memory eqTerms = new uint256[](len);
        for (uint256 i = 0; i < len; i++) {
            uint256 xv = x[len - 1 - i];
            uint256 yv = arr[offset + i]; // reversed: arr[offset+len-1-i] → position i in reversed = arr[offset + len-1 - (len-1-i)] = arr[offset+i]
            uint256 xvyv = mulmod(xv, yv, R);
            uint256 term = addmod(
                addmod(1, xvyv, R),
                R - addmod(xv, yv, R),
                R
            );
            eqTerms[i] = addmod(xvyv, term, R);
        }

        uint256[] memory suffixProd = new uint256[](len + 1);
        suffixProd[len] = 1;
        for (uint256 i = len; i > 0; i--) {
            suffixProd[i - 1] = mulmod(suffixProd[i], eqTerms[i - 1], R);
        }

        result = 0;
        uint256 lowerProd = 1;
        for (uint256 k = 0; k < len; k++) {
            uint256 xv = x[len - 1 - k];
            uint256 yv = arr[offset + k]; // reversed y[k] = arr[offset + len-1-k] when y is reversed...
            // Wait, we need y[l-1-k] in the original eqPlusOne.
            // In eqPlusOne(x, y), position k accesses x[l-1-k] and y[l-1-k].
            // Here y = reverse(arr[offset..offset+len]), so y[j] = arr[offset+len-1-j].
            // y[l-1-k] = arr[offset+len-1-(l-1-k)] = arr[offset+k].
            uint256 kthProd = mulmod(
                addmod(1, R - xv, R),
                yv,
                R
            );

            result = addmod(
                result,
                mulmod(mulmod(lowerProd, kthProd, R), suffixProd[k + 1], R),
                R
            );

            lowerProd = mulmod(
                lowerProd,
                mulmod(xv, addmod(1, R - yv, R), R),
                R
            );
        }
    }
}
