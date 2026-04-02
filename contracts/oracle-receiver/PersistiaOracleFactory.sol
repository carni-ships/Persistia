// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./PersistiaOracleReceiver.sol";

/// @title Persistia Oracle Factory — Deterministic CREATE2 deployment
/// @notice Deploys PersistiaOracleReceiver instances at deterministic addresses.
///         Same (feedId, decimals) always produces the same address regardless of
///         who deploys or when. Use computeAddress() to predict the address before
///         deployment.
/// @dev Deploy this factory at a deterministic address on each chain using
///      Nick's factory (0x4e59b44847b379578588920cA78FbF26c0B4956C) so that the
///      factory itself is at the same address across all chains.

contract PersistiaOracleFactory {
    event OracleDeployed(string feedId, uint8 decimals, address oracle);

    mapping(bytes32 => address) public oracles;

    /// @notice Deploy a new oracle receiver for a feed, or return existing
    /// @param feedId The Persistia feed identifier (e.g. "BTC/USD:pyth")
    /// @param decimals_ Price decimals (usually 8)
    /// @return oracle The address of the (new or existing) oracle contract
    function deployOracle(
        string calldata feedId,
        uint8 decimals_
    ) external returns (address oracle) {
        bytes32 salt = keccak256(abi.encodePacked(feedId, decimals_));

        if (oracles[salt] != address(0)) {
            return oracles[salt];
        }

        oracle = address(new PersistiaOracleReceiver{salt: salt}(decimals_, feedId));
        oracles[salt] = oracle;

        emit OracleDeployed(feedId, decimals_, oracle);
    }

    /// @notice Predict the deterministic address for a feed oracle
    /// @dev Pure CREATE2 computation — works before deployment
    function computeAddress(
        string calldata feedId,
        uint8 decimals_
    ) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(feedId, decimals_));
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(PersistiaOracleReceiver).creationCode,
                abi.encode(decimals_, feedId)
            )
        );
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), salt, initCodeHash)
        ))));
    }

    /// @notice Check if an oracle is already deployed for a feed
    function getOracle(string calldata feedId, uint8 decimals_) external view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(feedId, decimals_));
        return oracles[salt];
    }
}
