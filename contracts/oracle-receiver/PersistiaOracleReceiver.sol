// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Persistia Oracle Receiver — Chainlink AggregatorV3Interface compatible
/// @notice Receives price data from Persistia Oracle Network via relay transactions.
///         Any DeFi protocol expecting a Chainlink feed can read from this contract.
/// @dev Deployed deterministically via PersistiaOracleFactory using CREATE2.
///      Same (feedId, decimals) always produces the same address on any chain.

interface AggregatorV3Interface {
    function decimals() external view returns (uint8);
    function description() external view returns (string memory);
    function version() external view returns (uint256);
    function getRoundData(uint80 _roundId) external view returns (
        uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
    );
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
    );
}

contract PersistiaOracleReceiver is AggregatorV3Interface {
    struct RoundData {
        int256 answer;
        uint256 updatedAt;
        uint256 observers;
    }

    uint8 public immutable override decimals;
    string public override description;
    uint256 public constant override version = 1;

    uint80 public latestRoundId;
    mapping(uint80 => RoundData) public rounds;

    event AnswerUpdated(int256 indexed current, uint256 indexed roundId, uint256 updatedAt);

    constructor(uint8 _decimals, string memory _description) {
        decimals = _decimals;
        description = _description;
    }

    /// @notice Push a new oracle value from the Persistia network.
    /// @dev Called by any relayer (user wallet or keeper). The attestation hash
    ///      is a commitment from the Persistia validator quorum. Signature
    ///      verification is optional for MVP — the relayer trusts the Persistia
    ///      API from which they fetched the attestation.
    /// @param _answer The oracle value, scaled to `decimals` decimal places
    /// @param _roundId Sequential round number from Persistia consensus
    /// @param _updatedAt Unix timestamp (seconds) when the value was committed
    /// @param _observers Number of Persistia validators that observed this value
    /// @param _attestationHash SHA-256 hash of the canonical attestation payload
    /// @param _signatures Packed validator signatures over the attestation hash
    function transmit(
        int256 _answer,
        uint80 _roundId,
        uint256 _updatedAt,
        uint256 _observers,
        bytes32 _attestationHash,
        bytes calldata _signatures
    ) external {
        require(_roundId > latestRoundId, "stale round");
        require(_observers > 0, "no observers");

        rounds[_roundId] = RoundData({
            answer: _answer,
            updatedAt: _updatedAt,
            observers: _observers
        });
        latestRoundId = _roundId;

        emit AnswerUpdated(_answer, _roundId, _updatedAt);
    }

    /// @notice Chainlink-compatible: get the latest round data
    function latestRoundData() external view override returns (
        uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
    ) {
        RoundData storage r = rounds[latestRoundId];
        return (latestRoundId, r.answer, r.updatedAt, r.updatedAt, latestRoundId);
    }

    /// @notice Chainlink-compatible: get historical round data
    function getRoundData(uint80 _roundId) external view override returns (
        uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
    ) {
        RoundData storage r = rounds[_roundId];
        require(r.updatedAt > 0, "round not found");
        return (_roundId, r.answer, r.updatedAt, r.updatedAt, _roundId);
    }
}
