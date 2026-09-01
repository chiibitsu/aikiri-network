// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AikiriLedger
/// @notice Witness contract for the Aikiri chain. Records block index -> block hash.
///         v1: single validator (owner). v2 will accept multiple signers.
///         No content is ever stored here. Only hashes.
/// @author Angeline S. Viray
contract AikiriLedger {
    struct Anchor {
        bytes32 blockHash;
        uint64 anchoredAt; // Base block timestamp
        address by;
    }

    address public owner;
    bytes32 public genesisHash;
    uint256 public latestIndex;
    mapping(uint256 => Anchor) private _anchors;

    event Anchored(uint256 indexed index, bytes32 indexed blockHash, address by);
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error AlreadyAnchored(uint256 index);
    error NotSequential(uint256 expected, uint256 got);
    error ZeroHash();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param _genesisHash hash of block 0 of the Aikiri chain.
    constructor(bytes32 _genesisHash) {
        if (_genesisHash == bytes32(0)) revert ZeroHash();
        owner = msg.sender;
        genesisHash = _genesisHash;
        _anchors[0] = Anchor({blockHash: _genesisHash, anchoredAt: uint64(block.timestamp), by: msg.sender});
        latestIndex = 0;
        emit Anchored(0, _genesisHash, msg.sender);
    }

    /// @notice Anchor the next block. Must be sequential; a block can never be re-anchored.
    function anchor(uint256 index, bytes32 blockHash) external onlyOwner {
        if (blockHash == bytes32(0)) revert ZeroHash();
        if (_anchors[index].blockHash != bytes32(0)) revert AlreadyAnchored(index);
        if (index != latestIndex + 1) revert NotSequential(latestIndex + 1, index);
        _anchors[index] = Anchor({blockHash: blockHash, anchoredAt: uint64(block.timestamp), by: msg.sender});
        latestIndex = index;
        emit Anchored(index, blockHash, msg.sender);
    }

    function blocks(uint256 index) external view returns (bytes32 blockHash, uint64 anchoredAt, address by) {
        Anchor memory a = _anchors[index];
        return (a.blockHash, a.anchoredAt, a.by);
    }

    /// @notice Verify a claimed hash for an index. Anyone can call. Free (view).
    function matches(uint256 index, bytes32 blockHash) external view returns (bool) {
        return _anchors[index].blockHash == blockHash && blockHash != bytes32(0);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }
}
