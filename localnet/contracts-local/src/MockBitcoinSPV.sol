// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBitcoinSPV} from "bitvm-l2/interfaces/IBitcoinSPV.sol";

/// @title MockBitcoinSPV
/// @notice Local-only stand-in for the GOAT BitcoinSPV relay used by the BitVM2 localnet.
///         Implements exactly the four functions the node calls
///         (goat_adaptor.rs):
///             - blockHash(uint256)          view
///             - latestHeight()              view
///             - postBlockHash(uint256,bytes32)
///             - postBlockHashBatch(uint256[],bytes32[])
///         plus IBitcoinSPV (blockHash + latestHeight), so it can be wired into the Gateway as the
///         `bitcoinSPV` dependency and satisfy Gateway._verifyMerkleInclusion.
///
///         Header hashes are stored exactly as posted. The node posts BlockHash::to_byte_array(), i.e.
///         internal (little-endian) byte order, which is the same order Gateway._verifyMerkleInclusion
///         compares against (sha256d(rawHeader)). Do NOT byte-reverse anything if the node is the only
///         poster (spv_maintenance_tasks.rs, ENABLE_UPDATE_SPV_CONTRACT).
///
///         Posting model: `openPosting` (constructor arg) lets anybody post; otherwise only `owner` and
///         addresses whitelisted via setPoster() may post. The node's SPV poster is committee_0's
///         GOAT_PRIVATE_KEY address; deploy-local.sh both enables openPosting and whitelists it.
///
///         batch/postBlockHash are permissive on ordering: the node always posts contiguously from
///         latestHeight()+1 via the batch call, but it also calls the single postBlockHash() to OVERWRITE
///         an already-posted height on a regtest rollback (goat_chain/mod.rs:456-464), so this mock must
///         accept arbitrary-height writes. latestHeight only ever advances to the highest height seen.
contract MockBitcoinSPV is IBitcoinSPV {
    address public owner;
    bool public openPosting;
    uint256 public override latestHeight;

    mapping(address => bool) public posters;
    mapping(uint256 => bytes32) private hashes;

    event BlockHashPosted(uint256 indexed height, bytes32 headerHash);
    event PosterSet(address indexed poster, bool allowed);
    event OpenPostingSet(bool open);

    error NotOwner();
    error NotAuthorizedPoster();
    error LengthMismatch();
    error EmptyBatch();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyPoster() {
        if (!openPosting && msg.sender != owner && !posters[msg.sender]) revert NotAuthorizedPoster();
        _;
    }

    /// @param _initialHeight starting latestHeight (0 lets the node backfill from height 1)
    /// @param _openPosting   true => anybody may post (convenient for a single-poster localnet)
    constructor(uint256 _initialHeight, bool _openPosting) {
        owner = msg.sender;
        latestHeight = _initialHeight;
        openPosting = _openPosting;
        posters[msg.sender] = true;
    }

    // ---- IBitcoinSPV views ----
    function blockHash(uint256 height) external view override returns (bytes32) {
        return hashes[height];
    }

    // latestHeight() is the auto-generated getter of the `override` public state variable above,
    // which satisfies IBitcoinSPV.latestHeight().

    // ---- posting ----
    function postBlockHash(uint256 height, bytes32 headerHash) external onlyPoster {
        _post(height, headerHash);
    }

    function postBlockHashBatch(uint256[] calldata heights, bytes32[] calldata headerHashes) external onlyPoster {
        if (heights.length != headerHashes.length) revert LengthMismatch();
        if (heights.length == 0) revert EmptyBatch();
        for (uint256 i = 0; i < heights.length; i++) {
            _post(heights[i], headerHashes[i]);
        }
    }

    function _post(uint256 height, bytes32 headerHash) internal {
        hashes[height] = headerHash;
        if (height > latestHeight) {
            latestHeight = height;
        }
        emit BlockHashPosted(height, headerHash);
    }

    // ---- owner helpers (regtest reorgs / setup) ----
    function setPoster(address poster, bool allowed) external onlyOwner {
        posters[poster] = allowed;
        emit PosterSet(poster, allowed);
    }

    function setOpenPosting(bool open) external onlyOwner {
        openPosting = open;
        emit OpenPostingSet(open);
    }

    /// @notice Force-set a height's hash and/or latestHeight without ordering checks (setup/reorg escape hatch).
    function forceSet(uint256 height, bytes32 headerHash) external onlyOwner {
        hashes[height] = headerHash;
        emit BlockHashPosted(height, headerHash);
    }

    function setLatestHeight(uint256 height) external onlyOwner {
        latestHeight = height;
    }
}
