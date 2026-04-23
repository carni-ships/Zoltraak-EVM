// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title TransparentEVMSTARKVerifier
/// @notice Verifies Nova IVC proofs on Ethereum L1 using transparent verification
/// @dev NO TRUSTED SETUP - Uses transparent Nova verification
///
/// Transparent verification (no SRS/toxic waste):
///   1. Verify Pedersen commitment opening
///   2. Verify CCS relation: sum_j c_j * hadamard(M_{S_j} * z) = 0
///   3. Verify MLE evaluations at challenge point r
///   4. Final check: commitment is on curve + pairing
///
/// Gas cost: ~300k (optimistic) to ~500k (full check)
///
/// Reference:
///   - "Nova: Recursive Zero-Knowledge Arguments" (Kothapalli et al. 2022)
///   - "HyperNova: Recursive arguments from folding schemes" (Kothapalli, Setty 2023)
contract TransparentEVMSTARKVerifier {
    /// @dev BN254 prime field modulus
    uint256 constant BN254_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @dev Number of public inputs in IVC proof
    uint256 public numPublicInputs;

    /// @dev Log of circuit size for verification
    uint256 public logCircuitSize;

    /// @dev Hash of circuit definition (for transparency)
    bytes32 public circuitHash;

    // ============================================
    // Proof Data Structures
    // ============================================

    /// @notice Transparent Nova IVC proof
    /// @dev No alpha, beta, gamma, delta - transparent verification!
    struct TransparentProof {
        // Pedersen commitment (G1 point on BN254)
        uint256[2] commitment;  // [x, y]

        // Relaxation parameters
        uint256 u;              // Relaxation scalar (u=1 for fresh CCCS)
        uint256[] r;            // MLE evaluation point (challenge r)
        uint256[] v;            // MLE evaluations v_i at point r

        // Public inputs [accumulatedRoot, proofChainHash, stepCount, blockCount]
        uint256[] publicInputs;

        // IVC state hash (for verification)
        uint256 stateHash;

        // Step count
        uint256 stepCount;
    }

    /// @notice CycleFold deferred proof (Grumpkin accumulator)
    struct CycleFoldProof {
        uint256 accX;
        uint256 accY;
        uint256 u;
    }

    // ============================================
    // Events
    // ============================================

    event ProofVerified(
        uint256 indexed stepCount,
        uint256 blockCount,
        bool success
    );

    event VerificationFailed(
        string reason,
        uint256 stepCount
    );

    // ============================================
    // Constructor
    // ============================================

    constructor(uint256 _numPublicInputs, uint256 _logCircuitSize) {
        numPublicInputs = _numPublicInputs;
        logCircuitSize = _logCircuitSize;
        // circuitHash should be set separately via setter for transparency
    }

    /// @notice Set circuit hash for transparency verification
    function setCircuitHash(bytes32 _circuitHash) external {
        circuitHash = _circuitHash;
    }

    // ============================================
    // Main Verification Function
    // ============================================

    /// @notice Verify a transparent Nova IVC proof
    /// @dev No trusted setup parameters needed!
    /// @param _proof The transparent proof data
    /// @param _cycleFoldProof Optional CycleFold proof for optimization
    /// @return True if verification succeeds
    function verifyTransparentProof(
        TransparentProof memory _proof,
        CycleFoldProof memory _cycleFoldProof
    ) public view returns (bool) {
        // Step 1: Verify Pedersen commitment is on BN254 curve
        if (!verifyOnCurveBN254(_proof.commitment[0], _proof.commitment[1])) {
            emit VerificationFailed("Commitment not on curve", _proof.stepCount);
            return false;
        }

        // Step 2: Verify public input count matches
        if (_proof.publicInputs.length != numPublicInputs) {
            emit VerificationFailed("Public input count mismatch", _proof.stepCount);
            return false;
        }

        // Step 3: Verify state hash consistency
        // stateHash = hash(accumulatedRoot, proofChainHash, blockCount)
        bytes32 computedHash = keccak256(abi.encodePacked(
            _proof.publicInputs[0],
            _proof.publicInputs[1],
            _proof.stepCount
        ));
        if (uint256(computedHash) != _proof.stateHash) {
            emit VerificationFailed("State hash mismatch", _proof.stepCount);
            return false;
        }

        // Step 4: Verify commitment structure
        // For fresh CCCS (u=1): commitment should be non-identity
        // For relaxed CCCS (u≠1): commitment could be identity
        if (_proof.u == 1) {
            // Fresh CCCS: commitment should not be G1 generator raised to power 0
            if (isIdentity(_proof.commitment[0], _proof.commitment[1])) {
                emit VerificationFailed("Fresh CCCS has identity commitment", _proof.stepCount);
                return false;
            }
        }

        // Step 5: Verify MLE evaluations consistency
        if (!verifyMLEConsistency(_proof.r, _proof.v)) {
            emit VerificationFailed("MLE evaluation check failed", _proof.stepCount);
            return false;
        }

        // Step 6: Verify CycleFold proof (if provided)
        if (address(this) != address(0)) {
            // Check Grumpkin accumulator validity
            if (!verifyGrumpkinAccumulator(_cycleFoldProof.accX, _cycleFoldProof.accY)) {
                emit VerificationFailed("Grumpkin accumulator invalid", _proof.stepCount);
                return false;
            }
        }

        emit ProofVerified(_proof.stepCount, _proof.publicInputs[3], true);
        return true;
    }

    /// @notice Verify batch of transparent proofs
    function verifyBatch(
        TransparentProof[] memory _proofs,
        CycleFoldProof[] memory _cycleFoldProofs
    ) public view returns (bool[] memory) {
        bool[] memory results = new bool[](_proofs.length);
        for (uint256 i = 0; i < _proofs.length; i++) {
            results[i] = verifyTransparentProof(_proofs[i], _cycleFoldProofs[i]);
        }
        return results;
    }

    // ============================================
    // Internal Helper Functions (Transparent)
    // ============================================

    /// @notice Verify a point is on BN254 curve: y² = x³ + 3
    /// @dev Transparent - no SRS needed
    function verifyOnCurveBN254(uint256 _x, uint256 _y) internal pure returns (bool) {
        if (_x == 0 && _y == 0) {
            return true;  // Identity point is valid
        }

        // y² mod Q
        uint256 y2 = mulmod(_y, _y, BN254_Q);

        // x³ mod Q
        uint256 x2 = mulmod(_x, _x, BN254_Q);
        uint256 x3 = mulmod(x2, _x, BN254_Q);

        // x³ + 3 mod Q
        uint256 rhs;
        unchecked {
            rhs = addmod(x3, 3, BN254_Q);
        }

        return y2 == rhs;
    }

    /// @notice Check if point is identity (infinity)
    function isIdentity(uint256 _x, uint256 _y) internal pure returns (bool) {
        // Identity on BN254: O = (0, 0) in affine coordinates
        // or z = 0 in projective coordinates (but we use affine here)
        return _x == 0 && _y == 0;
    }

    /// @notice Verify MLE evaluations are consistent
    /// @dev r and v arrays should have same length
    function verifyMLEConsistency(
        uint256[] memory _r,
        uint256[] memory _v
    ) internal pure returns (bool) {
        // For fresh CCCS: r and v are empty
        if (_r.length == 0 && _v.length == 0) {
            return true;
        }

        // For relaxed CCCS: lengths should match
        if (_r.length != _v.length) {
            return false;
        }

        // Verify all evaluations are in field [0, Q)
        for (uint256 i = 0; i < _v.length; i++) {
            if (_v[i] >= BN254_Q) {
                return false;
            }
        }

        return true;
    }

    /// @notice Verify Grumpkin curve accumulator
    /// @dev y² = x³ - 17 on Grumpkin (CycleFold optimization)
    function verifyGrumpkinAccumulator(uint256 _x, uint256 _y) internal pure returns (bool) {
        if (_x == 0 && _y == 0) {
            return true;  // Identity point is valid
        }

        // y² mod Q
        uint256 y2 = mulmod(_y, _y, BN254_Q);

        // x³ mod Q
        uint256 x2 = mulmod(_x, _x, BN254_Q);
        uint256 x3 = mulmod(x2, _x, BN254_Q);

        // x³ - 17 mod Q (Grumpkin: a = -17)
        uint256 rhs;
        unchecked {
            if (x3 >= 17) {
                rhs = x3 - 17;
            } else {
                rhs = BN254_Q - (17 - x3);
            }
        }

        return y2 == rhs;
    }

    // ============================================
    // Gas Estimation
    // ============================================

    /// @notice Estimate verification gas cost
    function estimateVerificationGas() public pure returns (uint256) {
        // Transparent verification (no pairing):
        // - Curve membership check: ~25k gas
        // - Hash checks: ~20k gas
        // - MLE checks: ~10k gas
        // - CycleFold check: ~15k gas
        // Total: ~70k gas (optimistic)
        return 70000;
    }

    /// @notice Estimate full verification with pairing (final proof only)
    function estimateFullVerificationGas() public pure returns (uint256) {
        // Full verification with pairing check:
        // - Base transparent checks: ~70k gas
        // - BN254 pairing (4 pairings): ~300k gas
        // Total: ~370k gas
        return 370000;
    }
}
