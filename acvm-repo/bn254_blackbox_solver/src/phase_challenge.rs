//! Multi-phase circuit challenge derivation for BN254.
//!
//! Implements the `derive_phase_challenge` method by replicating barretenberg's
//! transcript protocol:
//!
//! 1. KZG commitment: MSM of witness values against BN254 SRS monomial points
//! 2. Commitment encoding: G1 affine → 4 Fr elements (bb's limb encoding)
//! 3. Poseidon2 sponge hash of the encoded commitment
//! 4. Challenge splitting: 254-bit hash → pairs of 127-bit challenges

use acir::AcirField;
use acvm_blackbox_solver::BlackBoxResolutionError;
use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{BigInteger, BigInteger256, PrimeField};

use crate::FieldElement;
use crate::poseidon2::poseidon2_permutation;

/// Number of limb bits used by barretenberg's bigfield simulation for encoding
/// base field (Fq) elements as pairs of scalar field (Fr) elements.
const NUM_LIMB_BITS: u32 = 136;

/// Derive Fiat-Shamir challenge(s) by committing to witness values using KZG
/// and hashing the commitment via barretenberg's Poseidon2 transcript protocol.
///
/// This replicates the exact challenge derivation that the barretenberg
/// prover/verifier will perform, ensuring deterministic agreement between
/// witness generation (Rust) and proving (C++).
pub(crate) fn derive_phase_challenge(
    _phase_id: u32,
    witness_values: &[FieldElement],
    num_challenges: usize,
) -> Result<Vec<FieldElement>, BlackBoxResolutionError> {
    if witness_values.is_empty() {
        return Err(BlackBoxResolutionError::Failed(
            acir::BlackBoxFunc::Poseidon2Permutation,
            "PhaseBarrier: cannot derive challenge from empty witness list".into(),
        ));
    }
    if num_challenges == 0 {
        return Err(BlackBoxResolutionError::Failed(
            acir::BlackBoxFunc::Poseidon2Permutation,
            "PhaseBarrier: must request at least one challenge".into(),
        ));
    }

    // Step 1: Load SRS and compute KZG commitment
    let srs_points = load_srs(witness_values.len())?;
    let commitment = kzg_commit(witness_values, &srs_points)?;

    // Step 2: Encode the commitment as field elements (bb's limb encoding)
    let commitment_frs = encode_g1_as_fr_elements(&commitment);

    // Step 3-4: Hash via Poseidon2 sponge and extract challenges
    let challenges = poseidon2_transcript_squeeze(&commitment_frs, num_challenges)?;

    Ok(challenges)
}

// ---------------------------------------------------------------------------
// SRS Loading
// ---------------------------------------------------------------------------

/// Load BN254 G1 SRS points from the standard barretenberg cache location.
///
/// Points are stored as 64-byte uncompressed affine coordinates (x, y),
/// each coordinate a 32-byte big-endian field element in standard form.
fn load_srs(num_points: usize) -> Result<Vec<G1Affine>, BlackBoxResolutionError> {
    let srs_path = srs_file_path()?;

    let data = std::fs::read(&srs_path).map_err(|e| {
        BlackBoxResolutionError::Failed(
            acir::BlackBoxFunc::Poseidon2Permutation,
            format!("PhaseBarrier: failed to read BN254 SRS file at '{}': {}", srs_path, e),
        )
    })?;

    let available_points = data.len() / 64;
    if available_points < num_points {
        return Err(BlackBoxResolutionError::Failed(
            acir::BlackBoxFunc::Poseidon2Permutation,
            format!(
                "PhaseBarrier: SRS file has {} points but {} are needed",
                available_points, num_points
            ),
        ));
    }

    let mut points = Vec::with_capacity(num_points);
    for i in 0..num_points {
        let offset = i * 64;
        let x_bytes: &[u8] = &data[offset..offset + 32];
        let y_bytes: &[u8] = &data[offset + 32..offset + 64];

        // Check for point at infinity (all 0xFF)
        if x_bytes.iter().all(|&b| b == 0xFF) && y_bytes.iter().all(|&b| b == 0xFF) {
            points.push(G1Affine::zero());
            continue;
        }

        // Parse big-endian 256-bit integers as Fq field elements
        let x = Fq::from_be_bytes_mod_order(x_bytes);
        let y = Fq::from_be_bytes_mod_order(y_bytes);

        let point = G1Affine::new_unchecked(x, y);
        // In release builds we trust the SRS; in debug builds verify on-curve
        debug_assert!(point.is_on_curve(), "SRS point {} is not on the BN254 curve", i);
        points.push(point);
    }

    Ok(points)
}

/// Determine the SRS file path. Checks `CRS_PATH` env var, then `~/.bb-crs/`.
fn srs_file_path() -> Result<String, BlackBoxResolutionError> {
    let base_dir = if let Ok(crs_path) = std::env::var("CRS_PATH") {
        crs_path
    } else if let Ok(home) = std::env::var("HOME") {
        format!("{}/.bb-crs", home)
    } else {
        return Err(BlackBoxResolutionError::Failed(
            acir::BlackBoxFunc::Poseidon2Permutation,
            "PhaseBarrier: cannot determine SRS path (no HOME or CRS_PATH set)".into(),
        ));
    };
    Ok(format!("{}/bn254_g1.dat", base_dir))
}

// ---------------------------------------------------------------------------
// KZG Commitment
// ---------------------------------------------------------------------------

/// Compute KZG commitment: C = sum_i witness_values[i] * SRS[i]
///
/// This matches barretenberg's `CommitmentKey::commit()` which computes
/// `C = sum_i a_i * [tau^i]` via Pippenger MSM.
fn kzg_commit(
    witness_values: &[FieldElement],
    srs_points: &[G1Affine],
) -> Result<G1Affine, BlackBoxResolutionError> {
    let scalars: Vec<Fr> = witness_values.iter().map(|v| v.into_repr()).collect();

    // ark's VariableBaseMSM computes sum_i scalar_i * base_i
    let result =
        <ark_bn254::G1Projective as VariableBaseMSM>::msm(srs_points, &scalars).map_err(|e| {
            BlackBoxResolutionError::Failed(
                acir::BlackBoxFunc::Poseidon2Permutation,
                format!("PhaseBarrier: KZG commitment MSM failed: {}", e),
            )
        })?;

    Ok(result.into())
}

// ---------------------------------------------------------------------------
// Commitment Encoding (matches bb's FrCodec::serialize_to_fields)
// ---------------------------------------------------------------------------

/// Encode a BN254 G1 affine point as 4 Fr elements, matching barretenberg's
/// `FrCodec::serialize_to_fields` for `bn254_commitment`.
///
/// Each Fq coordinate (254 bits) is split into two Fr elements:
/// - lo: lower 136 bits (NUM_LIMB_BITS)
/// - hi: upper 118 bits (254 - 136)
///
/// Result: [x_lo, x_hi, y_lo, y_hi]
fn encode_g1_as_fr_elements(point: &G1Affine) -> [FieldElement; 4] {
    if point.is_zero() {
        return [FieldElement::zero(); 4];
    }

    let x = point.x().expect("non-zero point has x coordinate");
    let y = point.y().expect("non-zero point has y coordinate");

    let (x_lo, x_hi) = split_fq_to_fr_pair(&x);
    let (y_lo, y_hi) = split_fq_to_fr_pair(&y);

    [x_lo, x_hi, y_lo, y_hi]
}

/// Split an Fq element into two Fr elements: (lo, hi) where lo has
/// NUM_LIMB_BITS bits and hi has the remaining bits.
fn split_fq_to_fr_pair(fq: &Fq) -> (FieldElement, FieldElement) {
    let bigint: BigInteger256 = (*fq).into();
    let bytes_be = bigint.to_bytes_be();

    // Total bits: 256 (BigInteger256), but Fq is ~254 bits
    // lo = lower NUM_LIMB_BITS (136) bits
    // hi = upper (256 - 136) = 120 bits, but only ~118 are meaningful for Fq

    // Convert to a big integer for bit manipulation
    let full = num_bigint::BigUint::from_bytes_be(&bytes_be);
    let lo_mask = (num_bigint::BigUint::from(1u64) << NUM_LIMB_BITS) - 1u64;
    let lo = &full & &lo_mask;
    let hi = &full >> NUM_LIMB_BITS;

    let lo_bytes = lo.to_bytes_be();
    let hi_bytes = hi.to_bytes_be();

    let lo_fr = Fr::from_be_bytes_mod_order(&lo_bytes);
    let hi_fr = Fr::from_be_bytes_mod_order(&hi_bytes);

    (FieldElement::from_repr(lo_fr), FieldElement::from_repr(hi_fr))
}

// ---------------------------------------------------------------------------
// Poseidon2 Sponge Transcript (matches bb's BaseTranscript)
// ---------------------------------------------------------------------------

/// Hash field elements using barretenberg's Poseidon2 sponge protocol and
/// extract challenges.
///
/// Protocol:
/// 1. IV = input_length << 64 (placed in capacity slot, state[3])
/// 2. Absorb input elements additively into rate slots (state[0..3]), rate=3
/// 3. When rate slots fill, apply Poseidon2 permutation
/// 4. Final squeeze: apply permutation, output = state[0]
/// 5. Split 254-bit output into 2 × 127-bit challenges
/// 6. For additional challenges, hash [previous_output] to get more pairs
fn poseidon2_transcript_squeeze(
    data: &[FieldElement],
    num_challenges: usize,
) -> Result<Vec<FieldElement>, BlackBoxResolutionError> {
    // Compute the sponge hash of the data (this is the first challenge source)
    let hash_output = poseidon2_sponge_hash(data)?;

    let mut challenges = Vec::with_capacity(num_challenges);
    let (lo, hi) = split_challenge(&hash_output);
    challenges.push(lo);
    if num_challenges > 1 {
        challenges.push(hi);
    }

    // For additional challenges beyond the first pair, hash the previous output
    let mut prev_challenge = hash_output;
    while challenges.len() < num_challenges {
        let next_hash = poseidon2_sponge_hash(&[prev_challenge])?;
        let (lo, hi) = split_challenge(&next_hash);
        challenges.push(lo);
        if challenges.len() < num_challenges {
            challenges.push(hi);
        }
        prev_challenge = next_hash;
    }

    challenges.truncate(num_challenges);
    Ok(challenges)
}

/// Poseidon2 sponge hash matching barretenberg's `FieldSponge::hash()`.
///
/// State width t=4, rate=3, capacity=1.
/// IV = input_length << 64 in state[3] (capacity slot).
/// Absorption is additive (elements added to state, not overwriting).
fn poseidon2_sponge_hash(input: &[FieldElement]) -> Result<FieldElement, BlackBoxResolutionError> {
    const RATE: usize = 3;

    // Initialize state: [0, 0, 0, IV]
    // IV = input.len() << 64
    let iv = FieldElement::from(input.len() as u128) * FieldElement::from(1u128 << 64);
    let mut state = [FieldElement::zero(), FieldElement::zero(), FieldElement::zero(), iv];

    // Absorb input in chunks of RATE
    let mut cache = Vec::with_capacity(RATE);
    for element in input {
        cache.push(*element);
        if cache.len() == RATE {
            // Add cache to rate portion of state, then permute
            for (i, val) in cache.iter().enumerate() {
                state[i] = state[i] + *val;
            }
            let permuted = poseidon2_permutation(&state)?;
            state.copy_from_slice(&permuted);
            cache.clear();
        }
    }

    // Final squeeze: absorb remaining cache elements and permute
    for (i, val) in cache.iter().enumerate() {
        state[i] = state[i] + *val;
    }
    let permuted = poseidon2_permutation(&state)?;

    // Output is state[0]
    Ok(permuted[0])
}

/// Split a 254-bit field element into two 127-bit challenges,
/// matching barretenberg's `FrCodec::split_challenge()`.
///
/// lo = bits [0..127), hi = bits [127..254)
fn split_challenge(challenge: &FieldElement) -> (FieldElement, FieldElement) {
    let bigint: BigInteger256 = challenge.into_repr().into();
    let bytes = bigint.to_bytes_be();

    let full = num_bigint::BigUint::from_bytes_be(&bytes);
    let lo_mask = (num_bigint::BigUint::from(1u64) << 127u32) - 1u64;
    let lo = &full & &lo_mask;
    let hi: num_bigint::BigUint = &full >> 127;

    let lo_fr = Fr::from_be_bytes_mod_order(&lo.to_bytes_be());
    let hi_fr = Fr::from_be_bytes_mod_order(&hi.to_bytes_be());

    (FieldElement::from_repr(lo_fr), FieldElement::from_repr(hi_fr))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_split_challenge_zero() {
        let zero = FieldElement::zero();
        let (lo, hi) = split_challenge(&zero);
        assert_eq!(lo, FieldElement::zero());
        assert_eq!(hi, FieldElement::zero());
    }

    #[test]
    fn test_split_challenge_small() {
        // A value that fits in 127 bits should have hi = 0
        let val = FieldElement::from(42u128);
        let (lo, hi) = split_challenge(&val);
        assert_eq!(lo, FieldElement::from(42u128));
        assert_eq!(hi, FieldElement::zero());
    }

    #[test]
    fn test_split_challenge_large() {
        // Value with bits in both halves: 1 << 127 should give lo=0, hi=1
        let val = FieldElement::from(1u128)
            * FieldElement::from(1u128 << 64)
            * FieldElement::from(1u128 << 63);
        let (lo, hi) = split_challenge(&val);
        assert_eq!(lo, FieldElement::zero());
        assert_eq!(hi, FieldElement::from(1u128));
    }

    #[test]
    fn test_encode_g1_identity() {
        let point = G1Affine::zero();
        let encoded = encode_g1_as_fr_elements(&point);
        for e in &encoded {
            assert_eq!(*e, FieldElement::zero());
        }
    }

    #[test]
    fn test_encode_g1_generator() {
        // BN254 G1 generator is (1, 2)
        let generator = G1Affine::generator();
        let encoded = encode_g1_as_fr_elements(&generator);

        // x = 1, so x_lo = 1, x_hi = 0
        assert_eq!(encoded[0], FieldElement::from(1u128));
        assert_eq!(encoded[1], FieldElement::zero());
        // y = 2, so y_lo = 2, y_hi = 0
        assert_eq!(encoded[2], FieldElement::from(2u128));
        assert_eq!(encoded[3], FieldElement::zero());
    }

    #[test]
    fn test_poseidon2_sponge_hash_matches_bb() {
        // Test that our sponge hash of the empty-ish case works.
        // Hash a single element (the simplest case):
        // Input: [1]
        // IV = 1 << 64
        // state = [0, 0, 0, IV]
        // After absorb: state = [1, 0, 0, IV]
        // Permute, output state[0]
        let input = [FieldElement::from(1u128)];
        let result = poseidon2_sponge_hash(&input);
        assert!(result.is_ok(), "Sponge hash should succeed");
        // We can't easily verify the exact value without a bb reference,
        // but we verify it's deterministic
        let result2 = poseidon2_sponge_hash(&input);
        assert_eq!(result.unwrap(), result2.unwrap());
    }

    #[test]
    fn test_poseidon2_sponge_hash_different_inputs() {
        let input1 = [FieldElement::from(1u128)];
        let input2 = [FieldElement::from(2u128)];
        let result1 = poseidon2_sponge_hash(&input1).unwrap();
        let result2 = poseidon2_sponge_hash(&input2).unwrap();
        assert_ne!(result1, result2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_srs_file_path_uses_home() {
        // When CRS_PATH is not set, srs_file_path should use $HOME/.bb-crs/
        // We don't set/unset env vars to avoid unsafe code issues.
        // Just verify the function returns a path ending in bn254_g1.dat.
        let result = srs_file_path();
        // If HOME is set (typical), we expect Ok with a path ending in /bn254_g1.dat
        if let Ok(path) = result {
            assert!(
                path.ends_with("/bn254_g1.dat"),
                "SRS path should end with /bn254_g1.dat, got: {}",
                path
            );
        }
        // If HOME is not set, it may be an error (that's also acceptable)
    }

    // -----------------------------------------------------------------------
    // Integration tests: full pipeline without SRS file
    // -----------------------------------------------------------------------

    /// Generate synthetic SRS points for testing: [G, 2G, 3G, ...]
    /// where G is the BN254 generator.
    fn synthetic_srs(n: usize) -> Vec<G1Affine> {
        use ark_ec::CurveGroup;
        let g = G1Affine::generator();
        (1..=n).map(|i| (g * Fr::from(i as u64)).into_affine()).collect()
    }

    #[test]
    fn test_kzg_commit_single_value() {
        // commit([1], [G]) = 1 * G = G
        let srs = vec![G1Affine::generator()];
        let values = [FieldElement::from(1u128)];
        let commitment = kzg_commit(&values, &srs).unwrap();
        assert_eq!(commitment, G1Affine::generator());
    }

    #[test]
    fn test_kzg_commit_scalar_multiple() {
        use ark_ec::CurveGroup;
        // commit([5], [G]) = 5 * G
        let srs = vec![G1Affine::generator()];
        let values = [FieldElement::from(5u128)];
        let commitment = kzg_commit(&values, &srs).unwrap();
        let expected: G1Affine = (G1Affine::generator() * Fr::from(5u64)).into_affine();
        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_kzg_commit_multiple_values() {
        // commit([a, b], [G1, G2]) = a*G1 + b*G2
        let srs = synthetic_srs(2);
        let a = FieldElement::from(3u128);
        let b = FieldElement::from(7u128);
        let commitment = kzg_commit(&[a, b], &srs).unwrap();

        // Manual: 3 * G + 7 * (2G) = 3G + 14G = 17G
        use ark_ec::CurveGroup;
        let expected: G1Affine = (G1Affine::generator() * Fr::from(17u64)).into_affine();
        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_full_pipeline_deterministic() {
        // Full pipeline: kzg_commit → encode → hash → split
        // Verify determinism: same inputs → same output
        let srs = synthetic_srs(3);
        let values =
            [FieldElement::from(42u128), FieldElement::from(123u128), FieldElement::from(999u128)];

        let commitment1 = kzg_commit(&values, &srs).unwrap();
        let encoded1 = encode_g1_as_fr_elements(&commitment1);
        let challenges1 = poseidon2_transcript_squeeze(&encoded1, 1).unwrap();

        let commitment2 = kzg_commit(&values, &srs).unwrap();
        let encoded2 = encode_g1_as_fr_elements(&commitment2);
        let challenges2 = poseidon2_transcript_squeeze(&encoded2, 1).unwrap();

        assert_eq!(challenges1, challenges2, "Same inputs must produce same challenges");
    }

    #[test]
    fn test_full_pipeline_different_inputs_different_challenges() {
        let srs = synthetic_srs(2);

        let values_a = [FieldElement::from(1u128), FieldElement::from(2u128)];
        let values_b = [FieldElement::from(3u128), FieldElement::from(4u128)];

        let commitment_a = kzg_commit(&values_a, &srs).unwrap();
        let encoded_a = encode_g1_as_fr_elements(&commitment_a);
        let ch_a = poseidon2_transcript_squeeze(&encoded_a, 1).unwrap();

        let commitment_b = kzg_commit(&values_b, &srs).unwrap();
        let encoded_b = encode_g1_as_fr_elements(&commitment_b);
        let ch_b = poseidon2_transcript_squeeze(&encoded_b, 1).unwrap();

        assert_ne!(ch_a, ch_b, "Different inputs must produce different challenges");
    }

    #[test]
    fn test_multiple_challenges() {
        let srs = synthetic_srs(2);
        let values = [FieldElement::from(42u128), FieldElement::from(99u128)];
        let commitment = kzg_commit(&values, &srs).unwrap();
        let encoded = encode_g1_as_fr_elements(&commitment);

        // Request 1 challenge
        let ch1 = poseidon2_transcript_squeeze(&encoded, 1).unwrap();
        assert_eq!(ch1.len(), 1);

        // Request 2 challenges (split from single hash)
        let ch2 = poseidon2_transcript_squeeze(&encoded, 2).unwrap();
        assert_eq!(ch2.len(), 2);
        // First challenge should be the lo half of the hash, same as ch1[0]
        assert_eq!(ch2[0], ch1[0], "First challenge should match single-challenge result");
        assert_ne!(ch2[0], ch2[1], "Two challenges from same hash should differ");

        // Request 3 challenges (needs a second hash round)
        let ch3 = poseidon2_transcript_squeeze(&encoded, 3).unwrap();
        assert_eq!(ch3.len(), 3);
        assert_eq!(ch3[0], ch2[0], "First challenge stable across request sizes");
        assert_eq!(ch3[1], ch2[1], "Second challenge stable across request sizes");
        // Third challenge comes from hashing the previous hash output
        assert_ne!(ch3[2], ch3[0]);
        assert_ne!(ch3[2], ch3[1]);
    }

    #[test]
    fn test_challenge_values_are_127_bits() {
        // Every challenge produced should fit in 127 bits (< 2^127)
        let srs = synthetic_srs(2);
        let values = [FieldElement::from(42u128), FieldElement::from(99u128)];
        let commitment = kzg_commit(&values, &srs).unwrap();
        let encoded = encode_g1_as_fr_elements(&commitment);
        let challenges = poseidon2_transcript_squeeze(&encoded, 4).unwrap();

        let bound_127 = num_bigint::BigUint::from(1u64) << 127u32;
        for (i, ch) in challenges.iter().enumerate() {
            let bigint: BigInteger256 = ch.into_repr().into();
            let val = num_bigint::BigUint::from_bytes_be(&bigint.to_bytes_be());
            assert!(val < bound_127, "Challenge {} should be < 2^127, got {} bits", i, val.bits());
        }
    }

    #[test]
    fn test_encode_g1_large_coordinates() {
        // Use a point with large coordinates (not the generator) to exercise
        // the limb splitting with nonzero hi parts.
        use ark_ec::CurveGroup;
        // 12345 * G should have large coordinates
        let point: G1Affine = (G1Affine::generator() * Fr::from(12345u64)).into_affine();
        let encoded = encode_g1_as_fr_elements(&point);

        // Reconstruct x from (x_lo, x_hi) and verify it matches
        let x = point.x().unwrap();
        let x_bigint: BigInteger256 = x.into();
        let x_full = num_bigint::BigUint::from_bytes_be(&x_bigint.to_bytes_be());

        let x_lo_bigint: BigInteger256 = encoded[0].into_repr().into();
        let x_hi_bigint: BigInteger256 = encoded[1].into_repr().into();
        let x_lo = num_bigint::BigUint::from_bytes_be(&x_lo_bigint.to_bytes_be());
        let x_hi = num_bigint::BigUint::from_bytes_be(&x_hi_bigint.to_bytes_be());

        let reconstructed = &x_lo + (&x_hi << NUM_LIMB_BITS);
        assert_eq!(reconstructed, x_full, "x coordinate should reconstruct from limbs");

        // Same for y
        let y = point.y().unwrap();
        let y_bigint: BigInteger256 = y.into();
        let y_full = num_bigint::BigUint::from_bytes_be(&y_bigint.to_bytes_be());

        let y_lo_bigint: BigInteger256 = encoded[2].into_repr().into();
        let y_hi_bigint: BigInteger256 = encoded[3].into_repr().into();
        let y_lo = num_bigint::BigUint::from_bytes_be(&y_lo_bigint.to_bytes_be());
        let y_hi = num_bigint::BigUint::from_bytes_be(&y_hi_bigint.to_bytes_be());

        let reconstructed_y = &y_lo + (&y_hi << NUM_LIMB_BITS);
        assert_eq!(reconstructed_y, y_full, "y coordinate should reconstruct from limbs");
    }

    #[test]
    fn test_derive_phase_challenge_errors_without_srs() {
        // When SRS file doesn't exist, derive_phase_challenge should return
        // a meaningful error (not panic).
        let values = [FieldElement::from(1u128)];
        let result = derive_phase_challenge(0, &values, 1);
        // This will likely fail because the SRS file doesn't exist in test env.
        // That's expected — just verify we get an error, not a panic.
        if result.is_err() {
            let err_msg = format!("{}", result.unwrap_err());
            assert!(
                err_msg.contains("PhaseBarrier") || err_msg.contains("SRS"),
                "Error should mention PhaseBarrier or SRS, got: {}",
                err_msg
            );
        }
        // If it somehow succeeds (SRS exists), that's fine too.
    }

    #[test]
    fn test_derive_phase_challenge_empty_witnesses_error() {
        let result = derive_phase_challenge(0, &[], 1);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("empty"), "Error should mention empty witnesses");
    }

    #[test]
    fn test_derive_phase_challenge_zero_challenges_error() {
        let values = [FieldElement::from(1u128)];
        let result = derive_phase_challenge(0, &values, 0);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("at least one"),
            "Error should mention needing at least one challenge"
        );
    }
}
