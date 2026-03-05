//! Multi-phase circuit challenge derivation for BN254.
//!
//! Implements the `derive_phase_challenge` method using a **standalone sponge**
//! protocol that both the Rust ACVM executor and barretenberg's C++ prover/verifier
//! can compute identically:
//!
//! 1. KZG commitment: MSM of witness values against BN254 SRS monomial points
//! 2. Commitment encoding: G1 affine -> 4 Fr elements (bb's limb encoding)
//! 3. Standalone Poseidon2 sponge hash of `[phase_id, x_lo, x_hi, y_lo, y_hi]`
//! 4. Challenge splitting: 254-bit hash -> pairs of 127-bit challenges
//!
//! ## Why a standalone sponge (not the transcript)?
//!
//! Barretenberg's Oink transcript accumulates VK hash + public inputs before
//! phase barriers. The Rust side (nargo execute) doesn't have the VK hash at
//! execution time (it's only computed by bb after proving key generation).
//!
//! To ensure both sides derive identical challenges, phase barrier challenges
//! are derived via a standalone Poseidon2 sponge hash that depends only on:
//! - The `phase_id` (domain separation for multiple barriers)
//! - The KZG commitment to the witness values
//!
//! The bb prover/verifier still absorb the commitment into the main transcript
//! (for binding/ordering), but derive the challenge via this same standalone hash.

use acir::AcirField;
use acvm_blackbox_solver::BlackBoxResolutionError;
use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{BigInteger, BigInteger256, PrimeField};

use std::io::{Read, Seek, SeekFrom};
use std::sync::OnceLock;

use crate::FieldElement;
use crate::poseidon2::poseidon2_permutation;

/// Number of limb bits used by barretenberg's bigfield simulation for encoding
/// base field (Fq) elements as pairs of scalar field (Fr) elements.
const NUM_LIMB_BITS: u32 = 136;

/// Maximum number of SRS points to cache. Points beyond this are loaded on demand.
/// 2^16 = 65536 points * 64 bytes = 4MB — reasonable for most circuits.
const SRS_CACHE_MAX_POINTS: usize = 1 << 16;

/// Global SRS cache. Loaded once on first successful use and reused across all calls.
/// Stores `Result` so that initialization errors are preserved and callers get the
/// real error message (not a misleading "SRS has 0 points" sentinel).
static SRS_CACHE: OnceLock<Result<SrsCache, String>> = OnceLock::new();

/// Cached SRS data: pre-parsed G1 affine points and the file path for overflow.
struct SrsCache {
    /// Pre-parsed points (up to SRS_CACHE_MAX_POINTS).
    points: Vec<G1Affine>,
    /// Path to the SRS file, for loading additional points beyond the cache.
    file_path: String,
    /// Total number of points available in the SRS file.
    total_points: usize,
}

/// Error helper that uses a descriptive string (no misleading BlackBoxFunc variant).
fn phase_err(msg: String) -> BlackBoxResolutionError {
    // We reuse Poseidon2Permutation as the closest existing discriminant.
    // The error message itself clearly identifies this as a PhaseBarrier error.
    BlackBoxResolutionError::Failed(acir::BlackBoxFunc::Poseidon2Permutation, msg)
}

/// Derive Fiat-Shamir challenge(s) by committing to witness values using KZG
/// and hashing the commitment via a standalone Poseidon2 sponge.
///
/// Protocol:
/// 1. `C = KZG_commit(witness_values)` using the BN254 SRS
/// 2. Encode `C` as `[x_lo, x_hi, y_lo, y_hi]` (bb's limb encoding)
/// 3. `hash = Poseidon2_sponge_hash([phase_id, x_lo, x_hi, y_lo, y_hi])`
/// 4. Split hash into 127-bit challenge pair `(lo, hi)`
/// 5. For >2 challenges, chain: `hash_n = Poseidon2_sponge_hash([hash_{n-1}])`
///
/// Both the Rust ACVM executor and bb's C++ prover/verifier compute this
/// identical standalone hash, ensuring challenge agreement without requiring
/// VK hash or public input context.
pub(crate) fn derive_phase_challenge(
    phase_id: u32,
    witness_values: &[FieldElement],
    num_challenges: usize,
) -> Result<Vec<FieldElement>, BlackBoxResolutionError> {
    if witness_values.is_empty() {
        return Err(phase_err(
            "PhaseBarrier: cannot derive challenge from empty witness list".into(),
        ));
    }
    if num_challenges == 0 {
        return Err(phase_err("PhaseBarrier: must request at least one challenge".into()));
    }

    // Step 1: Load SRS points and compute KZG commitment
    let srs_points = load_srs_cached(witness_values.len())?;
    let commitment = kzg_commit(witness_values, &srs_points)?;

    // Step 2: Encode the commitment as field elements (bb's limb encoding)
    let commitment_frs = encode_g1_as_fr_elements(&commitment);

    // Step 3: Build standalone sponge input: [phase_id, x_lo, x_hi, y_lo, y_hi]
    let phase_id_fr = FieldElement::from(phase_id as u128);
    let sponge_input =
        [phase_id_fr, commitment_frs[0], commitment_frs[1], commitment_frs[2], commitment_frs[3]];

    // Step 4-5: Hash via Poseidon2 sponge and extract challenges
    let challenges = poseidon2_squeeze_challenges(&sponge_input, num_challenges)?;

    Ok(challenges)
}

// ---------------------------------------------------------------------------
// SRS Loading (with caching and partial reads)
// ---------------------------------------------------------------------------

/// Initialize the global SRS cache from disk. Called once via OnceLock.
fn init_srs_cache() -> Result<SrsCache, BlackBoxResolutionError> {
    let file_path = srs_file_path()?;

    let file = std::fs::File::open(&file_path).map_err(|e| {
        phase_err(format!("PhaseBarrier: failed to open BN254 SRS file at '{}': {}", file_path, e))
    })?;

    let file_len = file
        .metadata()
        .map_err(|e| phase_err(format!("PhaseBarrier: failed to read SRS file metadata: {}", e)))?
        .len() as usize;

    let total_points = file_len / 64;
    let cache_count = total_points.min(SRS_CACHE_MAX_POINTS);

    // Read only the bytes we need for the cache
    let bytes_needed = cache_count * 64;
    let mut buf = vec![0u8; bytes_needed];
    let mut reader = std::io::BufReader::new(file);
    reader.read_exact(&mut buf).map_err(|e| {
        phase_err(format!("PhaseBarrier: failed to read {} bytes from SRS: {}", bytes_needed, e))
    })?;

    let points = parse_srs_points(&buf, cache_count)?;

    Ok(SrsCache { points, file_path, total_points })
}

/// Load SRS points, using the global cache for the first SRS_CACHE_MAX_POINTS
/// and reading additional points from disk on demand.
fn load_srs_cached(num_points: usize) -> Result<Vec<G1Affine>, BlackBoxResolutionError> {
    let cache_result = SRS_CACHE.get_or_init(|| init_srs_cache().map_err(|e| format!("{}", e)));

    let cache = cache_result
        .as_ref()
        .map_err(|e| phase_err(format!("PhaseBarrier: SRS initialization failed: {}", e)))?;

    if num_points > cache.total_points {
        return Err(phase_err(format!(
            "PhaseBarrier: SRS has {} points but {} are needed",
            cache.total_points, num_points
        )));
    }

    if num_points <= cache.points.len() {
        // Fast path: all points are in cache
        Ok(cache.points[..num_points].to_vec())
    } else {
        // Slow path: need more points than the cache holds
        let mut points = cache.points.clone();
        let additional = num_points - points.len();
        let offset = points.len() * 64;
        let bytes_needed = additional * 64;

        let mut file = std::fs::File::open(&cache.file_path)
            .map_err(|e| phase_err(format!("PhaseBarrier: failed to reopen SRS file: {}", e)))?;
        file.seek(SeekFrom::Start(offset as u64))
            .map_err(|e| phase_err(format!("PhaseBarrier: failed to seek in SRS file: {}", e)))?;
        let mut buf = vec![0u8; bytes_needed];
        file.read_exact(&mut buf).map_err(|e| {
            phase_err(format!("PhaseBarrier: failed to read additional SRS points: {}", e))
        })?;

        let extra_points = parse_srs_points(&buf, additional)?;
        points.extend(extra_points);
        Ok(points)
    }
}

/// Parse raw SRS bytes into G1Affine points.
///
/// Points are stored as 64-byte uncompressed affine coordinates (x, y),
/// each coordinate a 32-byte big-endian field element.
///
/// Validates that coordinates are in range (< Fq modulus) and that the
/// resulting point is on the BN254 curve. Returns an error for corrupt data.
fn parse_srs_points(
    data: &[u8],
    num_points: usize,
) -> Result<Vec<G1Affine>, BlackBoxResolutionError> {
    let mut points = Vec::with_capacity(num_points);
    for i in 0..num_points {
        let offset = i * 64;
        let x_bytes = &data[offset..offset + 32];
        let y_bytes = &data[offset + 32..offset + 64];

        // Check for point at infinity (all 0xFF)
        if x_bytes.iter().all(|&b| b == 0xFF) && y_bytes.iter().all(|&b| b == 0xFF) {
            points.push(G1Affine::zero());
            continue;
        }

        // Parse coordinates with range validation: Fq::from_be_bytes_mod_order silently
        // reduces values >= Fq modulus, which would accept corrupt data. Instead, parse
        // as a BigInteger and check that it's within range before constructing the field element.
        let x_bigint = BigInteger256::new({
            let mut limbs = [0u64; 4];
            for (j, limb) in limbs.iter_mut().enumerate() {
                let start = 24 - j * 8;
                *limb = u64::from_be_bytes(x_bytes[start..start + 8].try_into().unwrap());
            }
            limbs
        });
        let y_bigint = BigInteger256::new({
            let mut limbs = [0u64; 4];
            for (j, limb) in limbs.iter_mut().enumerate() {
                let start = 24 - j * 8;
                *limb = u64::from_be_bytes(y_bytes[start..start + 8].try_into().unwrap());
            }
            limbs
        });

        let x = Fq::from_bigint(x_bigint).ok_or_else(|| {
            phase_err(format!("SRS point {}: x coordinate out of range (>= Fq modulus)", i))
        })?;
        let y = Fq::from_bigint(y_bigint).ok_or_else(|| {
            phase_err(format!("SRS point {}: y coordinate out of range (>= Fq modulus)", i))
        })?;

        // Use new() which validates the point is on the curve (not new_unchecked)
        let point = G1Affine::new(x, y);
        if !point.is_on_curve() {
            return Err(phase_err(format!("SRS point {} is not on the BN254 curve", i)));
        }
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
        return Err(phase_err(
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

    let result = <ark_bn254::G1Projective as VariableBaseMSM>::msm(srs_points, &scalars)
        .map_err(|e| phase_err(format!("PhaseBarrier: KZG commitment MSM failed: {}", e)))?;

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

    let full = num_bigint::BigUint::from_bytes_be(&bytes_be);
    let lo_mask = (num_bigint::BigUint::from(1u64) << NUM_LIMB_BITS) - 1u64;
    let lo = &full & &lo_mask;
    let hi = &full >> NUM_LIMB_BITS;

    let lo_fr = Fr::from_be_bytes_mod_order(&lo.to_bytes_be());
    let hi_fr = Fr::from_be_bytes_mod_order(&hi.to_bytes_be());

    (FieldElement::from_repr(lo_fr), FieldElement::from_repr(hi_fr))
}

// ---------------------------------------------------------------------------
// Poseidon2 Standalone Sponge (NOT the transcript — independent hash)
// ---------------------------------------------------------------------------

/// Derive challenges from a standalone Poseidon2 sponge hash.
///
/// This is NOT the transcript protocol — it's a simple hash-and-split:
/// 1. `hash_0 = Poseidon2_sponge_hash(data)` -> split into (lo_0, hi_0)
/// 2. `hash_1 = Poseidon2_sponge_hash([hash_0])` -> split into (lo_1, hi_1)
/// 3. Continue chaining for additional challenges.
///
/// Both the Rust ACVM executor and bb's C++ prover/verifier use this same
/// standalone hash (not the transcript) for phase barrier challenges.
fn poseidon2_squeeze_challenges(
    data: &[FieldElement],
    num_challenges: usize,
) -> Result<Vec<FieldElement>, BlackBoxResolutionError> {
    let hash_output = poseidon2_sponge_hash(data)?;

    let mut challenges = Vec::with_capacity(num_challenges);
    let (lo, hi) = split_challenge(&hash_output);
    challenges.push(lo);
    if num_challenges > 1 {
        challenges.push(hi);
    }

    // For additional challenges beyond the first pair, chain hash outputs
    let mut prev_hash = hash_output;
    while challenges.len() < num_challenges {
        let next_hash = poseidon2_sponge_hash(&[prev_hash])?;
        let (lo, hi) = split_challenge(&next_hash);
        challenges.push(lo);
        if challenges.len() < num_challenges {
            challenges.push(hi);
        }
        prev_hash = next_hash;
    }

    challenges.truncate(num_challenges);
    Ok(challenges)
}

/// Poseidon2 sponge hash matching barretenberg's `FieldSponge::hash_internal()`.
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
    fn test_poseidon2_sponge_hash_deterministic() {
        let input = [FieldElement::from(1u128)];
        let result1 = poseidon2_sponge_hash(&input).unwrap();
        let result2 = poseidon2_sponge_hash(&input).unwrap();
        assert_eq!(result1, result2, "Sponge hash must be deterministic");
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
    fn test_phase_id_affects_challenge() {
        // Same commitment data but different phase_id should produce different challenges.
        // We test the sponge input directly since KZG is deterministic.
        let comm_frs = [
            FieldElement::from(1u128),
            FieldElement::zero(),
            FieldElement::from(2u128),
            FieldElement::zero(),
        ];

        let input_phase0 =
            [FieldElement::from(0u128), comm_frs[0], comm_frs[1], comm_frs[2], comm_frs[3]];
        let input_phase1 =
            [FieldElement::from(1u128), comm_frs[0], comm_frs[1], comm_frs[2], comm_frs[3]];

        let hash0 = poseidon2_sponge_hash(&input_phase0).unwrap();
        let hash1 = poseidon2_sponge_hash(&input_phase1).unwrap();
        assert_ne!(hash0, hash1, "Different phase_ids must produce different challenges");
    }

    #[test]
    fn test_srs_file_path_uses_home() {
        let result = srs_file_path();
        if let Ok(path) = result {
            assert!(
                path.ends_with("/bn254_g1.dat"),
                "SRS path should end with /bn254_g1.dat, got: {}",
                path
            );
        }
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
        let srs = vec![G1Affine::generator()];
        let values = [FieldElement::from(1u128)];
        let commitment = kzg_commit(&values, &srs).unwrap();
        assert_eq!(commitment, G1Affine::generator());
    }

    #[test]
    fn test_kzg_commit_scalar_multiple() {
        use ark_ec::CurveGroup;
        let srs = vec![G1Affine::generator()];
        let values = [FieldElement::from(5u128)];
        let commitment = kzg_commit(&values, &srs).unwrap();
        let expected: G1Affine = (G1Affine::generator() * Fr::from(5u64)).into_affine();
        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_kzg_commit_multiple_values() {
        use ark_ec::CurveGroup;
        let srs = synthetic_srs(2);
        let a = FieldElement::from(3u128);
        let b = FieldElement::from(7u128);
        let commitment = kzg_commit(&[a, b], &srs).unwrap();
        // 3 * G + 7 * 2G = 3G + 14G = 17G
        let expected: G1Affine = (G1Affine::generator() * Fr::from(17u64)).into_affine();
        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_full_pipeline_deterministic() {
        let srs = synthetic_srs(3);
        let values =
            [FieldElement::from(42u128), FieldElement::from(123u128), FieldElement::from(999u128)];

        let commitment = kzg_commit(&values, &srs).unwrap();
        let encoded = encode_g1_as_fr_elements(&commitment);
        let phase_id_fr = FieldElement::from(0u128);
        let sponge_input = [phase_id_fr, encoded[0], encoded[1], encoded[2], encoded[3]];
        let ch1 = poseidon2_squeeze_challenges(&sponge_input, 1).unwrap();

        let commitment2 = kzg_commit(&values, &srs).unwrap();
        let encoded2 = encode_g1_as_fr_elements(&commitment2);
        let sponge_input2 = [phase_id_fr, encoded2[0], encoded2[1], encoded2[2], encoded2[3]];
        let ch2 = poseidon2_squeeze_challenges(&sponge_input2, 1).unwrap();

        assert_eq!(ch1, ch2, "Same inputs must produce same challenges");
    }

    #[test]
    fn test_full_pipeline_different_inputs_different_challenges() {
        let srs = synthetic_srs(2);
        let phase_id_fr = FieldElement::from(0u128);

        let values_a = [FieldElement::from(1u128), FieldElement::from(2u128)];
        let commitment_a = kzg_commit(&values_a, &srs).unwrap();
        let enc_a = encode_g1_as_fr_elements(&commitment_a);
        let input_a = [phase_id_fr, enc_a[0], enc_a[1], enc_a[2], enc_a[3]];
        let ch_a = poseidon2_squeeze_challenges(&input_a, 1).unwrap();

        let values_b = [FieldElement::from(3u128), FieldElement::from(4u128)];
        let commitment_b = kzg_commit(&values_b, &srs).unwrap();
        let enc_b = encode_g1_as_fr_elements(&commitment_b);
        let input_b = [phase_id_fr, enc_b[0], enc_b[1], enc_b[2], enc_b[3]];
        let ch_b = poseidon2_squeeze_challenges(&input_b, 1).unwrap();

        assert_ne!(ch_a, ch_b, "Different inputs must produce different challenges");
    }

    #[test]
    fn test_multiple_challenges() {
        let srs = synthetic_srs(2);
        let values = [FieldElement::from(42u128), FieldElement::from(99u128)];
        let commitment = kzg_commit(&values, &srs).unwrap();
        let encoded = encode_g1_as_fr_elements(&commitment);
        let phase_id_fr = FieldElement::from(0u128);
        let sponge_input = [phase_id_fr, encoded[0], encoded[1], encoded[2], encoded[3]];

        // Request 1 challenge
        let ch1 = poseidon2_squeeze_challenges(&sponge_input, 1).unwrap();
        assert_eq!(ch1.len(), 1);

        // Request 2 challenges (split from single hash)
        let ch2 = poseidon2_squeeze_challenges(&sponge_input, 2).unwrap();
        assert_eq!(ch2.len(), 2);
        assert_eq!(ch2[0], ch1[0], "First challenge should match single-challenge result");
        assert_ne!(ch2[0], ch2[1], "Two challenges from same hash should differ");

        // Request 3 challenges (needs a second hash round)
        let ch3 = poseidon2_squeeze_challenges(&sponge_input, 3).unwrap();
        assert_eq!(ch3.len(), 3);
        assert_eq!(ch3[0], ch2[0], "First challenge stable across request sizes");
        assert_eq!(ch3[1], ch2[1], "Second challenge stable across request sizes");
        assert_ne!(ch3[2], ch3[0]);
        assert_ne!(ch3[2], ch3[1]);
    }

    #[test]
    fn test_challenge_values_are_127_bits() {
        let srs = synthetic_srs(2);
        let values = [FieldElement::from(42u128), FieldElement::from(99u128)];
        let commitment = kzg_commit(&values, &srs).unwrap();
        let encoded = encode_g1_as_fr_elements(&commitment);
        let phase_id_fr = FieldElement::from(0u128);
        let sponge_input = [phase_id_fr, encoded[0], encoded[1], encoded[2], encoded[3]];
        let challenges = poseidon2_squeeze_challenges(&sponge_input, 4).unwrap();

        let bound_127 = num_bigint::BigUint::from(1u64) << 127u32;
        for (i, ch) in challenges.iter().enumerate() {
            let bigint: BigInteger256 = ch.into_repr().into();
            let val = num_bigint::BigUint::from_bytes_be(&bigint.to_bytes_be());
            assert!(val < bound_127, "Challenge {} should be < 2^127, got {} bits", i, val.bits());
        }
    }

    #[test]
    fn test_encode_g1_large_coordinates() {
        use ark_ec::CurveGroup;
        let point: G1Affine = (G1Affine::generator() * Fr::from(12345u64)).into_affine();
        let encoded = encode_g1_as_fr_elements(&point);

        // Reconstruct x from (x_lo, x_hi) and verify
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
        if result.is_err() {
            let err_msg = format!("{}", result.unwrap_err());
            assert!(
                err_msg.contains("PhaseBarrier") || err_msg.contains("SRS"),
                "Error should mention PhaseBarrier or SRS, got: {}",
                err_msg
            );
        }
        // If it succeeds (SRS exists in this env), that's fine too.
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

    #[test]
    fn test_different_phase_ids_different_challenges() {
        // Using synthetic SRS to test full pipeline with phase_id variation
        let srs = synthetic_srs(2);
        let values = [FieldElement::from(42u128), FieldElement::from(99u128)];
        let commitment = kzg_commit(&values, &srs).unwrap();
        let encoded = encode_g1_as_fr_elements(&commitment);

        let input_0 = [FieldElement::from(0u128), encoded[0], encoded[1], encoded[2], encoded[3]];
        let input_1 = [FieldElement::from(1u128), encoded[0], encoded[1], encoded[2], encoded[3]];

        let ch_0 = poseidon2_squeeze_challenges(&input_0, 1).unwrap();
        let ch_1 = poseidon2_squeeze_challenges(&input_1, 1).unwrap();

        assert_ne!(ch_0, ch_1, "Different phase_ids must produce different challenges");
    }
}
