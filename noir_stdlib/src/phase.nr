/// Mark a phase boundary and derive a Fiat-Shamir challenge.
///
/// The prover commits to all values in `witnesses` using the proving
/// backend's native polynomial commitment scheme, then derives a
/// challenge from the commitment via the backend's Fiat-Shamir
/// transcript.
///
/// The challenge is binding: any change to `witnesses` produces a
/// different challenge. The verifier independently recomputes the
/// same challenge from the proof's commitments.
///
/// # When to use this vs in-circuit hashing
///
/// Use `challenge()` when you need a random evaluation point for
/// polynomial identity testing (Schwartz-Zippel) or similar
/// protocols where the challenge must be derived from committed data.
///
/// Use in-circuit hashing (e.g., Poseidon2) when you need a
/// deterministic commitment that is visible as a public output for
/// cross-circuit linking, or when you need the commitment value to
/// be independent of the proving backend.
///
/// # Example
///
/// ```noir
/// use std::phase::challenge;
///
/// fn main(poly_coeffs: [Field; 1024], expected: Field) {
///     let gamma = challenge(poly_coeffs);
///     let eval = horner_evaluate(poly_coeffs, gamma);
///     assert(eval == expected);
/// }
/// ```
#[builtin(phase_challenge)]
pub fn challenge<let N: u32>(witnesses: [Field; N]) -> Field {}

/// Derive multiple independent challenges from a single commitment
/// round.
///
/// This is useful when a protocol needs several challenge values
/// derived from the same committed data (e.g., one per CRT modulus
/// in the Enclave PVSS scheme).
#[builtin(phase_challenge_multi)]
pub fn challenge_multi<let N: u32, let M: u32>(witnesses: [Field; N]) -> [Field; M] {}
