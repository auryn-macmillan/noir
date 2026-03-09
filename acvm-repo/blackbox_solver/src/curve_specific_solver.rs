use acir::BlackBoxFunc;

use crate::BlackBoxResolutionError;

/// This component will generate outputs for Blackbox function calls where the underlying [`acir::BlackBoxFunc`]
/// doesn't have a canonical Rust implementation.
///
/// Returns an [`BlackBoxResolutionError`] if the backend does not support the given [`acir::BlackBoxFunc`].
pub trait BlackBoxFunctionSolver<F> {
    fn multi_scalar_mul(
        &self,
        points: &[F],
        scalars_lo: &[F],
        scalars_hi: &[F],
        predicate: bool,
    ) -> Result<(F, F, F), BlackBoxResolutionError>;

    #[allow(clippy::too_many_arguments)]
    fn ec_add(
        &self,
        input1_x: &F,
        input1_y: &F,
        input1_infinite: &F,
        input2_x: &F,
        input2_y: &F,
        input2_infinite: &F,
        predicate: bool,
    ) -> Result<(F, F, F), BlackBoxResolutionError>;

    fn poseidon2_permutation(&self, inputs: &[F]) -> Result<Vec<F>, BlackBoxResolutionError>;

    /// Commit to witness values and derive Fiat-Shamir challenge(s).
    ///
    /// The backend should:
    /// 1. Interpret `witness_values` as data to be committed
    /// 2. Commit using its native polynomial commitment scheme
    /// 3. Derive `num_challenges` challenge values from that commitment
    ///    according to the backend's phase-challenge protocol
    ///
    /// The challenge derivation must be deterministic: given the same
    /// `witness_values`, the same challenges are always produced. The
    /// verifier checks constraints that depend on these challenges in
    /// the same proof that binds the commitments.
    ///
    /// `phase_id` identifies which phase transition this is, allowing
    /// the backend to maintain ordered transcript state across multiple
    /// barriers in a single circuit.
    ///
    /// The default implementation returns an error for backends that
    /// do not support multi-phase proving.
    fn derive_phase_challenge(
        &self,
        _phase_id: u32,
        _witness_values: &[F],
        _num_challenges: usize,
    ) -> Result<Vec<F>, BlackBoxResolutionError> {
        Err(BlackBoxResolutionError::Failed(
            BlackBoxFunc::Poseidon2Permutation,
            "Backend does not support multi-phase challenge derivation".into(),
        ))
    }
}
pub struct StubbedBlackBoxSolver;

impl StubbedBlackBoxSolver {
    fn fail(black_box_function: BlackBoxFunc) -> BlackBoxResolutionError {
        BlackBoxResolutionError::Failed(
            black_box_function,
            format!("{} is not supported", black_box_function.name()),
        )
    }
}

impl<F> BlackBoxFunctionSolver<F> for StubbedBlackBoxSolver {
    fn multi_scalar_mul(
        &self,
        _points: &[F],
        _scalars_lo: &[F],
        _scalars_hi: &[F],
        _predicate: bool,
    ) -> Result<(F, F, F), BlackBoxResolutionError> {
        Err(Self::fail(BlackBoxFunc::MultiScalarMul))
    }
    fn ec_add(
        &self,
        _input1_x: &F,
        _input1_y: &F,
        _input1_infinite: &F,
        _input2_x: &F,
        _input2_y: &F,
        _input2_infinite: &F,
        _predicate: bool,
    ) -> Result<(F, F, F), BlackBoxResolutionError> {
        Err(Self::fail(BlackBoxFunc::EmbeddedCurveAdd))
    }
    fn poseidon2_permutation(&self, _inputs: &[F]) -> Result<Vec<F>, BlackBoxResolutionError> {
        Err(Self::fail(BlackBoxFunc::Poseidon2Permutation))
    }
}
