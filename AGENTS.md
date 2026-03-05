# Multi-Phase Circuit Support for Noir/ACVM

## 1. Problem Statement

The Enclave PVSS circuits ([enclave/circuits](https://github.com/gnosisguild/enclave/tree/main/circuits/bin), [pvss docs](https://github.com/gnosisguild/pvss)) spend **50–70% of their constraint budget** on in-circuit Fiat-Shamir hashing. The [SAFE sponge implementation](https://github.com/gnosisguild/enclave/blob/main/circuits/lib/src/math/safe.nr) uses a Poseidon2-based construction with Keccak-256 tags, incurring:

- ~150K constraints per sponge instance (Keccak tag computation alone)
- ~300 constraints per Poseidon2 permutation (data absorption/squeeze)
- 3+ sponge instances per circuit (commitments + Fiat-Shamir challenge derivation)

The `verify_shares` circuits hit **11M gates** each; the `share_encryption` circuits hit **3.6M gates** each. In all cases, a majority of the gate count goes to:

1. **Polynomial commitments** — hashing packed polynomial coefficients to produce a single binding field element per polynomial.
2. **Fiat-Shamir challenge derivation** — absorbing transcript data (commitments, ciphertexts, public keys) and squeezing challenge values for Schwartz-Zippel polynomial identity testing.

This work is redundant: the proving backend (barretenberg) already commits to all witness polynomials via KZG and derives Fiat-Shamir challenges via its own Poseidon2 transcript during the Oink proving rounds. Exposing those backend-derived challenges to the circuit would eliminate the in-circuit hashing.

### Current Cost Breakdown (share_encryption circuit)

| Component | Approx. Constraints |
|---|---|
| PK commitment (SAFE sponge) | ~200K |
| Message commitment (SAFE sponge) | ~175K |
| Fiat-Shamir challenge (SAFE sponge) | ~300K |
| Polynomial evaluations (Horner + Schwartz-Zippel) | ~50K |
| Batch verification | ~5K |
| **Total** | **~730K** |

With multi-phase support, the three sponge instances (~675K) are eliminated. Only the polynomial evaluations and batch checks remain (~55K). This is a **~92% reduction** in the Fiat-Shamir portion of the circuit.

## 2. Design Overview

### Core Idea

Introduce a **phase barrier** that splits a single ACIR circuit into multiple execution phases. The ACVM executes Phase 1 (laying out polynomial witnesses), pauses at the barrier, and reports the partial witness to the backend. The backend commits to the Phase 1 wire polynomials and derives a challenge via its Fiat-Shamir transcript. The challenge value is injected back into the ACVM as a new witness, and Phase 2 execution resumes using it for polynomial evaluations and identity checks.

This follows the **pause-commit-resume** pattern, directly mirroring how barretenberg's Oink prover already handles logUp inverse polynomials internally:
- Phase 1: commit to wire polynomials (w_l, w_r, w_o)
- Derive challenges: η, β, γ
- Phase 2: compute challenge-dependent witnesses (w_4 memory records, lookup inverses, grand product)

### Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        Noir Source                              │
│   let (phase1_wits) = compute_polynomials(...);                │
│   let challenge: Field = std::phase::challenge(phase1_wits);   │
│   let eval = polynomial.evaluate(challenge);                   │
│   assert(eval == expected);                                    │
└──────────────────────────┬─────────────────────────────────────┘
                           │ Compilation
                           ▼
┌────────────────────────────────────────────────────────────────┐
│                     ACIR Program                                │
│   Phase 1 opcodes: [AssertZero, ..., MemoryOp, ...]           │
│   ─── PhaseBarrier { commit: [w3..w99], out: w100 } ──────    │
│   Phase 2 opcodes: [AssertZero(w100 * ...), ...]               │
└──────────────────────────┬─────────────────────────────────────┘
                           │ Execution
                           ▼
┌─────────────────┐    ┌─────────────┐    ┌──────────────────┐
│   ACVM Phase 1  │───▶│   Backend   │───▶│   ACVM Phase 2   │
│ Solve opcodes   │    │ Commit to   │    │ Inject challenge  │
│ up to barrier   │    │ witnesses,  │    │ as w100, continue │
│ Return partial  │    │ derive      │    │ solving            │
│ witness map     │    │ challenge   │    │                    │
└─────────────────┘    └─────────────┘    └──────────────────┘
```

### Design Principles

1. **No proving backend changes required.** Barretenberg already performs multi-round commitment and challenge derivation (Oink rounds). This plan exposes that existing capability through the ACVM to Noir.
2. **Full flexibility.** Circuit authors choose per-use whether to use backend challenges or in-circuit hashing. The two approaches coexist.
3. **Backend-agnostic at the ACIR level.** The `PhaseBarrier` opcode is generic — any backend that implements `derive_phase_challenge` can support it.
4. **Follows existing ACVM patterns.** The pause-resume model mirrors `RequiresForeignCall` and `RequiresAcirCall`.

## 3. Detailed Changes by Layer

### 3.1 ACIR Layer — Circuit Representation

#### New Opcode: `PhaseBarrier`

**File: `acvm-repo/acir/src/circuit/opcodes.rs`** (extends the `Opcode<F>` enum at line 52)

```rust
/// Marks a phase boundary in a multi-phase circuit.
///
/// When the ACVM reaches this opcode, it must:
/// 1. Pause execution
/// 2. Report the committed witness values to the backend
/// 3. Receive challenge value(s) derived from the backend's
///    Fiat-Shamir transcript
/// 4. Write the challenges to `challenge_outputs`
/// 5. Resume execution
///
/// All `commit_witnesses` must be resolved (assigned values) before
/// this opcode is reached. The `challenge_outputs` witnesses must NOT
/// be assigned — they are written by the resolution step.
PhaseBarrier {
    /// Identifier for this phase transition. Supports multiple barriers
    /// per circuit (e.g., for 3+ phase protocols). Must be sequential
    /// starting from 0.
    phase_id: u32,

    /// Witnesses whose values the backend should commit to before
    /// deriving the challenge. These define the "transcript" for this
    /// phase transition.
    commit_witnesses: Vec<Witness>,

    /// Witnesses that receive the backend-derived challenge value(s).
    /// Typically 1 element, but multiple are supported for protocols
    /// needing several independent challenges from one commitment round.
    challenge_outputs: Vec<Witness>,
},
```

#### Circuit Metadata

**File: `acvm-repo/acir/src/circuit/mod.rs`** (extends `Circuit<F>` struct at line 38)

```rust
pub struct Circuit<F: AcirField> {
    // ... existing fields ...

    /// Number of phase barriers in this circuit. 0 means single-phase
    /// (legacy behavior). The backend uses this to pre-allocate
    /// commitment round structures.
    pub num_phases: u32,
}
```

### 3.2 ACVM Layer — Execution Engine

#### New Status Variant

**File: `acvm-repo/acvm/src/pwg/mod.rs`** (extends `ACVMStatus<F>` at line 102)

```rust
pub enum ACVMStatus<F> {
    Solved,
    InProgress,
    Failure(OpcodeResolutionError<F>),
    RequiresForeignCall(ForeignCallWaitInfo<F>),
    RequiresAcirCall(AcirCallWaitInfo<F>),

    /// The ACVM has reached a phase barrier and requires the backend to
    /// commit to the specified witnesses and return challenge value(s).
    ///
    /// The caller must:
    /// 1. Read committed witness values from `PhaseBarrierWaitInfo`
    /// 2. Pass them to the backend for polynomial commitment
    /// 3. Receive challenge(s) from the backend
    /// 4. Call `ACVM::resolve_pending_phase_challenge` with the values
    /// 5. Resume `ACVM::solve()`
    RequiresPhaseChallenge(PhaseBarrierWaitInfo<F>),
}
```

#### Wait Info Structure

```rust
/// Information needed to resolve a phase barrier.
pub struct PhaseBarrierWaitInfo<F> {
    /// The phase identifier from the PhaseBarrier opcode.
    pub phase_id: u32,

    /// The witness values the backend should commit to.
    /// Ordered as specified in the PhaseBarrier opcode.
    pub committed_witnesses: Vec<(Witness, F)>,

    /// The witness indices where challenge values should be written.
    pub challenge_outputs: Vec<Witness>,
}
```

#### Solve Loop Modification

In `ACVM::solve_opcode()` (around line 490), add a match arm:

```rust
Opcode::PhaseBarrier { phase_id, commit_witnesses, challenge_outputs } => {
    // Verify all commit_witnesses are resolved
    let mut committed = Vec::with_capacity(commit_witnesses.len());
    for w in commit_witnesses {
        match self.witness_map.get(w) {
            Some(val) => committed.push((*w, *val)),
            None => {
                return self.fail(
                    OpcodeNotSolvable::MissingAssignment(w.0)
                );
            }
        }
    }

    self.status = ACVMStatus::RequiresPhaseChallenge(
        PhaseBarrierWaitInfo {
            phase_id: *phase_id,
            committed_witnesses: committed,
            challenge_outputs: challenge_outputs.clone(),
        }
    );
    // Do NOT advance instruction_pointer — advances on resolution
    return self.status.clone();
}
```

#### Resolution Method

```rust
/// Resolve a pending phase barrier by injecting backend-derived
/// challenge values into the witness map.
pub fn resolve_pending_phase_challenge(&mut self, challenge_values: Vec<F>) {
    let ACVMStatus::RequiresPhaseChallenge(ref info) = self.status else {
        panic!("ACVM is not waiting on a phase challenge");
    };
    assert_eq!(
        challenge_values.len(),
        info.challenge_outputs.len(),
        "Challenge value count mismatch: expected {}, got {}",
        info.challenge_outputs.len(),
        challenge_values.len(),
    );
    for (witness, value) in info.challenge_outputs.iter().zip(challenge_values) {
        self.witness_map.insert(*witness, value);
    }
    self.instruction_pointer += 1;
    self.status = ACVMStatus::InProgress;
}
```

### 3.3 Backend Solver Trait

**File: `acvm-repo/blackbox_solver/src/curve_specific_solver.rs`** (extends trait at line 9)

```rust
pub trait BlackBoxFunctionSolver<F> {
    fn multi_scalar_mul(
        &self,
        points: &[F],
        scalars_lo: &[F],
        scalars_hi: &[F],
        predicate: bool,
    ) -> Result<(F, F, F), BlackBoxResolutionError>;

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

    fn poseidon2_permutation(
        &self,
        inputs: &[F],
    ) -> Result<Vec<F>, BlackBoxResolutionError>;

    /// Commit to witness values and derive Fiat-Shamir challenge(s).
    ///
    /// The backend should:
    /// 1. Interpret `witness_values` as data to be committed
    /// 2. Commit using its native polynomial commitment scheme
    /// 3. Absorb the commitment into its Fiat-Shamir transcript
    /// 4. Squeeze `num_challenges` independent challenge values
    ///
    /// The challenge derivation must be deterministic: given the same
    /// `witness_values`, the same challenges are always produced. The
    /// verifier independently recomputes the same challenges from the
    /// proof's commitments.
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
            "Backend does not support multi-phase challenge derivation"
                .into(),
        ))
    }
}
```

The default implementation errors, preserving backward compatibility. `StubbedBlackBoxSolver` inherits the default and continues to work for single-phase circuits.

### 3.4 Orchestrator — nargo Execute

**File: `tooling/nargo/src/ops/execute.rs`** (extends match in `execute_circuit`, around line 121)

Add a new arm to the `match solver_status` block:

```rust
ACVMStatus::RequiresPhaseChallenge(phase_info) => {
    let witness_values: Vec<F> = phase_info
        .committed_witnesses
        .iter()
        .map(|(_, v)| *v)
        .collect();

    match self.blackbox_solver.derive_phase_challenge(
        phase_info.phase_id,
        &witness_values,
        phase_info.challenge_outputs.len(),
    ) {
        Ok(challenges) => {
            acvm.resolve_pending_phase_challenge(challenges);
        }
        Err(error) => {
            return Err(NargoError::ExecutionError(
                ExecutionError::SolvingError(
                    OpcodeResolutionError::BlackBoxFunctionFailed(
                        BlackBoxFunc::Poseidon2Permutation,
                        error.to_string(),
                    ),
                    None,
                ),
            ));
        }
    }
}
```

### 3.5 Noir Language — Standard Library

New module: `noir_stdlib/src/phase.nr`

```noir
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
pub fn challenge_multi<let N: u32, let M: u32>(
    witnesses: [Field; N],
) -> [Field; M] {}
```

### 3.6 Compiler — SSA to ACIR Codegen

**File: `compiler/noirc_evaluator/src/acir/`**

The `#[builtin(phase_challenge)]` intrinsic requires a codegen path that:

1. Resolves all input expressions to witness indices (they must be concrete values, not unsolved symbolic expressions — enforced by requiring them in an array of `Field`).
2. Allocates one or more fresh `Witness` indices for the challenge output(s).
3. Emits `Opcode::PhaseBarrier { phase_id, commit_witnesses, challenge_outputs }`.
4. Increments a phase counter on the `GeneratedAcir` being built (for `Circuit::num_phases`).
5. Returns the challenge output witness(es) as the result of the builtin call.

**Ordering constraint**: The compiler must ensure that all opcodes producing `commit_witnesses` values are emitted *before* the `PhaseBarrier`, and all opcodes consuming `challenge_outputs` are emitted *after*. This is naturally enforced by SSA data dependencies — the challenge output is a fresh value that can only be used after the `PhaseBarrier` opcode.

### 3.7 Serialization

**File: `acvm-repo/acir/src/circuit/opcodes.rs`** (serde derives)

The `PhaseBarrier` variant needs `Serialize`/`Deserialize` support. Since `Opcode<F>` already derives both, this is automatic once the variant is added. The MessagePack serialization used for ACIR programs will include the new variant.

**Backward compatibility**: Programs compiled without `PhaseBarrier` opcodes have `num_phases: 0` and behave identically to current single-phase circuits. Older backends that receive a program with `PhaseBarrier` opcodes will fail at the ACVM level (the `derive_phase_challenge` default returns an error), which is the correct behavior.

## 4. Barretenberg Integration Details

### Challenge Derivation Strategy — Standalone Sponge Protocol

**Implemented design** (refined from original "deterministic re-derivation" plan):

Phase barrier challenges are derived via a **standalone Poseidon2 sponge hash** that is completely independent of barretenberg's main Fiat-Shamir transcript. This avoids a fundamental impedance mismatch: the Rust-side `derive_phase_challenge` (called during `nargo execute`) does not have access to the VK hash or public inputs that barretenberg's transcript has already absorbed.

The protocol:

1. `derive_phase_challenge` is a **pure function** in the Rust `Bn254BlackBoxSolver`:
   - Commits to `witness_values` via KZG (using the BN254 SRS loaded from `~/.bb-crs/bn254_g1.dat`)
   - Encodes the KZG commitment point (x, y) as 4 Fr limbs (lo/hi split at 2^136)
   - Feeds `[phase_id_as_fr, x_lo, x_hi, y_lo, y_hi]` into a Poseidon2 sponge hash
   - The hash output is the challenge; for multiple challenges, the 254-bit hash is split into 127-bit halves
2. The bb **OinkProver** commits to the phase barrier witness polynomial and sends the commitment to the transcript via `send_to_verifier()`, but does **NOT** squeeze a challenge from the transcript.
3. The bb **OinkVerifier** receives the commitment from the transcript via `receive_from_prover()`, but does **NOT** squeeze a challenge.
4. **Soundness argument**: The commitment is binding (KZG) and becomes part of the proof. The challenge was deterministically derived from the commitment during ACVM execution. Phase 2 circuit constraints check polynomial identities using the challenge. Sumcheck + PCS verify all constraints and wire polynomial commitments. If the prover used a wrong challenge, circuit constraints would fail Sumcheck.

This cleanly separates ACVM execution (witness generation + challenge derivation) from proving (commitment + transcript binding).

### Mapping to Oink Rounds

Barretenberg's Oink prover already performs this exact pattern:

| Oink Round | Commits To | Derives | Used For |
|---|---|---|---|
| Round 0 | w_l, w_r, w_o (wire polynomials) | η (eta) | Memory record combination in w_4 |
| Round 1 | w_4, lookup_read_counts, lookup_read_tags | β, γ | Permutation argument, logUp lookup batching |
| Round 2 | lookup_inverses, z_perm | α | Subrelation batching in Sumcheck |

Phase barriers are processed *before* the standard Oink rounds begin (`commit_to_phase_barriers()` is called before Round 0). Each barrier commits to its witness polynomial and sends the commitment to the transcript. The commitments are included in the proof before the standard wire commitments.

### Verifier Behavior

The verifier receives phase barrier commitments from the proof and absorbs them into the transcript (for ordering/binding), but does not derive challenges from the transcript. The challenge values are verified implicitly: they are part of the witness, used in Phase 2 constraints, and Sumcheck verifies all constraint satisfaction.

For **recursive verification** (used in Enclave's proof aggregation), the `RecursiveAggregation` black box function handles the extra transcript data. The recursive verifier receives the phase barrier commitments as part of the inner proof and processes them the same way — absorb into transcript, no challenge squeeze.

## 5. Impact on Enclave PVSS Circuits

### Before (Current Implementation)

Taking `share_encryption` as the representative circuit:

```
// In-circuit Fiat-Shamir via SAFE sponge
pk_commitment = SAFE_SPONGE("PK", pack(pk_coeffs))              // ~200K constraints
msg_commitment = SAFE_SPONGE("MSG", pack(msg_coeffs))            // ~175K constraints
gamma = SAFE_SPONGE("CLG", pk_commit || ct0 || ct1 || ...)       // ~300K constraints

// Actual cryptographic verification
eval = horner_evaluate(all_polys, gamma)                          // ~50K constraints
assert(batch_schwartz_zippel(eval) == 0)                          // ~5K constraints
```

### After (With Multi-Phase)

```noir
use std::phase::challenge;

// Phase 1: Lay out all polynomial witnesses (no hashing)
let pk_coeffs = ...;
let msg_coeffs = ...;
let ct0 = ...;
let ct1 = ...;

// Phase barrier: backend commits to all witnesses, derives challenge
let gamma = challenge(
    flatten([pk_coeffs, msg_coeffs, ct0, ct1, ...])
);

// Phase 2: Polynomial evaluation and batch check (unchanged)
let eval = horner_evaluate(all_polys, gamma);                     // ~50K constraints
assert(batch_schwartz_zippel(eval) == 0);                         // ~5K constraints
```

### Estimated Impact Across All Circuits

| Circuit | Current Gates | Est. After | Reduction |
|---|---|---|---|
| `verify_shares_trbfv_sk` | 11.1M | ~4–5M | ~55% |
| `verify_shares_trbfv_e_sm` | 11.3M | ~4–5M | ~55% |
| `pk_agg_trbfv` | 6.1M | ~2–3M | ~55% |
| `dec_share_trbfv` | 4.7M | ~2–3M | ~45% |
| `enc_bfv_sk` | 3.6M | ~1.5–2M | ~50% |
| `enc_bfv_e_sm` | 3.6M | ~1.5–2M | ~50% |
| `greco` | 4.1M | ~2–2.5M | ~45% |
| `dec_bfv_sk` | 1.3M | ~0.6–0.8M | ~45% |
| `dec_bfv_e_sm` | 1.3M | ~0.6–0.8M | ~45% |
| `pk_trbfv` | 2.2M | ~1–1.5M | ~40% |

These are rough estimates. The actual reduction depends on how much of each circuit's gate count is attributable to SAFE sponge operations vs. range checks and arithmetic.

### Cross-Circuit Integrity

The current commitment DAG (where each circuit's hash commitments become public inputs to downstream circuits) can be preserved via two approaches:

1. **Backend commitments as public outputs**: The Phase 1 wire polynomial commitment (a group element from KZG) is exposed as a public output. Downstream circuits receive it as a public input and use `RecursiveAggregation` to verify the upstream proof, which implicitly checks the commitment.

2. **Lightweight in-circuit hashing for linking**: Keep cheap Poseidon2 hash commitments (~300 constraints per permutation) for cross-circuit data integrity, while eliminating only the expensive Fiat-Shamir challenge derivation. This is the minimal change — replace `compute_challenge()` with `std::phase::challenge()` but keep `compute_commitment()`.

Both approaches are available to developers. The choice depends on whether the circuit already uses recursive verification (approach 1 is free) or needs standalone commitments (approach 2).

## 6. Implementation Roadmap

### Phase A: ACIR + ACVM Core

**Scope**: Noir monorepo changes only. No backend changes.

1. Add `PhaseBarrier` opcode variant to `Opcode<F>` in `acvm-repo/acir/src/circuit/opcodes.rs`
2. Add `num_phases: u32` field to `Circuit<F>` in `acvm-repo/acir/src/circuit/mod.rs`
3. Add `RequiresPhaseChallenge(PhaseBarrierWaitInfo<F>)` to `ACVMStatus<F>` in `acvm-repo/acvm/src/pwg/mod.rs`
4. Add `PhaseBarrierWaitInfo<F>` struct
5. Implement `PhaseBarrier` handling in `ACVM::solve_opcode()`
6. Implement `ACVM::resolve_pending_phase_challenge()`
7. Add `derive_phase_challenge` default method to `BlackBoxFunctionSolver<F>` in `acvm-repo/blackbox_solver/src/curve_specific_solver.rs`
8. Update `ACVMStatus::Display` impl
9. Update serialization tests and snapshot tests
10. Unit tests: ACVM correctly pauses at barrier, accepts challenge injection, and resumes

**Verification**: `cargo nextest run -p acvm -p acir -p blackbox_solver`

### Phase B: Noir Language Support

**Scope**: Compiler frontend + stdlib.

1. Add `noir_stdlib/src/phase.nr` with `challenge` and `challenge_multi` function signatures
2. Register `phase_challenge` and `phase_challenge_multi` as compiler builtins in the elaborator (`compiler/noirc_frontend/src/elaborator/`)
3. Add SSA intrinsic for the phase challenge builtins
4. Add SSA → ACIR codegen: emit `PhaseBarrier` opcode, allocate output witnesses, track phase count
5. Integration tests: Noir programs using `std::phase::challenge()` compile to correct ACIR with `PhaseBarrier` opcodes

**Verification**: `cargo nextest run -p noirc_frontend -p noirc_evaluator`

### Phase C: Orchestrator Integration

**Scope**: nargo execution layer.

1. Add `RequiresPhaseChallenge` match arm to `ProgramExecutor::execute_circuit()` in `tooling/nargo/src/ops/execute.rs`
2. Wire the `derive_phase_challenge` call through the blackbox solver
3. Add error handling and diagnostic messages for unsupported backends
4. Integration test: execute a multi-phase program end-to-end with a mock backend that returns known challenge values

**Verification**: `cargo nextest run -p nargo`

### Phase D: Barretenberg Backend (fork required)

**Scope**: BN254 blackbox solver + barretenberg prover/verifier.
**Repository**: Requires a fork of [AztecProtocol/barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg).

#### Why bb changes are necessary

Alternative approaches were considered and rejected:

- **Option B (multi-phase witness gen + in-circuit Poseidon2 check)**: The `PhaseBarrier` would derive a challenge during witness generation, but the circuit would also contain in-circuit Poseidon2 constraints to verify `challenge == Hash(witnesses)`. This was rejected because **the volume of data being hashed is the bottleneck, not the hash function**. The Enclave circuits absorb thousands of field elements (polynomial coefficients, ciphertexts, public keys) into their Fiat-Shamir transcripts. Even with raw Poseidon2 (~100 constraints per field element at rate-3), hashing 2000-3000 field elements would still cost ~200K-300K constraints. The SAFE sponge's Keccak tags add ~150K/instance on top, but eliminating only the tags still leaves most of the cost.

- **Option C (replace SAFE sponge with raw Poseidon2 in Enclave circuits)**: Pure Noir-side refactoring with no infrastructure changes. Saves the Keccak tag overhead (~450K across 3 instances) but keeps all Poseidon2 absorption costs. Achieves maybe 40-60% of the possible savings.

- **Option A (full multi-phase — chosen approach)**: The backend commits to witness polynomials via KZG *outside the circuit* as part of its normal proving flow, then derives challenges from those commitments via its Poseidon2 transcript. Zero in-circuit hashing is needed for challenge derivation. This is the only approach that eliminates the volume problem entirely, achieving the ~92% reduction in Fiat-Shamir constraint cost.

The key insight: barretenberg already commits to all wire polynomials and derives Fiat-Shamir challenges during its Oink rounds. The `PhaseBarrier` exposes this existing capability to circuit authors. The bb changes are about *plumbing*, not new cryptography.

#### Implementation Steps

##### D.1: `derive_phase_challenge` on `Bn254BlackBoxSolver`

The `Bn254BlackBoxSolver` (used during `nargo execute` / `nargo prove` for witness generation) must implement the `derive_phase_challenge` method. This is the function called when the ACVM pauses at a `PhaseBarrier`.

**Requirements**:
- Pure function: `(phase_id, witness_values[]) -> challenge_values[]`
- Deterministic: same inputs always produce same outputs
- Must match what the prover/verifier will compute from the proof's commitments

**Implementation**: Construct a KZG commitment to the witness values (treating them as evaluations of a polynomial over a domain), absorb the commitment into a Poseidon2 transcript, and squeeze challenge values. This mirrors what the Oink prover does internally.

**Location in bb**: The `Bn254BlackBoxSolver` lives in the Noir monorepo at `acvm-repo/bn254_blackbox_solver/` but wraps barretenberg's C++ via FFI. The `derive_phase_challenge` implementation will need a new FFI binding to a C++ function that performs the KZG commit + transcript squeeze.

##### D.2: `acir_format` translator

The `acir_format` module in barretenberg translates ACIR opcodes into bb's internal constraint system representation. It must recognize `PhaseBarrier` opcodes and:
- Record which witness indices are committed at each phase boundary
- Record which witness indices receive challenge values
- Pass this metadata to the proving key builder so the Oink prover knows about the extra commitment rounds

**Key files** (in bb repo):
- `barretenberg/cpp/src/barretenberg/dsl/acir_format/acir_format.hpp` — ACIR constraint structures
- `barretenberg/cpp/src/barretenberg/dsl/acir_format/acir_to_constraint_buf.cpp` — ACIR opcode translation

##### D.3: Oink prover modification

The Oink prover performs commitment rounds in a fixed sequence (Round 0: wires, Round 1: logUp, Round 2: grand product). Phase barrier rounds should be inserted **before** the standard Oink rounds so they don't interfere with the existing structure.

For each `PhaseBarrier` (ordered by `phase_id`):
1. Construct a polynomial from the committed witness values
2. Commit to it using the circuit's KZG commitment key
3. Absorb the commitment into the Fiat-Shamir transcript
4. Squeeze `num_challenges` challenge values
5. These challenges must equal the values already in the witness (injected during ACVM execution via `derive_phase_challenge`)

The prover does not need to *inject* values — they're already in the witness from ACVM execution. It just needs to include the extra commitments in the proof and ensure the transcript is consistent.

**Key files**:
- `barretenberg/cpp/src/barretenberg/ultra_honk/oink_prover.hpp`
- `barretenberg/cpp/src/barretenberg/ultra_honk/oink_prover.cpp`

##### D.4: Verifier modification

The verifier must reconstruct the same multi-round transcript:
1. Read the phase barrier commitment(s) from the proof
2. Absorb them into the transcript
3. Squeeze the same challenge values
4. Use those challenges when checking Phase 2 constraints

**Key files**:
- `barretenberg/cpp/src/barretenberg/ultra_honk/oink_verifier.hpp`
- `barretenberg/cpp/src/barretenberg/ultra_honk/oink_verifier.cpp`

##### D.5: Proof format

The proof must include the phase barrier commitments (group elements) in addition to the standard wire commitments. These appear at the beginning of the proof, before the standard Oink commitments. The proof size increases by one group element per phase barrier.

##### D.6: Recursive verifier

For Enclave's proof aggregation pipeline, the recursive verifier circuit (used via `RecursiveAggregation` black box) must also handle the extra transcript rounds. This is the same change as D.4 but in the recursive verifier circuit builder.

**Key files**:
- `barretenberg/cpp/src/barretenberg/stdlib/honk_verifier/`

##### D.7: End-to-end test

Prove and verify a multi-phase Noir program against the modified barretenberg:
- Compile a Noir program that uses `std::phase::challenge()`
- Generate witness via `nargo execute` (exercises `derive_phase_challenge`)
- Prove via the modified bb prover (exercises Oink round insertion)
- Verify via the modified bb verifier (exercises transcript reconstruction)
- Recursively verify the proof in another circuit (exercises recursive verifier)

**Verification**: Full prove/verify cycle including recursive verification.

### Phase E: Enclave Circuit Migration (fork required)

**Scope**: Enclave repository.
**Repository**: Requires a fork of [gnosisguild/enclave](https://github.com/gnosisguild/enclave).

#### Migration Strategy

The migration has two independent parts with different risk profiles:

##### E.1: Replace Fiat-Shamir challenge derivation (high impact, core change)

Replace `compute_challenge()` calls (the SAFE sponge Fiat-Shamir instances) with `std::phase::challenge()` in all PVSS circuits. This is where the bulk of the constraint savings come from.

**For each circuit**:
1. Identify all SAFE sponge calls used for Fiat-Shamir challenge derivation
2. Collect the witness data that was being absorbed (polynomial coefficients, ciphertexts, public keys)
3. Replace with `let gamma = std::phase::challenge(flatten([data...]))`
4. The polynomial evaluation and Schwartz-Zippel checks remain unchanged

The SAFE sponge calls used for **commitments** (as opposed to challenge derivation) are handled separately in E.2.

##### E.2: Decide commitment strategy (lower impact, design choice)

The current circuits compute in-circuit commitments (hashes of polynomial coefficients) that serve two purposes:
1. **Input to Fiat-Shamir** — eliminated by E.1
2. **Cross-circuit linking** — commitment values are exposed as public outputs and consumed as public inputs by downstream circuits

For purpose (2), there are two options:

**Option 1: Keep lightweight in-circuit commitments.** Replace the SAFE sponge commitments with raw Poseidon2 hashing (no Keccak tags, no domain separation overhead). This costs ~100 constraints per field element absorbed. For the commitment DAG, this may be acceptable if the number of field elements being committed is small (e.g., just the final evaluation results, not the full polynomial coefficients).

**Option 2: Use backend commitments via recursive verification.** The KZG commitments from Phase 1 are implicitly verified when a downstream circuit recursively verifies the upstream proof. No separate in-circuit commitment is needed. This is the cleanest approach if Enclave already uses recursive aggregation (which it does).

Recommendation: Start with Option 2 (no in-circuit commitments for linking) since Enclave's architecture already relies on recursive proof aggregation. Fall back to Option 1 only for cases where a commitment value must be visible outside the proving system (e.g., posted on-chain independently of the proof).

##### E.3: Benchmarking

For each of the 10+ circuits:
1. Measure current gate count (baseline)
2. Migrate to `std::phase::challenge()`
3. Measure new gate count
4. Compare against the estimates in Section 5
5. Measure proving time reduction (gate count is a proxy but proving time depends on other factors like FFT sizes and MSM batch sizes)

##### E.4: Recursive aggregation validation

The Enclave pipeline aggregates proofs recursively. After migration:
1. Generate a multi-phase proof for each circuit
2. Recursively verify it in the aggregation circuit
3. Verify the aggregated proof
4. Confirm the full pipeline works end-to-end

This is the highest-risk validation step. If the recursive verifier doesn't correctly handle the extra transcript rounds (Phase D.6), the aggregation will fail.

## 7. Open Questions

### 7.1 Challenge Binding and Proof Soundness

When the backend commits to Phase 1 witnesses and derives a challenge, the resulting Phase 2 constraints must be *part of the same proof*. The verifier must check that the challenge used in Phase 2 is correctly derived from the Phase 1 commitments.

This is naturally handled if `PhaseBarrier` maps to a barretenberg Oink commitment round, but requires careful specification for the general case. The `phase_id` ordering must correspond to a well-defined transcript sequence.

### 7.2 Multiple Barriers Per Circuit

The design supports multiple `PhaseBarrier` opcodes for multi-round protocols (e.g., commit → challenge₁ → compute → commit → challenge₂). The `phase_id` establishes ordering. The ACVM enforces sequential phase_id ordering (0, 1, 2, ...) at runtime. **Question for Enclave**: Do any of the 12 PVSS circuits need more than one phase barrier (i.e., more than 2 phases)?

### 7.3 Opcode Ordering Guarantees

All opcodes before a `PhaseBarrier` must be solvable without the challenge values. All opcodes after may use the challenge. The SSA data dependency graph naturally enforces this (the challenge is a fresh value that cannot be referenced before its definition). However, the compiler must ensure that no SSA optimization reorders opcodes across a phase boundary. This may require marking the `PhaseBarrier` as a sequencing barrier in the SSA pass pipeline.

### 7.4 Brillig Interaction

Unconstrained (Brillig) code can run before or after a phase barrier without issue. However, a single Brillig invocation **cannot span** a phase barrier — the Brillig VM would need to pause mid-execution, which is not supported (the existing foreign call mechanism pauses Brillig for external data, but a phase barrier requires the *entire ACVM* to pause, not just the Brillig VM).

The compiler should emit a compile-time error if a `std::phase::challenge()` call appears inside an unconstrained function, since the challenge value wouldn't be constrained.

### 7.5 Recursive Verification Compatibility

When a multi-phase proof is verified recursively via `RecursiveAggregation`, the inner verifier must reconstruct the multi-round transcript including phase barrier commitment rounds. This should work if the proof format encodes the phase structure (number of extra commitment rounds and their positions in the transcript). Needs validation against barretenberg's recursive verifier circuit.

This is the highest-risk item for the Enclave integration (Phase E.4). If the recursive verifier doesn't handle the extra transcript rounds correctly, the entire proof aggregation pipeline breaks. Recommend testing this early in Phase D (before migrating Enclave circuits).

### 7.6 Security Model Differences

The in-circuit SAFE sponge provides specific security properties:
- **Domain separation** via 128-bit Keccak tags (distinct per IO pattern + domain separator)
- **Sponge-based extraction** with a well-analyzed security bound

Backend-derived challenges have different properties:
- **Security bound tied to the proving system's Fiat-Shamir analysis** (which is rigorous for barretenberg/UltraHonk)
- **No application-level domain separation** — the challenge is derived from all committed wire polynomials, not a specific subset

For Schwartz-Zippel polynomial identity testing (Enclave's primary use case), backend challenges are sufficient — the security requirement is simply that the evaluation point is unpredictable to the prover before committing to the polynomial coefficients. The backend's Fiat-Shamir transcript provides exactly this guarantee.

However, for use cases requiring application-level domain separation or commitments visible to external systems (not just the verifier), in-circuit hashing remains the correct choice. The `std::phase` documentation should make this distinction clear.

### 7.7 Witness Subset Selection

The current design commits to an explicit list of witnesses (`commit_witnesses`). An alternative is to commit to *all* witnesses assigned so far (matching how barretenberg commits to entire wire polynomials). The explicit list is more flexible (allows committing to subsets) but requires the circuit author to specify which witnesses to include. The "commit all" approach is simpler but may include witnesses that shouldn't influence the challenge (e.g., intermediate computation values that are not part of the protocol transcript).

Recommendation: Start with explicit witness lists. If ergonomics are poor, add a `challenge_all()` variant that commits to the full witness state.

### 7.8 KZG Commitment Key Sizing

The `derive_phase_challenge` function constructs a KZG commitment from the committed witness values. The commitment key (SRS) must be large enough to commit to a polynomial of degree equal to the number of committed witnesses. For Enclave circuits committing thousands of field elements, this should be well within the standard SRS sizes used by barretenberg (which supports circuits with millions of gates). However, the Phase D implementation should verify that the SRS available to `Bn254BlackBoxSolver` during witness generation is the same SRS that the prover will use, to ensure deterministic challenge agreement.

### 7.9 Phase Barrier Interaction with Circuit Optimization Passes

The `PhaseBarrier` opcode must survive all ACIR-level optimization passes (common subexpression elimination, dead code elimination, etc.) without being reordered or removed. The current implementation marks `PhaseChallenge` / `PhaseChallengeMulti` intrinsics as having side effects (`has_side_effects: true`) and being impure, which prevents SSA-level reordering. At the ACIR level, the existing optimization passes already skip unknown opcodes, so `PhaseBarrier` passes through unchanged. This should be verified if new optimization passes are added.
