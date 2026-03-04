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

### Challenge Derivation Strategy

We recommend **deterministic re-derivation** for the initial implementation:

1. `derive_phase_challenge` is a **pure function**: it takes witness values, commits to them (KZG), hashes the commitment (Poseidon2), and squeezes challenge values. No shared state with the prover.
2. During actual proving, the barretenberg prover independently reconstructs the same transcript. The commitments to Phase 1 witnesses are part of the proof; the verifier recomputes the same challenge from them.
3. This cleanly separates ACVM execution (witness generation) from proving. The `BlackBoxFunctionSolver` instance does not need to outlive the ACVM execution or be passed to the prover.

An alternative (**shared transcript state**) avoids redundant commitment computation but couples the ACVM execution to a specific prover instance. This optimization can be layered on later without changing the ACIR or ACVM interfaces.

### Mapping to Oink Rounds

Barretenberg's Oink prover already performs this exact pattern:

| Oink Round | Commits To | Derives | Used For |
|---|---|---|---|
| Round 0 | w_l, w_r, w_o (wire polynomials) | η (eta) | Memory record combination in w_4 |
| Round 1 | w_4, lookup_read_counts, lookup_read_tags | β, γ | Permutation argument, logUp lookup batching |
| Round 2 | lookup_inverses, z_perm | α | Subrelation batching in Sumcheck |

A `PhaseBarrier` maps to a **custom commitment round** inserted into (or before) the Oink sequence. The `phase_id` determines where in the transcript this round falls. The simplest approach: Phase barriers are processed *before* the standard Oink rounds begin, so they don't interfere with barretenberg's existing round structure.

### Verifier Behavior

The verifier performs the same multi-round protocol:
1. Read Phase 1 wire commitments from the proof
2. Derive the same challenges using the same transcript
3. Verify Phase 2 constraints using those challenges

This is structurally identical to how barretenberg's verifier already processes Oink rounds. The `PhaseBarrier` simply adds one or more custom commitment rounds to the beginning of the transcript.

For **recursive verification** (used in Enclave's proof aggregation), the `RecursiveAggregation` black box function already handles multi-round transcript verification internally. A multi-phase inner proof is verified the same way as a single-phase proof — the recursive verifier reconstructs the full transcript including any phase barrier rounds.

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

### Phase D: Barretenberg Backend

**Scope**: BN254 blackbox solver + barretenberg prover/verifier.

1. Implement `derive_phase_challenge` in the BN254 blackbox solver using Poseidon2 transcript + KZG commitment
2. Ensure deterministic challenge derivation (same inputs → same challenge, always)
3. Modify barretenberg's `acir_format` translator to recognize `PhaseBarrier` opcodes and insert corresponding commitment rounds into the Oink prover
4. Modify barretenberg's verifier to reconstruct the multi-round transcript including phase barrier rounds
5. End-to-end test: prove and verify a multi-phase Noir program against barretenberg

**Verification**: Full prove/verify cycle with barretenberg backend.

### Phase E: Enclave Circuit Migration

**Scope**: Enclave repository.

1. Replace `compute_challenge()` calls (Fiat-Shamir) with `std::phase::challenge()` in all PVSS circuits
2. Optionally replace `compute_commitment()` calls with backend commitment approach or keep lightweight Poseidon2 hashing for cross-circuit linking
3. Benchmark constraint counts and proving times against the current implementation
4. Update the commitment DAG documentation
5. Validate recursive proof aggregation still works with multi-phase inner proofs

## 7. Open Questions

### 7.1 Challenge Binding and Proof Soundness

When the backend commits to Phase 1 witnesses and derives a challenge, the resulting Phase 2 constraints must be *part of the same proof*. The verifier must check that the challenge used in Phase 2 is correctly derived from the Phase 1 commitments.

This is naturally handled if `PhaseBarrier` maps to a barretenberg Oink commitment round, but requires careful specification for the general case. The `phase_id` ordering must correspond to a well-defined transcript sequence.

### 7.2 Multiple Barriers Per Circuit

The design supports multiple `PhaseBarrier` opcodes for multi-round protocols (e.g., commit → challenge₁ → compute → commit → challenge₂). The `phase_id` establishes ordering. **Question for Enclave**: Do any of the 12 PVSS circuits need more than one phase barrier (i.e., more than 2 phases)?

### 7.3 Opcode Ordering Guarantees

All opcodes before a `PhaseBarrier` must be solvable without the challenge values. All opcodes after may use the challenge. The SSA data dependency graph naturally enforces this (the challenge is a fresh value that cannot be referenced before its definition). However, the compiler must ensure that no SSA optimization reorders opcodes across a phase boundary. This may require marking the `PhaseBarrier` as a sequencing barrier in the SSA pass pipeline.

### 7.4 Brillig Interaction

Unconstrained (Brillig) code can run before or after a phase barrier without issue. However, a single Brillig invocation **cannot span** a phase barrier — the Brillig VM would need to pause mid-execution, which is not supported (the existing foreign call mechanism pauses Brillig for external data, but a phase barrier requires the *entire ACVM* to pause, not just the Brillig VM).

The compiler should emit a compile-time error if a `std::phase::challenge()` call appears inside an unconstrained function, since the challenge value wouldn't be constrained.

### 7.5 Recursive Verification Compatibility

When a multi-phase proof is verified recursively via `RecursiveAggregation`, the inner verifier must reconstruct the multi-round transcript including phase barrier commitment rounds. This should work if the proof format encodes the phase structure (number of extra commitment rounds and their positions in the transcript). Needs validation against barretenberg's recursive verifier circuit.

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
