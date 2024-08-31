use libspartan::SNARK;
use merlin::Transcript;
extern crate libspartan;
extern crate merlin;
use libspartan::SNARKGens;

mod structures;
mod transform;

pub use structures::SpartanConfig;
pub use structures::SpartanProof;

pub use transform::transform_r1cs;

/// We return a SNARK, commitment,
pub fn prove(
    (
        num_cons,
        num_vars,
        num_inputs,
        num_non_zero_entries,
        inst,
        assignment_vars,
        assignment_inputs,
    ): SpartanConfig,
) -> SpartanProof {
    // produce public parameters
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"ashlang-spartan");
    SpartanProof {
        snark: SNARK::prove(
            &inst,
            &comm,
            &decomm,
            assignment_vars,
            &assignment_inputs,
            &gens,
            &mut prover_transcript,
        ),
        comm,
        gens,
        inputs: assignment_inputs,
    }
}

pub fn verify(serialized_proof: SpartanProof) -> bool {
    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"ashlang-spartan");
    serialized_proof
        .snark
        .verify(
            &serialized_proof.comm,
            &serialized_proof.inputs,
            &mut verifier_transcript,
            &serialized_proof.gens,
        )
        .is_ok()
}
