use ashlang::compiler::Compiler;
use ashlang::Config;
use scalarff::Curve25519FieldElement;
extern crate libspartan;
extern crate merlin;
use libspartan::SNARKGens;
use libspartan::SNARK;
use merlin::Transcript;

use transform::transform_r1cs;

mod transform;

const PROGRAM: &'static str = "
let x = 4
let y = 5

let z = x * y
";

fn main() {
    let mut compiler: Compiler<Curve25519FieldElement> = Compiler::new(&Config {
        include_paths: vec![],
        verbosity: 0,
        inputs: vec![],
        secret_inputs: vec![],
        target: "r1cs".to_string(),
        extension_priorities: vec!["ash".to_string()],
        entry_fn: "entry".to_string(),
        field: "curve25519".to_string(),
    });
    let out = compiler.compile_str(PROGRAM, "r1cs");
    // produce a tiny instance
    let (
        num_cons,
        num_vars,
        num_inputs,
        num_non_zero_entries,
        inst,
        assignment_vars,
        assignment_inputs,
    ) = transform_r1cs(&out);

    // produce public parameters
    let gens = SNARKGens::new(num_cons, num_vars, num_inputs, num_non_zero_entries);

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(
        &inst,
        &comm,
        &decomm,
        assignment_vars,
        &assignment_inputs,
        &gens,
        &mut prover_transcript,
    );

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
        .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
        .is_ok());
    println!("proof verification successful!");
}
