use ashlang::compiler::Compiler;
use ashlang::Config;
use scalarff::Curve25519FieldElement;
extern crate libspartan;
extern crate merlin;

use ashlang_spartan::prove;
use ashlang_spartan::verify;
pub use structures::SpartanConfig;
pub use structures::SpartanProof;
use transform::transform_r1cs;

mod structures;
mod transform;

const PROGRAM: &str = "
let x = 4
let y = 5

let z = x * y

let _ = z * x
";

fn main() {
    let mut compiler: Compiler<Curve25519FieldElement> = Compiler::new(&Config {
        include_paths: vec![],
        verbosity: 1,
        inputs: vec![],
        secret_inputs: vec![],
        target: "r1cs".to_string(),
        extension_priorities: vec!["ash".to_string()],
        entry_fn: "entry".to_string(),
        field: "curve25519".to_string(),
    });
    let out = compiler.compile_str(PROGRAM, "r1cs");
    // produce a tiny instance
    let config = transform_r1cs(&out);
    let spartan_proof = prove(config);

    let valid = verify(spartan_proof);
    assert!(valid);
    println!("proof verification successful!");
}
