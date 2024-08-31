use ashlang::r1cs::constraint::R1csConstraint;
use ashlang::Config;
use ashlang::{compiler::Compiler, r1cs::parser::R1csParser};
use curve25519_dalek;
use scalarff::{Curve25519FieldElement, FieldElement};
extern crate libspartan;
extern crate merlin;
use curve25519_dalek::scalar::Scalar;
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, SNARK};
use merlin::Transcript;
use rand::rngs::OsRng;

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
    ) = produce_tiny_r1cs(&out);

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

fn to_32(v: Vec<u8>) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    if v.len() > 32 {
        panic!("too many bytes");
    }
    for i in 0..32 {
        if i < v.len() {
            out[i] = v[i];
        }
    }
    out
}

fn produce_tiny_r1cs(
    r1cs: &str,
) -> (
    usize,
    usize,
    usize,
    usize,
    Instance,
    VarsAssignment,
    InputsAssignment,
) {
    // We will encode the above constraints into three matrices, where
    // the coefficients in the matrix are in the little-endian byte order
    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

    // parameters of the R1CS instance rounded to the nearest power of two
    let witness = ashlang::r1cs::witness::build::<Curve25519FieldElement>(r1cs);
    if let Err(e) = witness {
        panic!("error building witness: {:?}", e);
    }
    let mut witness = witness.unwrap();
    let l = witness.len();
    witness[0] = witness[l - 1];
    witness[l - 1] = Curve25519FieldElement::from(1);
    let constraints;
    {
        let r1cs_parser: R1csParser<Curve25519FieldElement> = R1csParser::new(r1cs);
        constraints = r1cs_parser
            .constraints
            .into_iter()
            .filter(|c| !c.symbolic)
            .collect::<Vec<_>>();
    }

    let num_cons = constraints.len();
    let num_vars = witness.len() - 1;
    let num_inputs = 0;
    // in each constraint remap the one variable to the end of the
    // var vector
    let remapped_constraints = constraints
        .iter()
        .map(|constraint| {
            let mut new_a = vec![];
            let mut new_b = vec![];
            let mut new_c = vec![];
            for (v, var_i) in constraint.a.clone() {
                if var_i == 0 {
                    new_a.push((v, witness.len() - 1));
                } else if var_i == witness.len() - 1 {
                    new_a.push((v, 0));
                } else {
                    new_a.push((v, var_i));
                }
            }
            for (v, var_i) in constraint.b.clone() {
                if var_i == 0 {
                    new_b.push((v, witness.len() - 1));
                } else if var_i == witness.len() - 1 {
                    new_b.push((v, 0));
                } else {
                    new_b.push((v, var_i));
                }
            }
            for (v, var_i) in constraint.c.clone() {
                if var_i == 0 {
                    new_c.push((v, witness.len() - 1));
                } else if var_i == witness.len() - 1 {
                    new_c.push((v, 0));
                } else {
                    new_c.push((v, var_i));
                }
            }
            R1csConstraint {
                a: new_a,
                b: new_b,
                c: new_c,
                out_i: None,
                comment: None,
                symbolic: false,
                symbolic_op: None,
            }
        })
        .collect::<Vec<_>>();
    let num_non_zero_entries = witness.len() - 1;

    // create a VarsAssignment
    let mut vars = vec![Scalar::ZERO.to_bytes(); num_vars];
    for i in 0..num_vars {
        vars[i] = to_32(witness[i].to_bytes_le());
    }

    // every row = constrint
    // every column = variable

    for (i, constraint) in remapped_constraints.iter().enumerate() {
        for (v, col_i) in &constraint.a {
            A.push((i, *col_i, to_32(v.to_bytes_le())));
        }
        for (v, col_i) in &constraint.b {
            B.push((i, *col_i, to_32(v.to_bytes_le())));
        }
        for (v, col_i) in &constraint.c {
            C.push((i, *col_i, to_32(v.to_bytes_le())));
        }
    }
    // We will use the following example, but one could construct any R1CS instance.
    // Our R1CS instance is three constraints over five variables and two public inputs
    // (Z0 + Z1) * I0 - Z2 = 0
    // (Z0 + I1) * Z2 - Z3 = 0
    // Z4 * 1 - 0 = 0

    // The constraint system is defined over a finite field, which in our case is
    // the scalar field of ristreeto255/curve25519 i.e., p =  2^{252}+27742317777372353535851937790883648493
    // To construct these matrices, we will use `curve25519-dalek` but one can use any other method.

    // a variable that holds a byte representation of 1
    // let one = Scalar::ONE.to_bytes();

    // R1CS is a set of three sparse matrices A B C, where is a row for every
    // constraint and a column for every entry in z = (vars, 1, inputs)
    // An R1CS instance is satisfiable iff:
    // Az \circ Bz = Cz, where z = (vars, 1, inputs)

    // constraint 0 entries in (A,B,C)
    // constraint 0 is (Z0 + Z1) * I0 - Z2 = 0.
    // We set 1 in matrix A for columns that correspond to Z0 and Z1
    // We set 1 in matrix B for column that corresponds to I0
    // We set 1 in matrix C for column that corresponds to Z2
    // A.push((0, 0, one));
    // A.push((0, 1, one));
    // B.push((0, num_vars + 1, one));
    // C.push((0, 2, one));

    // constraint 1 entries in (A,B,C)
    // A.push((1, 0, one));
    // A.push((1, num_vars + 2, one));
    // B.push((1, 2, one));
    // C.push((1, 3, one));

    // constraint 3 entries in (A,B,C)
    // A.push((2, 4, one));
    // B.push((2, num_vars, one));

    let inst = Instance::new(num_cons, num_vars, num_inputs, &A, &B, &C);
    if let Err(e) = inst {
        panic!("error building instance: {:?}", e);
    }
    let inst = inst.unwrap();

    // compute a satisfying assignment
    // let mut csprng: OsRng = OsRng;
    // let i0 = Scalar::random(&mut csprng);
    // let i1 = Scalar::random(&mut csprng);
    // let z0 = Scalar::random(&mut csprng);
    // let z1 = Scalar::random(&mut csprng);
    // let z2 = (z0 + z1) * i0; // constraint 0
    // let z3 = (z0 + i1) * z2; // constraint 1
    // let z4 = Scalar::ZERO; //constraint 2

    // vars[0] = z0.to_bytes();
    // vars[1] = z1.to_bytes();
    // vars[2] = z2.to_bytes();
    // vars[3] = z3.to_bytes();
    // vars[4] = z4.to_bytes();
    let assignment_vars = VarsAssignment::new(&vars).unwrap();

    // create an InputsAssignment
    let inputs = vec![Scalar::ZERO.to_bytes(); num_inputs];
    // inputs[0] = i0.to_bytes();
    // inputs[1] = i1.to_bytes();
    let assignment_inputs = InputsAssignment::new(&inputs).unwrap();

    // check if the instance we created is satisfiable
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    assert_eq!(res.unwrap(), true);

    (
        num_cons,
        num_vars,
        num_inputs,
        num_non_zero_entries,
        inst,
        assignment_vars,
        assignment_inputs,
    )
}
