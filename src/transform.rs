use ashlang::r1cs::constraint::R1csConstraint;
use ashlang::r1cs::parser::R1csParser;
use curve25519_dalek;
use scalarff::Curve25519FieldElement;
use scalarff::FieldElement;
extern crate libspartan;
extern crate merlin;
use curve25519_dalek::scalar::Scalar;
use libspartan::InputsAssignment;
use libspartan::Instance;
use libspartan::VarsAssignment;

use super::SpartanConfig;

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

pub fn transform_r1cs(r1cs: &str) -> SpartanConfig {
    // We will encode the above constraints into three matrices, where
    // the coefficients in the matrix are in the little-endian byte order
    let mut a_mat: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut b_mat: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut c_mat: Vec<(usize, usize, [u8; 32])> = Vec::new();

    // parameters of the R1CS instance rounded to the nearest power of two
    let witness = ashlang::r1cs::witness::build::<Curve25519FieldElement>(r1cs);
    if let Err(e) = witness {
        panic!("error building witness: {:?}", e);
    }
    let mut witness = witness.unwrap();
    // put the one variable at the end of the witness vector
    let l = witness.len();
    witness[0] = witness[l - 1];
    witness[l - 1] = Curve25519FieldElement::from(1);
    let constraints;
    // filter out the symbolic constraints
    {
        let r1cs_parser: R1csParser<Curve25519FieldElement> = R1csParser::new(r1cs);
        constraints = r1cs_parser
            .constraints
            .into_iter()
            .filter(|c| !c.symbolic)
            .collect::<Vec<_>>();
    }

    // number of constraints
    let num_cons = constraints.len();
    // number of variables
    let num_vars = witness.len() - 1;
    let num_inputs = 0;
    let num_non_zero_entries = witness.len() - 1;

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

    // create a VarsAssignment
    let mut vars = vec![Scalar::ZERO.to_bytes(); num_vars];
    for i in 0..num_vars {
        vars[i] = to_32(witness[i].to_bytes_le());
    }

    // every row = constrint
    // every column = variable

    for (i, constraint) in remapped_constraints.iter().enumerate() {
        for (v, col_i) in &constraint.a {
            a_mat.push((i, *col_i, to_32(v.to_bytes_le())));
        }
        for (v, col_i) in &constraint.b {
            b_mat.push((i, *col_i, to_32(v.to_bytes_le())));
        }
        for (v, col_i) in &constraint.c {
            c_mat.push((i, *col_i, to_32(v.to_bytes_le())));
        }
    }

    let inst = Instance::new(num_cons, num_vars, num_inputs, &a_mat, &b_mat, &c_mat);
    if let Err(e) = inst {
        panic!("error building instance: {:?}", e);
    }
    let inst = inst.unwrap();

    let assignment_vars = VarsAssignment::new(&vars).unwrap();

    // create an InputsAssignment
    let inputs = vec![Scalar::ZERO.to_bytes(); num_inputs];
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
