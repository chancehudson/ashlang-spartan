use libspartan::ComputationCommitment;
use libspartan::SNARK;
extern crate libspartan;
extern crate merlin;
use libspartan::Assignment;
use libspartan::InputsAssignment;
use libspartan::Instance;
use libspartan::SNARKGens;
use libspartan::VarsAssignment;

pub type SpartanConfig = (
    usize,
    usize,
    usize,
    usize,
    Instance,
    VarsAssignment,
    InputsAssignment,
);

// contains the data necessary to
// verify a proof
pub struct SpartanProof {
    pub snark: SNARK,
    pub comm: ComputationCommitment,
    pub gens: SNARKGens,
    pub inputs: Assignment,
}
