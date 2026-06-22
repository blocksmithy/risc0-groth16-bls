//! Validates the native Rust verifier against the REAL artifacts produced by the gnark prover
//! (`groth16bls prove` over the identity_bls seal). gnark's own `groth16.Verify` accepts this
//! proof; an independent Rust verifier that ALSO accepts it - and rejects tampered / wrong-public
//! variants - demonstrates the equation is mirrored correctly (not merely accept-everything).

use groth16_bls_verify::{parse_proof, parse_public, parse_vk, verify, verify_cardano, Error};

const VK: &[u8] = include_bytes!("../testdata/vk.cardano.bin");
const PROOF: &[u8] = include_bytes!("../testdata/proof.cardano.bin");
const PUBLIC: &[u8] = include_bytes!("../testdata/public.cardano.bin");

#[test]
fn accepts_real_proof() {
    verify_cardano(VK, PROOF, PUBLIC).expect("real gnark proof must verify");
}

#[test]
fn structure_is_as_pinned() {
    let vk = parse_vk(VK).unwrap();
    assert_eq!(vk.ic.len(), 7, "len(K)=7 (one + 5 public + 1 commitment)");
    assert_eq!(vk.commitment_keys.len(), 1, "nC=1");
    assert_eq!(vk.committed[0].len(), 0, "PublicAndCommitmentCommitted=[[]]");
    let proof = parse_proof(PROOF).unwrap();
    assert_eq!(proof.commitments.len(), 1);
    let public = parse_public(PUBLIC).unwrap();
    assert_eq!(public.len(), 5, "risc0 5-input schema");
}

#[test]
fn rejects_tampered_proof() {
    let mut bad = PROOF.to_vec();
    bad[80] ^= 0x01; // inside b_g2
    match verify_cardano(VK, &bad, PUBLIC) {
        Err(Error::BadPoint(_)) | Err(Error::PairingCheckFailed) | Err(Error::CommitmentMismatch) => {}
        other => panic!("tampered proof must be rejected, got {other:?}"),
    }
}

#[test]
fn rejects_wrong_public() {
    let vk = parse_vk(VK).unwrap();
    let proof = parse_proof(PROOF).unwrap();
    let mut public = parse_public(PUBLIC).unwrap();
    public[0] += bls12_381::Scalar::from(1u64); // flip one public input
    assert_eq!(
        verify(&vk, &proof, &public),
        Err(Error::PairingCheckFailed),
        "a wrong public input must fail the pairing (public binding is real)"
    );
}
