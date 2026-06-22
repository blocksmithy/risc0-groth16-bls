//! Native Rust verifier for the BLS12-381 Groth16 (+ one bsb22 Pedersen commitment) proofs that
//! the stark-to-snark-bls gnark prover produces. It mirrors gnark's `backend/groth16/bls12-381`
//! `Verify` byte-for-byte:
//!
//! 1. subgroup checks on every proof point (via `from_compressed`);
//! 2. commitment challenge  h_j = fr.Hash( commitment_j ‖ committed_publics , "bsb22-commitment" )
//!    where fr.Hash = reduce_be( expand_message_xmd(SHA256, ·, L=48) ) and the committed-publics
//!    list is empty for our circuit (`PublicAndCommitmentCommitted = [[]]`);
//! 3. PoK pairing (nC=1, fold = identity):  e(C, GSigmaNeg) · e(pok, G) == 1 ;
//! 4. kSum = K[0] + Σ publicExt[i]·K[i+1] + C   (publicExt = public ‖ [h_0]);
//! 5. main pairing:  e(A,B) · e(C, −δ) · e(kSum, −γ) == e(α, β).
//!
//! Inputs are the Cardano-v2 byte format (Zcash/IETF compressed points), which the zkcrypto
//! `bls12_381` crate decodes natively. The on-chain Aiken verifier checks the same equation.

use bls12_381::{
    multi_miller_loop, pairing, G1Affine, G1Projective, G2Affine, G2Prepared, Gt, Scalar,
};
use group::Curve;
use sha2::{Digest, Sha256};

/// fr.Hash domain separator for the per-commitment challenge (gnark `constraint.CommitmentDst`).
const COMMITMENT_DST: &[u8] = b"bsb22-commitment";
/// L from gnark `fr.Hash`: L = 16 + ceil(255/8)+0 ... = 16 + 32 = 48 bytes of XMD output per element.
const FR_HASH_L: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated(&'static str),
    BadPoint(&'static str),
    BadScalar(&'static str),
    CommitmentMismatch,
    UnsupportedShape(String),
    PokCheckFailed,
    PairingCheckFailed,
}

/// Parsed Cardano-v2 verifying key.
pub struct VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic: Vec<G1Affine>,
    /// One per commitment (nC). Empty if the proof has no commitment.
    pub commitment_keys: Vec<CommitmentKey>,
    /// committed[j] = 1-indexed public-wire positions commitment j binds (often empty).
    pub committed: Vec<Vec<u32>>,
}

pub struct CommitmentKey {
    pub g: G2Affine,
    pub g_sigma_neg: G2Affine,
}

/// Parsed Cardano-v2 proof. `commitments_uncompressed[j]` is the exact 96-byte gnark hash input.
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
    pub commitments: Vec<G1Affine>,
    pub commitments_uncompressed: Vec<[u8; 96]>,
    pub commitment_pok: G1Affine,
}

// ---------------------------------------------------------------------------
// byte readers
// ---------------------------------------------------------------------------

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Error> {
        if self.i + n > self.b.len() {
            return Err(Error::Truncated(what));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u32(&mut self, what: &'static str) -> Result<u32, Error> {
        let s = self.take(4, what)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn g1(&mut self, what: &'static str) -> Result<G1Affine, Error> {
        let s = self.take(48, what)?;
        let mut buf = [0u8; 48];
        buf.copy_from_slice(s);
        Option::<G1Affine>::from(G1Affine::from_compressed(&buf)).ok_or(Error::BadPoint(what))
    }
    fn g2(&mut self, what: &'static str) -> Result<G2Affine, Error> {
        let s = self.take(96, what)?;
        let mut buf = [0u8; 96];
        buf.copy_from_slice(s);
        Option::<G2Affine>::from(G2Affine::from_compressed(&buf)).ok_or(Error::BadPoint(what))
    }
    fn done(&self) -> bool {
        self.i == self.b.len()
    }
}

pub fn parse_vk(bytes: &[u8]) -> Result<VerifyingKey, Error> {
    let mut r = Reader::new(bytes);
    let alpha_g1 = r.g1("alpha_g1")?;
    let beta_g2 = r.g2("beta_g2")?;
    let gamma_g2 = r.g2("gamma_g2")?;
    let delta_g2 = r.g2("delta_g2")?;
    let ic_count = r.u32("ic_count")? as usize;
    let mut ic = Vec::with_capacity(ic_count);
    for _ in 0..ic_count {
        ic.push(r.g1("ic")?);
    }
    let n_c = r.u32("nC")? as usize;
    let mut commitment_keys = Vec::with_capacity(n_c);
    let mut committed = Vec::with_capacity(n_c);
    for _ in 0..n_c {
        let g = r.g2("pedersen_G")?;
        let g_sigma_neg = r.g2("pedersen_GSigmaNeg")?;
        let n_idx = r.u32("committed_count")? as usize;
        let mut idxs = Vec::with_capacity(n_idx);
        for _ in 0..n_idx {
            idxs.push(r.u32("committed_index")?);
        }
        commitment_keys.push(CommitmentKey { g, g_sigma_neg });
        committed.push(idxs);
    }
    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
        commitment_keys,
        committed,
    })
}

pub fn parse_proof(bytes: &[u8]) -> Result<Proof, Error> {
    let mut r = Reader::new(bytes);
    let a = r.g1("a_g1")?;
    let b = r.g2("b_g2")?;
    let c = r.g1("c_g1")?;
    let n_c = r.u32("nC")? as usize;
    let mut commitments = Vec::with_capacity(n_c);
    let mut commitments_uncompressed = Vec::with_capacity(n_c);
    for _ in 0..n_c {
        let cm = r.g1("commitment")?;
        let unc = r.take(96, "commitment_uncompressed")?;
        let mut buf = [0u8; 96];
        buf.copy_from_slice(unc);
        // Cross-check the uncompressed copy decodes to the same point (gnark hashes the uncompressed).
        let from_unc: Option<G1Affine> = G1Affine::from_uncompressed(&buf).into();
        match from_unc {
            Some(p) if p == cm => {}
            _ => return Err(Error::CommitmentMismatch),
        }
        commitments.push(cm);
        commitments_uncompressed.push(buf);
    }
    let commitment_pok = r.g1("commitment_pok")?;
    Ok(Proof {
        a,
        b,
        c,
        commitments,
        commitments_uncompressed,
        commitment_pok,
    })
}

/// parse_public reads the Cardano-v2 public.bin (u32 n_inner ‖ u32 n_limbs ‖ scalars(32B BE)).
/// Requires n_limbs == 1 (our native BLS scalars); returns the n_inner field scalars.
pub fn parse_public(bytes: &[u8]) -> Result<Vec<Scalar>, Error> {
    let mut r = Reader::new(bytes);
    let n_inner = r.u32("n_inner_pub")? as usize;
    let n_limbs = r.u32("n_limbs_per_scalar")?;
    if n_limbs != 1 {
        return Err(Error::UnsupportedShape(format!(
            "n_limbs_per_scalar = {n_limbs}, native verifier requires 1"
        )));
    }
    let mut out = Vec::with_capacity(n_inner);
    for _ in 0..n_inner {
        let s = r.take(32, "public scalar")?;
        out.push(scalar_from_be(s)?);
    }
    if !r.done() {
        return Err(Error::Truncated("public.bin has trailing bytes"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// hash-to-field (gnark fr.Hash) and verification
// ---------------------------------------------------------------------------

/// expand_message_xmd(SHA-256) per RFC 9380, byte-identical to gnark-crypto `hash.ExpandMsgXmd`.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    const B_IN_BYTES: usize = 32; // SHA-256 output
    const S_IN_BYTES: usize = 64; // SHA-256 block
    let ell = (len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES;
    assert!(ell <= 255 && dst.len() <= 255);
    let size_domain = dst.len() as u8;

    let mut h = Sha256::new();
    h.update([0u8; S_IN_BYTES]);
    h.update(msg);
    h.update([(len_in_bytes >> 8) as u8, len_in_bytes as u8, 0u8]);
    h.update(dst);
    h.update([size_domain]);
    let b0 = h.finalize();

    let mut h = Sha256::new();
    h.update(b0);
    h.update([1u8]);
    h.update(dst);
    h.update([size_domain]);
    let mut b_prev = h.finalize();

    let mut res = vec![0u8; len_in_bytes];
    let first = B_IN_BYTES.min(len_in_bytes);
    res[..first].copy_from_slice(&b_prev[..first]);

    for i in 2..=ell {
        let mut strxor = [0u8; B_IN_BYTES];
        for j in 0..B_IN_BYTES {
            strxor[j] = b0[j] ^ b_prev[j];
        }
        let mut h = Sha256::new();
        h.update(strxor);
        h.update([i as u8]);
        h.update(dst);
        h.update([size_domain]);
        b_prev = h.finalize();
        let start = B_IN_BYTES * (i - 1);
        let end = (B_IN_BYTES * i).min(len_in_bytes);
        res[start..end].copy_from_slice(&b_prev[..end - start]);
    }
    res
}

/// reduce a big-endian byte string mod r into a Scalar (gnark `SetBytes` then reduce).
fn reduce_be(bytes: &[u8]) -> Scalar {
    let two56 = Scalar::from(256u64);
    let mut acc = Scalar::zero();
    for &b in bytes {
        acc = acc * two56 + Scalar::from(b as u64);
    }
    acc
}

/// scalar_from_be parses a canonical 32-byte big-endian field element (gnark `fr.Marshal`).
fn scalar_from_be(be: &[u8]) -> Result<Scalar, Error> {
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    Option::<Scalar>::from(Scalar::from_bytes(&le)).ok_or(Error::BadScalar("public input >= r"))
}

/// fr.Hash(msg, dst, 1)[0] = reduce_be( expand_message_xmd(SHA256, msg, dst, L) ).
fn fr_hash(msg: &[u8], dst: &[u8]) -> Scalar {
    reduce_be(&expand_message_xmd(msg, dst, FR_HASH_L))
}

/// verify checks a parsed proof against a VK and the public inputs (the risc0 5-input schema),
/// returning Ok(()) iff gnark's verification equation holds.
pub fn verify(vk: &VerifyingKey, proof: &Proof, public: &[Scalar]) -> Result<(), Error> {
    let n_c = vk.commitment_keys.len();
    if proof.commitments.len() != n_c || vk.committed.len() != n_c {
        return Err(Error::UnsupportedShape("commitment count mismatch".into()));
    }
    // len(K) = (nbPublic+1) + nC  ⇒  expected public = len(ic) - 1 - nC.
    let expected_public = vk
        .ic
        .len()
        .checked_sub(1 + n_c)
        .ok_or(Error::UnsupportedShape("ic too small".into()))?;
    if public.len() != expected_public {
        return Err(Error::UnsupportedShape(format!(
            "got {} public inputs, expected {}",
            public.len(),
            expected_public
        )));
    }

    // (2) per-commitment challenge h_j, appended to the public vector.
    let mut public_ext = public.to_vec();
    for j in 0..n_c {
        let mut prehash = Vec::with_capacity(96 + 32 * vk.committed[j].len());
        prehash.extend_from_slice(&proof.commitments_uncompressed[j]);
        for &idx in &vk.committed[j] {
            // 1-indexed into the ORIGINAL public vector (gnark: publicWitness[idx-1]).
            let p = public
                .get((idx as usize).wrapping_sub(1))
                .ok_or(Error::UnsupportedShape("committed index out of range".into()))?;
            // serialize the scalar big-endian (gnark fr.Marshal).
            let le = p.to_bytes();
            let mut be = [0u8; 32];
            for i in 0..32 {
                be[i] = le[31 - i];
            }
            prehash.extend_from_slice(&be);
        }
        public_ext.push(fr_hash(&prehash, COMMITMENT_DST));
    }

    // (3) PoK pairing for each commitment. nC=1 ⇒ fold is identity, challenge unused:
    //     e(C_j, GSigmaNeg_j) · e(pok, G_j) == 1.  (For nC>1 a folded form is needed.)
    if n_c == 1 {
        let terms = [
            (&proof.commitments[0], &G2Prepared::from(vk.commitment_keys[0].g_sigma_neg)),
            (&proof.commitment_pok, &G2Prepared::from(vk.commitment_keys[0].g)),
        ];
        let pok = multi_miller_loop(&terms).final_exponentiation();
        if pok != Gt::identity() {
            return Err(Error::PokCheckFailed);
        }
    } else if n_c > 1 {
        return Err(Error::UnsupportedShape(format!(
            "nC={n_c} PoK folding not implemented (our circuit is nC=1)"
        )));
    }

    // (4) kSum = K[0] + Σ public_ext[i]·K[i+1] + Σ C_j.
    let mut k_sum = G1Projective::from(vk.ic[0]);
    for (i, s) in public_ext.iter().enumerate() {
        k_sum += G1Projective::from(vk.ic[i + 1]) * s;
    }
    for cm in &proof.commitments {
        k_sum += G1Projective::from(*cm);
    }
    let k_sum = k_sum.to_affine();

    // (5) e(A,B) · e(C,−δ) · e(kSum,−γ) == e(α,β).
    let neg_delta = G2Prepared::from(-vk.delta_g2);
    let neg_gamma = G2Prepared::from(-vk.gamma_g2);
    let b_prep = G2Prepared::from(proof.b);
    let lhs = multi_miller_loop(&[
        (&proof.a, &b_prep),
        (&proof.c, &neg_delta),
        (&k_sum, &neg_gamma),
    ])
    .final_exponentiation();
    let rhs = pairing(&vk.alpha_g1, &vk.beta_g2);
    if lhs != rhs {
        return Err(Error::PairingCheckFailed);
    }
    Ok(())
}

/// verify_cardano parses the Cardano-v2 vk/proof/public byte blobs and verifies.
pub fn verify_cardano(vk_bytes: &[u8], proof_bytes: &[u8], public_bytes: &[u8]) -> Result<(), Error> {
    let vk = parse_vk(vk_bytes)?;
    let proof = parse_proof(proof_bytes)?;
    let public = parse_public(public_bytes)?;
    verify(&vk, &proof, &public)
}
