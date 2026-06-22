// Package stark implements the in-circuit RISC0 STARK verifier layers (Merkle, FRI,
// DEEP-ALI) over BLS12-381, consuming an identity_bls seal. Hashing uses the validated
// native poseidon_bls transcript; see go/hash/poseidon_bls and go/STARK_VERIFY_SPEC.md.
package stark

import (
	"github.com/consensys/gnark/frontend"

	pbls "github.com/pitcon/stark-to-snark-bls/go/hash/poseidon_bls"
)

// muxBits selects vals[index] where index = sum(bits[i]*2^i), via a binary select tree.
// len(vals) must equal 2^len(bits). bits are LE.
func muxBits(api frontend.API, bits []frontend.Variable, vals []frontend.Variable) frontend.Variable {
	cur := vals
	for _, b := range bits {
		next := make([]frontend.Variable, len(cur)/2)
		for i := range next {
			next[i] = api.Select(b, cur[2*i+1], cur[2*i])
		}
		cur = next
	}
	return cur[0]
}

// MerkleRoot folds the committed top row of `top_size` digests up to the tree root, exactly
// per risc0 verify/merkle.rs `MerkleTreeVerifier::new`: the root is at virtual index 1, with
// the children of virtual index i at 2i and 2i+1, so it is the standard bottom-up binary
// hash_pair fold over adjacent pairs. `top` must have a power-of-two length. This root is what
// the STARK driver commits to the Fiat-Shamir transcript for each register/check group.
func MerkleRoot(api frontend.API, top []frontend.Variable) frontend.Variable {
	level := top
	for len(level) > 1 {
		next := make([]frontend.Variable, len(level)/2)
		for i := range next {
			next[i] = pbls.HashPair(api, level[2*i], level[2*i+1])
		}
		level = next
	}
	return level[0]
}

// MerkleVerify reconstructs the leaf-to-top-row hash for a query at position `pos` and
// asserts it matches the committed top row, exactly per risc0 verify/merkle.rs `verify`:
//
//	cur = hash_elem_slice(leaf)
//	idx = pos + row_size
//	while idx >= 2*top_size: low_bit=idx&1; idx/=2;
//	    cur = low_bit==1 ? hash_pair(sib,cur) : hash_pair(cur,sib)
//	assert cur == top[idx - top_size]
//
// nbits = log2(row_size). The low len(siblings) bits of pos drive the fold (siblings given
// leaf-up), the remaining high bits index the top row. leaf holds col_size native BabyBear
// values; siblings and top hold digests as native BLS-Fr Variables.
//
// RISC0 calls is_digest_valid on each sibling/top digest (checking the 32-byte encoding decodes to
// a canonical Fr < r). That check is unnecessary here: siblings/top are BLS-Fr `frontend.Variable`s,
// already canonical field elements by construction - the byte-encoding ambiguity it guards against
// does not exist when the digest is carried as an Fr wire.
func MerkleVerify(api frontend.API, pos frontend.Variable, nbits int,
	leaf, siblings, top []frontend.Variable) {
	leafHash := pbls.HashElemSlice(api, leaf)
	MerkleVerifyFromLeafHash(api, pos, nbits, leafHash, siblings, top)
}

// MerkleVerifyFromLeafHash is MerkleVerify with the leaf already hashed: it folds the
// sibling path up to the top row and asserts the result equals the committed top-row entry
// selected by the high position bits. Separated so it can be validated directly against a
// real RISC0 Merkle opening (leaf hash + path + top row dumped from verify/merkle.rs).
func MerkleVerifyFromLeafHash(api frontend.API, pos frontend.Variable, nbits int,
	leafHash frontend.Variable, siblings, top []frontend.Variable) {

	bits := api.ToBinary(pos, nbits)
	cur := leafHash
	for k := 0; k < len(siblings); k++ {
		lowBit := bits[k]
		// low_bit==1 => cur is the right child: hash_pair(sibling, cur).
		left := api.Select(lowBit, siblings[k], cur)
		right := api.Select(lowBit, cur, siblings[k])
		cur = pbls.HashPair(api, left, right)
	}
	sel := muxBits(api, bits[len(siblings):], top)
	api.AssertIsEqual(cur, sel)
}
