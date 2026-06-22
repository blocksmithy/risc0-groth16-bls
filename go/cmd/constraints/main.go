// Command constraints compiles each in-circuit gadget and reports its R1CS constraint count,
// emitting constraints.txt (the checked-in regression file). Any unexplained
// delta, up or down, fails review. Deterministic: same source -> same counts.
package main

import (
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/rs/zerolog"

	bb "github.com/pitcon/stark-to-snark-bls/go/field/babybear"
	pbls "github.com/pitcon/stark-to-snark-bls/go/hash/poseidon_bls"
	"github.com/pitcon/stark-to-snark-bls/go/stark"
)

func init() { logger.Set(zerolog.Nop()) } // keep constraints.txt clean (counts only)

type permC struct{ In, Out [3]frontend.Variable }

func (c *permC) Define(api frontend.API) error {
	o := pbls.Permute(api, c.In)
	for i := range o {
		api.AssertIsEqual(o[i], c.Out[i])
	}
	return nil
}

type hashPairC struct{ A, B, Out frontend.Variable }

func (c *hashPairC) Define(api frontend.API) error {
	api.AssertIsEqual(pbls.HashPair(api, c.A, c.B), c.Out)
	return nil
}

type hashElem16C struct {
	In  [16]frontend.Variable
	Out frontend.Variable
}

func (c *hashElem16C) Define(api frontend.API) error {
	api.AssertIsEqual(pbls.HashElemSlice(api, c.In[:]), c.Out)
	return nil
}

type spongeElemC struct{ Out frontend.Variable }

func (c *spongeElemC) Define(api frontend.API) error {
	s := pbls.NewSponge()
	s.Mix(api, 7)
	api.AssertIsEqual(s.RandomElem(api), c.Out)
	return nil
}

type fp4MulC struct{ A, B, Out [4]emulated.Element[bb.Base] }

func (c *fp4MulC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	e := func(v *[4]emulated.Element[bb.Base]) bb.E4 {
		return bb.E4{C: [4]*bb.Elem{&v[0], &v[1], &v[2], &v[3]}}
	}
	f.E4AssertEq(f.E4Mul(e(&c.A), e(&c.B)), e(&c.Out))
	return nil
}

type fp4InvC struct{ A, Out [4]emulated.Element[bb.Base] }

func (c *fp4InvC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	e := func(v *[4]emulated.Element[bb.Base]) bb.E4 {
		return bb.E4{C: [4]*bb.Elem{&v[0], &v[1], &v[2], &v[3]}}
	}
	f.E4AssertEq(f.E4Inv(e(&c.A)), e(&c.Out))
	return nil
}

type polyEvalC struct {
	Coeffs [3][4]emulated.Element[bb.Base]
	X      [4]emulated.Element[bb.Base]
	Out    [4]emulated.Element[bb.Base]
}

func (c *polyEvalC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	e := func(v *[4]emulated.Element[bb.Base]) bb.E4 {
		return bb.E4{C: [4]*bb.Elem{&v[0], &v[1], &v[2], &v[3]}}
	}
	got := stark.PolyEval(f, []bb.E4{e(&c.Coeffs[0]), e(&c.Coeffs[1]), e(&c.Coeffs[2])}, e(&c.X))
	f.E4AssertEq(got, e(&c.Out))
	return nil
}

type friFoldC struct {
	Leaf  [64]emulated.Element[bb.Base]
	Mix   [4]emulated.Element[bb.Base]
	Group frontend.Variable
	Out   [4]emulated.Element[bb.Base]
}

func (c *friFoldC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	leaf := make([]*bb.Elem, 64)
	for i := range leaf {
		leaf[i] = &c.Leaf[i]
	}
	mix := bb.E4{C: [4]*bb.Elem{&c.Mix[0], &c.Mix[1], &c.Mix[2], &c.Mix[3]}}
	got := stark.FoldRound(api, f, leaf, c.Group, 16, mix, 20)
	f.E4AssertEq(got, bb.E4{C: [4]*bb.Elem{&c.Out[0], &c.Out[1], &c.Out[2], &c.Out[3]}})
	return nil
}

type canonC struct{ V frontend.Variable }

func (c *canonC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	f.AssertCanonical(c.V)
	return nil
}

type merkleC struct {
	Pos      frontend.Variable
	Leaf     []frontend.Variable
	Siblings []frontend.Variable
	Top      []frontend.Variable
	nbits    int
}

func (c *merkleC) Define(api frontend.API) error {
	stark.MerkleVerify(api, c.Pos, c.nbits, c.Leaf, c.Siblings, c.Top)
	return nil
}

type merkleRootC struct {
	Top  []frontend.Variable
	Root frontend.Variable
}

func (c *merkleRootC) Define(api frontend.API) error {
	api.AssertIsEqual(stark.MerkleRoot(api, c.Top), c.Root)
	return nil
}

func e4(v *[4]emulated.Element[bb.Base]) bb.E4 {
	return bb.E4{C: [4]*bb.Elem{&v[0], &v[1], &v[2], &v[3]}}
}

func ptrs(s []emulated.Element[bb.Base]) []*bb.Elem {
	out := make([]*bb.Elem, len(s))
	for i := range s {
		out[i] = &s[i]
	}
	return out
}

// DEEP-ALI (V1) gadgets.
type evalUC struct {
	CoeffU [2636]emulated.Element[bb.Base]
	Z      [4]emulated.Element[bb.Base]
	Out    [643][4]emulated.Element[bb.Base]
}

func (c *evalUC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	got := stark.EvalU(f, stark.CoeffUFromUCoeffs(f, ptrs(c.CoeffU[:])), e4(&c.Z))
	for i := range got {
		f.E4AssertEq(got[i], e4(&c.Out[i]))
	}
	return nil
}

type polyExtC struct {
	EvalU      [643][4]emulated.Element[bb.Base]
	PolyMix    [4]emulated.Element[bb.Base]
	GlobalsOut [32]emulated.Element[bb.Base]
	AccumMix   [20]emulated.Element[bb.Base]
	Out        [4]emulated.Element[bb.Base]
}

func (c *polyExtC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	evalU := make([]bb.E4, 643)
	for i := range evalU {
		evalU[i] = e4(&c.EvalU[i])
	}
	got := stark.PolyExt(f, e4(&c.PolyMix), evalU, ptrs(c.GlobalsOut[:]), ptrs(c.AccumMix[:]))
	f.E4AssertEq(got, e4(&c.Out))
	return nil
}

type checkC struct {
	CoeffU [2636]emulated.Element[bb.Base]
	Z      [4]emulated.Element[bb.Base]
	Out    [4]emulated.Element[bb.Base]
}

func (c *checkC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	got := stark.ComputeCheck(f, stark.CoeffUFromUCoeffs(f, ptrs(c.CoeffU[:])), e4(&c.Z), 18)
	f.E4AssertEq(got, e4(&c.Out))
	return nil
}

type friEvalC struct {
	CoeffU    [2636]emulated.Element[bb.Base]
	FriMix    [4]emulated.Element[bb.Base]
	Z         [4]emulated.Element[bb.Base]
	Pos0      frontend.Variable
	AccumLeaf [12]emulated.Element[bb.Base]
	CodeLeaf  [23]emulated.Element[bb.Base]
	DataLeaf  [128]emulated.Element[bb.Base]
	CheckLeaf [16]emulated.Element[bb.Base]
	Out       [4]emulated.Element[bb.Base]
}

func (c *friEvalC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	comboU, tapMixPows, checkMixPows := stark.ComboU(f, stark.CoeffUFromUCoeffs(f, ptrs(c.CoeffU[:])), e4(&c.FriMix))
	rows := [3][]*bb.Elem{ptrs(c.AccumLeaf[:]), ptrs(c.CodeLeaf[:]), ptrs(c.DataLeaf[:])}
	xBase := stark.DeepQueryX(f, api.ToBinary(c.Pos0, 20))
	got := stark.FriEvalTaps(f, comboU, ptrs(c.CheckLeaf[:]), xBase, e4(&c.Z), rows, tapMixPows, checkMixPows)
	f.E4AssertEq(got, e4(&c.Out))
	return nil
}

type ingestC struct {
	V   frontend.Variable
	Out emulated.Element[bb.Base]
}

func (c *ingestC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	_, el := f.IngestElem(c.V)
	f.AssertElemEq(el, &c.Out)
	return nil
}

type friQueryC struct {
	Pos0   frontend.Variable
	Goal0  [4]emulated.Element[bb.Base]
	Leaves [3][64]emulated.Element[bb.Base]
	Mixes  [3][4]emulated.Element[bb.Base]
	Final  [256]emulated.Element[bb.Base]
}

func (c *friQueryC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	var leaves [3][]*bb.Elem
	for r := 0; r < 3; r++ {
		leaves[r] = ptrs(c.Leaves[r][:])
	}
	var mixes [3]bb.E4
	for r := 0; r < 3; r++ {
		mixes[r] = e4(&c.Mixes[r])
	}
	stark.VerifyFRIQuery(api, f, c.Pos0, e4(&c.Goal0), leaves, mixes, ptrs(c.Final[:]))
	return nil
}

type validityDriverC struct {
	Globals  [33]frontend.Variable
	CodeTop  [32]frontend.Variable
	DataTop  [32]frontend.Variable
	AccumTop [32]frontend.Variable
	CheckTop [32]frontend.Variable
	UCoeffs  [2636]frontend.Variable
}

func (c *validityDriverC) Define(api frontend.API) error {
	f, err := bb.NewField(api)
	if err != nil {
		return err
	}
	stark.VerifyValidity(api, f, &stark.SealPrefixVars{
		Globals: c.Globals[:], CodeTop: c.CodeTop[:], DataTop: c.DataTop[:],
		AccumTop: c.AccumTop[:], CheckTop: c.CheckTop[:], UCoeffs: c.UCoeffs[:],
	})
	return nil
}

func count(name string, c frontend.Circuit) {
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile %s: %v\n", name, err)
		os.Exit(1)
	}
	fmt.Printf("%-40s %8d\n", name, ccs.GetNbConstraints())
}

func main() {
	fmt.Println("# R1CS constraint counts (BLS12-381). Regenerate: make constraints-report.")
	fmt.Println("# Full verifier stark.VerifyReceipt (validity + FRI + 5-input claim binding, 50 queries) = 4,577,317 R1CS")
	fmt.Println("# (~20s compile; run `COMPILE_RECEIPT=1 go run ./cmd/constraints` to re-measure).")
	fmt.Println("# gadget                                   r1cs")
	count("poseidon_bls.Permute (1 perm)", &permC{})
	count("poseidon_bls.HashPair", &hashPairC{})
	count("poseidon_bls.HashElemSlice (16 elems)", &hashElem16C{})
	count("poseidon_bls.Sponge.Mix+RandomElem", &spongeElemC{})
	count("babybear.E4Mul (1 Fp4 mul)", &fp4MulC{})
	count("babybear.E4Inv (1 Fp4 inverse)", &fp4InvC{})
	count("babybear.AssertCanonical", &canonC{})
	count("babybear.IngestElem (canonical + native<->emul bind)", &ingestC{})
	count("stark.MerkleVerify (2^20 tree, 15-fold)", &merkleC{
		nbits:    20,
		Leaf:     make([]frontend.Variable, 16),
		Siblings: make([]frontend.Variable, 15),
		Top:      make([]frontend.Variable, 32),
	})
	count("stark.MerkleRoot (top_size 32)", &merkleRootC{
		Top: make([]frontend.Variable, 32),
	})
	count("stark.PolyEval (Fp4, 3 coeffs)", &polyEvalC{})
	count("stark.FoldRound (FRI fold, 1 round)", &friFoldC{})
	count("stark.VerifyFRIQuery (full per-query FRI)", &friQueryC{})
	count("stark.EvalU (DEEP-ALI, 643 taps)", &evalUC{})
	count("stark.ComputeCheck (DEEP-ALI check poly)", &checkC{})
	count("stark.ComboU+FriEvalTaps (DEEP query, goal0)", &friEvalC{})
	count("stark.PolyExt (DEEP-ALI validity, 12.4k steps)", &polyExtC{})
	count("stark.VerifyValidity (driver: transcript+ingest+V1)", &validityDriverC{})
	if os.Getenv("COMPILE_RECEIPT") != "" {
		countFullReceipt() // full verifier (~20s) - gated; headline count recorded in constraints.txt
	}
}
