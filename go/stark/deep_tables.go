package stark

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// DEEP-ALI static circuit tables, dumped from the authoritative RISC0 source (recursion
// circuit `taps::TAPSET` + `poly_ext::DEF`) by the `dump_polyext_and_taps` test - see
// the pinned RISC0 fork. These are fixed circuit constants (they change only with the recursion circuit
// version, not per seal), embedded so the in-circuit verifier needs no external files.

//go:embed testdata/taps.json
var tapsJSON []byte

//go:embed testdata/polyext_def.json
var polyExtJSON []byte

// Reg is one tap register: its group (0=accum,1=code,2=data), column offset within the group,
// combo id, and the `back` cycle-offsets at which it is sampled (size = len(Backs)).
type Reg struct {
	Group  int   `json:"group"`
	Offset int   `json:"offset"`
	Combo  int   `json:"combo"`
	Size   int   `json:"size"`
	Backs  []int `json:"backs"`
}

// Taps is the recursion circuit's tap set (DEEP-ALI), mirroring risc0 zkp::taps::TapSet.
type Taps struct {
	TapSize       int      `json:"tap_size"`   // 643 = total taps across groups
	CheckSize     int      `json:"check_size"` // 16 = INV_RATE * EXT_SIZE
	CombosCount   int      `json:"combos_count"`
	RegCount      int      `json:"reg_count"`
	TotComboBacks int      `json:"tot_combo_backs"`
	ComboBegin    []int    `json:"combo_begin"` // combos_count+1 offsets into ComboTaps
	ComboTaps     []int    `json:"combo_taps"`  // per-combo `back` lists, concatenated
	GroupBegin    []int    `json:"group_begin"` // num_groups+1 offsets into the tap list
	GroupNames    []string `json:"group_names"`
	Regs          []Reg    `json:"regs"`
}

// PolyExtDef is the DEEP-ALI validity step program (risc0 adapter::PolyExtStepDef). Each entry of
// Block is a compact opcode array (tag, operands...) per the encoding in the Rust dumper:
//
//	0 Const(x)            1 ConstExt(a,b,c,d)   2 Get(tap)        3 GetGlobal(base,off)
//	4 Add(a,b)            5 Sub(a,b)            6 Mul(a,b)        7 True
//	8 AndEqz(chain,inner) 9 AndCond(chain,cond,inner)
//
// Operands index the fp-var bank (Const/ConstExt/Get/GetGlobal/Add/Sub/Mul/AndEqz.inner) or the
// mix-var bank (True/AndEqz/AndCond, and AndCond.inner) - the two banks grow independently in
// block order. Ret is the mix-var index whose `tot` is the program result.
type PolyExtDef struct {
	Ret   int     `json:"ret"`
	Block [][]int `json:"block"`
}

var (
	tapsTable  Taps
	polyExtDef PolyExtDef
)

func init() {
	if err := json.Unmarshal(tapsJSON, &tapsTable); err != nil {
		panic(fmt.Sprintf("deep: parsing taps.json: %v", err))
	}
	if err := json.Unmarshal(polyExtJSON, &polyExtDef); err != nil {
		panic(fmt.Sprintf("deep: parsing polyext_def.json: %v", err))
	}
	// Structural invariants (cheap, catch a corrupted/mismatched table at startup).
	if tapsTable.RegCount != len(tapsTable.Regs) || tapsTable.TapSize != 643 || tapsTable.CheckSize != 16 {
		panic(fmt.Sprintf("deep: taps table inconsistent: regs=%d reg_count=%d tap_size=%d check_size=%d",
			len(tapsTable.Regs), tapsTable.RegCount, tapsTable.TapSize, tapsTable.CheckSize))
	}
	sum := 0
	for _, r := range tapsTable.Regs {
		sum += r.Size
	}
	if sum != tapsTable.TapSize {
		panic(fmt.Sprintf("deep: sum of reg sizes %d != tap_size %d", sum, tapsTable.TapSize))
	}
	if len(polyExtDef.Block) == 0 || polyExtDef.Ret >= len(polyExtDef.Block) {
		panic(fmt.Sprintf("deep: poly_ext DEF malformed (ret=%d, block=%d)", polyExtDef.Ret, len(polyExtDef.Block)))
	}
}
