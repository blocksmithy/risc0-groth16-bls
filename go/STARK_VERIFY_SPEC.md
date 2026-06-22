# RISC0 STARK Verifier - in-circuit specification (identity_bls, Poseidon-over-BLS12-381-Fr)

Specification of the RISC0 succinct-receipt verifier (`risc0_zkp::verify`) as implemented by this
circuit, derived from risc0 v3.0.5 (`github.com/blocksmithy/risc0`, tag `v3.0.5-bls.1`). Trace field is
BabyBear `p=0x78000001`, extension `Fp4 = F_p[X]/(X^4+11)`. Transcript hash = Poseidon over
BLS12-381 Fr (t=3 sponge), already implemented in `go/hash/poseidon_bls/`.

## 0. Driver order (`zkp/src/verify/mod.rs:435-518`)
1. `Verifier::new`
2. commit `PROOF_SYSTEM_INFO` (`b"RISC0_STARK:v1__"`) then `CIRCUIT_INFO` (`b"RECURSION:rev1v1"`), each via `hash_elem_slice(encode())` (16 BabyBear elems, 1/byte) then `commit`.
3. `read_slice_with_po2(OUTPUT_SIZE=32)`: read 33 BabyBear elems (32 globals `out` + 1 `po2`), hash+commit all 33. po2 must = 18 for identity_bls -> `tot_cycles=2^18=262144`.
4. `verify_group(CODE)` (col=23) -> commit code_root; then `check_code(po2, code_root)` (caller/zkvm: control-id membership vs BLS_IDENTITY_CONTROL_ID - outside zkp).
5. `verify_group(DATA)` (col=128) -> commit data_root.
6. `read_rng(MIX_SIZE=20)`: draw 20 `random_elem()` (accum mix). Nothing read from seal.
7. `verify_group(ACCUM)` (col=12) -> commit accum_root.
8. `verify_validity(poly_ext)` (§4).
9. `iop().verify_complete()` (seal fully consumed).

Constants (`zkp/src/lib.rs`): QUERIES=50, INV_RATE=4, FRI_FOLD=16, FRI_FOLD_PO2=4,
FRI_MIN_DEGREE=256, ZK_CYCLES=1024. Register groups: ACCUM=0, CODE=1, DATA=2.
Recursion (`recursion/src/info.rs`): OUTPUT_SIZE=32, MIX_SIZE=20. (po2=18 is the identity_bls
program's cycle count, set via `read_slice_with_po2`/`tot_cycles=1<<po2` - not a named info.rs constant.)

## 1. Seal = Vec<u32>, consumed positionally (no length prefixes)
`ReadIOP` forward cursor (`verify/read_iop.rs`). Digest = 8×u32 = 1 Fr (LE). Readers:
`read_u32s(n)`, `read_field_elem_slice(n)` (n words, each validated `< P`),
`read_pod_slice(n)` (raw digests), `commit(d)`->`rng.mix(d)` (ONLY mutation of FS state).
Order: `[33 globals/po2] · [code top digests] · [data top] · [accum top] · [check top] ·
[659 Fp4 U-coeffs = 2636 words] · per-FRI-round[top digests] · [final-layer coeffs] ·
50× query openings (interleaved in fri_verify)`.

## 2. Transcript / Fiat-Shamir (byte-exact) - `poseidon_bls/mod.rs`
Sponge state `[Fr;3]` zero-init. cells[0]=capacity, cells[1..2]=rate.
- `mix(d)`: `cells[1] += digest_to_fr(d); permute`. (ADDS into cells[1].)
- `random_bits(b)`: `source=cells[2]; permute; extract b LSBs of source` (LSB-first).
- `random_elem()`: `source=cells[2]; permute; accumulate 160 low bits as Σ bit_i·2^i in BabyBear` (powers of 2 reduced mod p - NOT integer-mod-p; replicate exactly).
- `random_ext_elem()`: 4× random_elem -> Fp4. (= 4 permutations.)
- `unpadded_hash(elems)`: pack BabyBear into Fr by base-p limbs, 8 elems/limb into cells[1] then cells[2]; when idx==3 permute & zero rate; final partial block permute; out=cells[0].
- `hash_pair(a,b)`: `cells=[0,a,b]; permute; out=cells[0]`. (Zeroes capacity; does NOT add.)
- `hash_ext_elem_slice`: flatten each Fp4 -> 4 subelems, then unpadded_hash.

Event order (each commit=1 permute; draws permute as noted):
1 PROOF_SYSTEM_INFO mix · 2 CIRCUIT_INFO mix · 3 globals(33) mix · 4 code_root mix ·
5 data_root mix · 6 accum mix draw 20×random_elem · 7 accum_root mix ·
8 poly_mix=random_ext_elem (4) · 9 check_root mix · 10 z=random_ext_elem (4) ·
11 hash_ext_elem_slice(coeff_u) mix · 12 fri batch mix=random_ext_elem (4) ·
13 per FRI round: commit(round_root) THEN round.mix=random_ext_elem(4) ·
14 commit(hash_elem_slice(final_coeffs)) · 15 per query (50×): pos=random_bits(20).
Merkle path recomputation does NOT commit (only compares to committed root).

## 3. Merkle (`zkp/src/merkle.rs`, `verify/merkle.rs`)
`MerkleTreeParams(row_size, col_size, queries=50)`: row_size=domain=INV_RATE*tot_cycles=2^20
for main trees; layers=log2(row_size); top_layer=max i with 2^i≤50 -> top_size=32.
`MerkleTreeVerifier::new`: read top_size=32 digests, hash up to root via hash_pair, commit root.
`verify(idx)`: read col_size BabyBear leaf elems -> `hash_elem_slice`; ascend reading 1 sibling
digest per level, `hash_pair(low,high)` per `idx%2`, until idx≥2*top_size; compare to stored top.
Path len/query = layers−top_layer.

## 4. DEEP-ALI / constraint check (`verify/mod.rs:267-355`)
Taps (`recursion/src/taps.rs:4524-4533`): tap_size=643, group_begin=[0,16,39,643]
(accum 0..16, code 16..39, data 39..643), reg_count=163, combos_count=5,
combo_begin=[0,1,3,9,15,20], combo_taps=[0, 0,1, 0,1,2,3,4,68, 0,1,2,7,15,16, 0,2,7,15,16],
tot_combo_backs=20. group_size: accum=12, code=23, data=128.
Steps: read coeff_u=659 Fp4 (643+CHECK_SIZE=16); check_root Merkle (col=16) before z draw;
eval_u (len 643): eval each register poly at x=z·back_one^back, back_one=ROU_REV[po2];
result = `poly_ext(poly_mix, eval_u, [out,mix]).tot`; reconstruct check from last 16 coeff_u
(remap [0,2,1,3]); assert `check·((3z)^tot_cycles − 1) == result` (C(z)==Q(z)·Z_H(z)).

**poly_ext** (`recursion/src/poly_ext.rs`, DEF ret=1228, 12359 steps). Op counts:
Const 284, Get 669, GetGlobal 52, Add 4061, Sub 1385, Mul 4679, True 1, AndEqz 1076, AndCond 152.
Semantics (`adapter.rs:306-358`): Get(t)=eval_u[t]; GetGlobal(b,off)=args[b][off] (b0=out,b1=mix)->Fp4;
Add/Sub/Mul Fp4; True={tot:0,mul:1}; AndEqz(c,inner)={tot:c.tot+c.mul·inner, mul:c.mul·mix};
AndCond(c,cond,inner)={tot:c.tot+cond·inner.tot·c.mul, mul:c.mul·inner.mul}; result=mix_vars[ret].tot.
POLY_MIX_POWERS: 158 distinct powers (`info.rs:33-46`).
`fri_eval_taps` (`mod.rs:217-258`): per-query DEEP combine over 5 combos + check slot,
tap_mix_pows len reg_count=163, check_mix_pows len 16.

## 5. FRI (`verify/fri.rs`) - po2=18: orig_domain=2^20, 3 fold rounds
`random_bits(20)` per query. Round loop while degree>256: degree 262144->16384->1024->(64 stop).
Round trees: r0 row=2^16 path=11, r1 row=2^12 path=7, r2 row=2^8 path=3; col_size=64 each
(FRI_FOLD·EXT_SIZE). Final layer: read 256 BabyBear (=64 Fp4); gen=ROU_FWD[8].
Per query: pos=random_bits(20); goal=inner(pos) (open accum/code/data/check rows at pos,
x=gen.pow(pos), fri_eval_taps); per round verify_query: quot=pos/round.domain, group=pos%round.domain,
open 64-elem row->16 Fp4, assert data_ext[quot]==goal, inv_wk=ROU_REV[log2(16·domain)].pow(group),
interpolate_ntt+bit_reverse (16-pt inverse NTT), goal=poly_eval(data, round.mix·inv_wk), pos=group.
Final: x=gen.pow(pos), rebuild poly_buf from final_coeffs (column-major Fp4),
assert poly_eval(poly_buf, lift(x))==goal (z∉coset / final check).

## 6. Constants (`core/field/baby_bear.rs`)
P=2013265921; Fp4: X^4+11, BETA=11, NBETA=P−11, EXT_SIZE=4; mul `baby_bear.rs:762-766`; inv `:460-491`.
ROU_FWD[0..27] (`:184-189`): [1,2013265920,284861408,1801542727,567209306,740045640,918899846,
1881002012,1453957774,65325759,1538055801,515192888,483885487,157393079,1695124103,2005211659,
1540072241,88064245,1542985445,1269900459,1461624142,825701067,682402162,1311873874,1164520853,
352275361,18769,137].
ROU_REV[0..27] (`:192-197`): [1,2013265920,1728404513,1592366214,196396260,1253260071,72041623,
1091445674,145223211,1446820157,1030796471,2010749425,1827366325,1239938613,246299276,596347512,
1893145354,246074437,1525739923,1194341128,1463599021,704606912,95395244,15672543,647517488,
584175179,137728885,749463956]. (canonical ints; Montgomery-encode yourself.)

## 7. Sizing (po2=18)
tot_cycles=262144, domain=2^20. cols: accum=12,code=23,data=128,check=16. tap_size=643,reg_count=163.
U-coeffs=659 Fp4=2636 words. Main trees layers=20 top=32 path=15. FRI 3 rounds (paths 11/7/3, col 64).
Final 256 BabyBear. 50 queries. Transcript ~94 squeeze permutations + ~4,400 Merkle leaf/node
permutations (50×~88) - Merkle recomputation dominates Poseidon cost.
