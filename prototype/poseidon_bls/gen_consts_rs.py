#!/usr/bin/env python3
"""Generate risc0 poseidon_bls/consts.rs from the vendored canonical hadeshash
reference (poseidonperm_x5_255_3.sage). Mirrors poseidon_254/consts.rs format:
decimal-string constants parsed by Fr::from_str_vartime, generator 7, little-endian.
Reproducible: same input -> same output. No sage required."""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SAGE = os.path.join(HERE, "reference_x5_255_3.sage")
OUT  = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "consts.rs")

src = open(SAGE).read()
prime = int(re.search(r"prime = (0x[0-9a-fA-F]+)", src).group(1), 16)
R_F = int(re.search(r"^R_F = (\d+)", src, re.M).group(1))
R_P = int(re.search(r"^R_P = (\d+)", src, re.M).group(1))
t   = int(re.search(r"^t = (\d+)", src, re.M).group(1))

BLS_FR = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
assert prime == BLS_FR, "reference prime is not BLS12-381 Fr"
assert (t, R_F, R_P) == (3, 8, 57), (t, R_F, R_P)

rc  = [int(x, 16) for x in eval(re.search(r"round_constants = (\[[^\]]*\])", src).group(1))]
mds = [int(x, 16) for row in eval(re.search(r"MDS_matrix = (\[\[.*?\]\])", src, re.S).group(1)) for x in row]
assert len(rc) == (R_F + R_P) * t == 195
assert len(mds) == t * t == 9

HALF_FULL = R_F // 2  # 4

def arr(name, vals, decl):
    out = [f"const {name}: [&str; {decl}] = ["]
    out += [f'    "{v}",' for v in vals]
    out.append("];")
    return "\n".join(out)

body = f'''// Copyright 2026 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Poseidon parameters for the BLS12-381 scalar field: width t = 3, S-box x^5,
// 4 full + 57 partial + 4 full rounds, security level M = 128.
//
// Round constants and MDS are the canonical published reference values, taken from
//   https://extgit.iaik.tugraz.at/krypto/hadeshash
//   commit b5434fd2b2785926dd1dd386efbef167da57c064, code/poseidonperm_x5_255_3.sage
// This mirrors how poseidon_254 sourced poseidon_params_n254_t3_alpha8_M128.txt. The values
// are verified against that reference by a mechanical re-extraction check.

use std::sync::OnceLock;

use ff::PrimeField;

#[derive(PrimeField)]
#[PrimeFieldModulus = "{prime}"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Fr([u64; 4]);

pub const CELLS: usize = {t};
pub const ROUNDS_HALF_FULL: usize = {HALF_FULL};
pub const ROUNDS_PARTIAL: usize = {R_P};
pub const ROUNDS_TOT: usize = 2 * ROUNDS_HALF_FULL + ROUNDS_PARTIAL;

{arr("ROUND_CONSTANTS_STR", rc, "ROUNDS_TOT * CELLS")}

{arr("MDS_STR", mds, "CELLS * CELLS")}

pub fn round_constants() -> &'static Vec<Fr> {{
    static ONCE: OnceLock<Vec<Fr>> = OnceLock::new();
    ONCE.get_or_init(|| {{
        ROUND_CONSTANTS_STR
            .iter()
            .map(|x| Fr::from_str_vartime(x).unwrap())
            .collect()
    }})
}}

pub fn mds() -> &'static Vec<Fr> {{
    static ONCE: OnceLock<Vec<Fr>> = OnceLock::new();
    ONCE.get_or_init(|| {{
        MDS_STR
            .iter()
            .map(|x| Fr::from_str_vartime(x).unwrap())
            .collect()
    }})
}}
'''

open(OUT, "w").write(body)
print(f"wrote {OUT}: prime=BLS12-381 Fr, t={t}, R_F={R_F}, R_P={R_P}, "
      f"#rc={len(rc)}, #mds={len(mds)}")
