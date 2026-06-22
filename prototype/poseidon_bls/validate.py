#!/usr/bin/env python3
"""Validate the poseidon_bls construction (poseidon_254 structure + x5_255_3 constants)
against the canonical hadeshash known-answer vector. Pure-python, offline."""
import re, sys

SAGE = ""+__import__("os").path.dirname(__file__)+"/reference_x5_255_3.sage"
src = open(SAGE).read()

# Pull the published constants straight out of the reference file (valid python literals).
prime = int(re.search(r"prime = (0x[0-9a-fA-F]+)", src).group(1), 16)
t   = int(re.search(r"^t = (\d+)", src, re.M).group(1))
R_F = int(re.search(r"^R_F = (\d+)", src, re.M).group(1))
R_P = int(re.search(r"^R_P = (\d+)", src, re.M).group(1))

rc_literal  = re.search(r"round_constants = (\[[^\]]*\])", src).group(1)
mds_literal = re.search(r"MDS_matrix = (\[\[.*?\]\])", src, re.S).group(1)
round_constants = [int(x, 16) for x in eval(rc_literal)]
MDS = [[int(x, 16) for x in row] for row in eval(mds_literal)]

assert len(round_constants) == (R_F + R_P) * t, len(round_constants)
assert len(MDS) == t and all(len(r) == t for r in MDS)

BLS_FR = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
print(f"prime == BLS12-381 Fr : {prime == BLS_FR}")
print(f"t={t}  R_F={R_F}  R_P={R_P}  alpha=5  #rc={len(round_constants)}  MDS={t}x{t}")

def sbox(x):                       # x^5, mirrors poseidon_254 sbox but alpha=5
    x2 = x * x % prime
    x4 = x2 * x2 % prime
    return x4 * x % prime

def matmul(state):                 # M . v  (row-major, no transpose) == poseidon_254 multiply_by_mds
    return [sum(MDS[i][j] * state[j] for j in range(t)) % prime for i in range(t)]

def perm(state):
    state = list(state); c = 0
    half = R_F // 2
    for _ in range(half):          # full rounds
        state = [(state[i] + round_constants[c+i]) % prime for i in range(t)]; c += t
        state = [sbox(x) for x in state]
        state = matmul(state)
    for _ in range(R_P):           # partial rounds (sbox on cell 0 only)
        state = [(state[i] + round_constants[c+i]) % prime for i in range(t)]; c += t
        state[0] = sbox(state[0])
        state = matmul(state)
    for _ in range(half):          # full rounds
        state = [(state[i] + round_constants[c+i]) % prime for i in range(t)]; c += t
        state = [sbox(x) for x in state]
        state = matmul(state)
    return state

out = perm([0, 1, 2])
expected = [0x28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a,
            0x51f3e312c95343a896cfd8945ea82ba956c1118ce9b9859b6ea56637b4b1ddc4,
            0x3b2b69139b235626a0bfb56c9527ae66a7bf486ad8c11c14d1da0c69bbe0f79a]
print("\nperm([0,1,2]):")
for o in out: print(f"  {hex(o)}")
ok = out == expected
print(f"\nMATCHES canonical test_vectors.txt golden vector: {ok}")
sys.exit(0 if ok else 1)
