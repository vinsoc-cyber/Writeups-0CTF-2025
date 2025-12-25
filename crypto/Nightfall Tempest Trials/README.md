# Nightfall Tempest Trials (Crypto)
task.py
```python
from random import randint
from secret import flag
from Crypto.Cipher import AES
from hashlib import sha256
import ctypes
import os
import re


def capture_c_stdout(fn, *args):
    libc = ctypes.CDLL(None)
    libc.fflush(None)
    r_fd, w_fd = os.pipe()
    saved_fd = os.dup(1)
    os.dup2(w_fd, 1)
    os.close(w_fd)
    try:
        fn(*args)
        libc.fflush(None)
    finally:
        os.dup2(saved_fd, 1)
        os.close(saved_fd)
    out = os.read(r_fd, 1 << 20)
    os.close(r_fd)
    return out.decode()


def parse_leaks_from_output(output):
    blocks = re.findall(r"leak\s*=\s*\[([^\]]*?)\]", output, flags=re.DOTALL | re.MULTILINE)
    leaks = []
    for block in blocks:
        vals = re.split(r"[,\s]+", block.strip())
        leaks.append([int(x) for x in vals if x])
    return leaks


K = 12
PK_BYTES = K * 384 + 32
SK_BUF_BYTES = 2 * K * 384 + 96
SK_BYTES = K * 384
DELTAs = [240, 430, 600, 75, 70, 88, 99]
NS_PREFIX = "pqcrystals_kyber1024_ref_"
LIB_PATH = "./kyber/ref/lib/libpqcrystals_kyber1024_ref.so"
kyber_lib = ctypes.CDLL(LIB_PATH)

pk_buf = ctypes.create_string_buffer(PK_BYTES)
sk_buf = ctypes.create_string_buffer(SK_BUF_BYTES)
getattr(kyber_lib, NS_PREFIX + "keypair").argtypes = [ctypes.c_void_p, ctypes.c_void_p]
out = capture_c_stdout(getattr(kyber_lib, NS_PREFIX + "keypair"), pk_buf, sk_buf)
raw_leaks = parse_leaks_from_output(out)
leaks = raw_leaks[:K]
leaks = [
    [
        leaki + randint(-DELTAs[idx // 256], DELTAs[idx // 256])
        for idx, leaki in enumerate(leak)
    ]
    for leak in leaks
]
key = sha256(sk_buf.raw[:SK_BYTES]).digest()
pad = 16 - len(flag) % 16
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(flag + bytes([pad]) * pad)

print(f"pk = {pk_buf.raw[:PK_BYTES].hex()}")
print(f"leaks = {leaks}")
print(f"ct = {ct.hex()}")
print(f"iv = {iv.hex()}")
```
## Challenge Overview
- Patched Kyber1024 keygen with a non-standard vector length \(K = 12\) (so \(\text{PK\_BYTES} = 12 \times 384 + 32 = 4640\)).
- `ref/ntt.c` is patched to print every NTT stage, leaking \(7 \times 256 = 1792\) values per polynomial (see `attachment/ntt.patch`).
- `task.py` keeps only the first \(K\) leak blocks (secret polys), adds bounded noise per stage \(\Delta = [240, 430, 600, 75, 70, 88, 99]\), hashes the packed NTT-domain secret to derive an AES-CBC key, and prints `pk`, noisy `leaks`, `ct`, and `iv`.
- Goal: recover the exact NTT-domain secret bytes despite noise and decrypt the ciphertext in `attachment/output.txt`.

## Leakage Model
Each NTT butterfly operates as
\[
t = \zeta \cdot v,\qquad
a = u + t,\qquad
b = u - t,
\]
where arithmetic is modulo \(q = 3329\). The patched code leaks \(a', b'\) for every stage with
\[
|a' - a|,\ |b' - b| \le \Delta_s
\]
using the stage-specific \(\Delta_s\) above. Inputs of the first stage are small (\(\eta_1 = 2 \Rightarrow u,v \in \{-2,-1,0,1,2\}\)), giving a strong anchor for reversing the transform.

## Stage-Wise Reconstruction
- **Allowed residue sets:** For every observed value \(o_{s,i}\) at stage \(s\), build \(S_{s,i} = \{(o_{s,i} + d) \bmod q \mid d \in [-\Delta_s,\Delta_s]\}\).
- **Reverse butterflies:** Starting from the last stage (\(\text{len}=2\)) and moving backward through lengths \(4,8,16,32,64\), solve for predecessor residues using
  \[
  u = \tfrac{A+B}{2},\qquad v = \tfrac{(A-B)\,\zeta^{-1}}{2},
  \]
  keeping only solutions consistent with \(S_{s-1}\) (implemented in `reverse_stage` in `crypto/Nightfall Tempest Trials/solve/solve.py`).
- **First stage constraint:** At \(\text{len}=128\), additionally intersect with the small-coefficient set \(\{0, \pm1, \pm2\}\) (`reverse_final_small`).
- **Consistency check:** For indices that remain ambiguous, enumerate the small cartesian product, forward NTT them (`ntt_stages`) and keep only vectors matching all noisy bounds. Each polynomial ends up with a tiny candidate set of packed NTT outputs (`poly_tobytes`).

## Recovering the Key
1. Enumerate one candidate chunk per polynomial (12 total) and concatenate to form \( \text{SK\_BYTES} = 12 \times 384\).
2. Derive \(k = \mathrm{SHA256}(\text{sk\_bytes})\) and attempt AES-CBC decryption with the provided IV.
3. Stop when padding is valid and plaintext starts with `0ctf{}`.

The search space is small enough that a direct product enumeration succeeds quickly.

## PoC
```python
#!/usr/bin/env python3
import re, ast, itertools, hashlib, math
from Crypto.Cipher import AES

# ------------------------
# Kyber constants
# ------------------------
Q = 3329
QINV = 62209
RINV = 169                 # (2^16)^(-1) mod Q
INV2 = pow(2, -1, Q)

K = 12                      # patched
DELTAS = [240, 430, 600, 75, 70, 88, 99]

# η1 = 2 => coefficients in [-2,2]
ALLOWED = {0, 1, 2, Q-1, Q-2}

# zetas from Kyber ref ntt.c
ZETAS_RAW = [
-1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
 -171,   622,  1577,   182,   962, -1202, -1474,  1468,
  573, -1325,   264,   383,  -829,  1458, -1602,  -130,
 -681,  1017,   732,   608, -1542,   411,  -205, -1571,
 1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
  516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
 -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
 -398,   961, -1508,  -725,   448, -1065,   677, -1275,
-1103,   430,   555,   843, -1251,   871,  1550,   105,
  422,   587,   177,  -235,  -291,  -460,  1574,  1653,
 -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
-1590,   644,  -872,   349,   418,   329,  -156,   -75,
  817,  1097,   603,   610,  1322, -1285, -1465,   384,
-1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
-1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
 -108,  -308,   996,   991,   958, -1460,  1522,  1628
]

# Convert zetas to normal-domain values (Montgomery factor removed)
ZETAS_EFF = [(z % Q) * RINV % Q for z in ZETAS_RAW]

# ------------------------
# Montgomery reduce (signed int16 behavior)
# ------------------------
def montgomery_reduce(a):
    u = (a * QINV) & 0xFFFF
    if u >= 0x8000:
        u -= 0x10000
    t = a - u * Q
    return t >> 16

def fqmul(a, b):
    return montgomery_reduce(a * b)

def to_signed(x):
    x %= Q
    return x if x <= Q//2 else x - Q

# ------------------------
# Forward NTT stages (signed like C int16)
# ------------------------
def ntt_stages(inp):
    r = [to_signed(x) for x in inp]
    stages = []
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            z = ZETAS_RAW[k]
            k += 1
            for j in range(start, start + length):
                t = fqmul(z, r[j + length])
                r[j + length] = r[j] - t
                r[j] = r[j] + t
        stages.append(r[:])
        length //= 2
    return stages

def stage_match(stages, obs):
    for s in range(7):
        delta = DELTAS[s]
        for i in range(256):
            if abs(stages[s][i] - obs[s][i]) > delta:
                return False
    return True

# ------------------------
# Reverse-stage helpers (residue constraints)
# ------------------------
def allowed_residue_sets(obs_stage, delta):
    return [set((x % Q) for x in range(o - delta, o + delta + 1)) for o in obs_stage]

# stage ordering
LENS = [128, 64, 32, 16, 8, 4, 2]
kstart = {}
k = 1
for L in LENS:
    kstart[L] = k
    k += 256 // (2 * L)

invz_by_L = {}
for L in LENS:
    ks = kstart[L]
    nb = 256 // (2 * L)
    invz_by_L[L] = [pow(ZETAS_EFF[ks + b], -1, Q) for b in range(nb)]

def reverse_stage(cand_out, allowed_prev, L):
    cand_in = [set() for _ in range(256)]
    nb = 256 // (2 * L)
    invzs = invz_by_L[L]
    for b in range(nb):
        invz = invzs[b]
        start = b * 2 * L
        for j in range(start, start + L):
            SA = cand_out[j]
            SB = cand_out[j + L]
            allowA = allowed_prev[j]
            allowB = allowed_prev[j + L]

            outA, outB = set(), set()
            for A in SA:
                for B in SB:
                    a = (A + B) * INV2 % Q
                    if a not in allowA:
                        continue
                    t = (A - B) * INV2 % Q
                    bb = t * invz % Q
                    if bb not in allowB:
                        continue
                    outA.add(a)
                    outB.add(bb)

            if not outA or not outB:
                return None

            cand_in[j] = outA
            cand_in[j + L] = outB

    return cand_in

def reverse_final_small(cand_out):
    cand_in = [set() for _ in range(256)]
    invz = invz_by_L[128][0]
    for j in range(128):
        SA = cand_out[j]
        SB = cand_out[j + 128]
        outA, outB = set(), set()
        for A in SA:
            for B in SB:
                a = (A + B) * INV2 % Q
                t = (A - B) * INV2 % Q
                bb = t * invz % Q
                if a in ALLOWED and bb in ALLOWED:
                    outA.add(a)
                    outB.add(bb)
        if not outA or not outB:
            return None
        cand_in[j] = outA
        cand_in[j + 128] = outB
    return cand_in

# ------------------------
# Packing poly_tobytes (Kyber format)
# ------------------------
def poly_tobytes(coeffs):
    out = bytearray(384)
    for i in range(0, 256, 2):
        t0 = coeffs[i] % Q
        t1 = coeffs[i + 1] % Q
        j = 3 * (i // 2)
        out[j] = t0 & 0xFF
        out[j + 1] = ((t0 >> 8) | ((t1 & 0x0F) << 4)) & 0xFF
        out[j + 2] = (t1 >> 4) & 0xFF
    return bytes(out)

def unpad_pkcs7(x):
    pad = x[-1]
    if pad < 1 or pad > 16:
        return None
    if x[-pad:] != bytes([pad]) * pad:
        return None
    return x[:-pad]

# ------------------------
# Main solve
# ------------------------
def main(fn):
    txt = open(fn, "r").read()

    pk_hex = re.search(r"pk = ([0-9a-f]+)", txt).group(1)
    ct_hex = re.search(r"ct = ([0-9a-f]+)", txt).group(1)
    iv_hex = re.search(r"iv = ([0-9a-f]+)", txt).group(1)

    leaks = ast.literal_eval(re.search(r"leaks = (\[\[.*\]\])\nct", txt, re.S).group(1))
    ct = bytes.fromhex(ct_hex)
    iv = bytes.fromhex(iv_hex)

    # enumerate candidate chunks for each poly
    poly_chunks = []
    for leak in leaks:
        obs = [leak[i*256:(i+1)*256] for i in range(7)]
        allowed_sets = [allowed_residue_sets(obs[s], DELTAS[s]) for s in range(7)]

        cand = [[(obs[6][i] + d) % Q for d in range(-DELTAS[6], DELTAS[6] + 1)] for i in range(256)]

        # reverse from stage 7 -> stage 1
        for (L, prev_stage) in [(2,5),(4,4),(8,3),(16,2),(32,1),(64,0)]:
            cand = reverse_stage(cand, allowed_sets[prev_stage], L)
            if cand is None:
                raise RuntimeError("reverse failed")

        # reverse final stage to small coeff input
        cand0 = reverse_final_small(cand)
        if cand0 is None:
            raise RuntimeError("final reverse failed")

        amb = [i for i,s in enumerate(cand0) if len(s) > 1]
        base = [next(iter(s)) if len(s)==1 else 0 for s in cand0]

        sols = []
        for values in itertools.product(*[sorted(cand0[i]) for i in amb]):
            arr = base[:]
            for idx,val in zip(amb, values):
                arr[idx] = val
            st = ntt_stages(arr)
            if stage_match(st, obs):
                ntt_out = [x % Q for x in st[-1]]
                sols.append(poly_tobytes(ntt_out))

        poly_chunks.append(sols)

    # brute across all polys
    sizes = [len(x) for x in poly_chunks]
    for idxs in itertools.product(*[range(s) for s in sizes]):
        sk = b''.join(poly_chunks[i][idxs[i]] for i in range(K))
        key = hashlib.sha256(sk).digest()
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
        msg = unpad_pkcs7(pt)
        if msg and msg.startswith(b"0ctf{"):
            print(msg.decode())
            return

    print("not found")

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv)>1 else "output.txt")
```
0ctf{7n_the_Twilight_0f_br0k3n_ReAlm5_mY_deSt1ny_rise5_froM_7he_v0id.}
```
