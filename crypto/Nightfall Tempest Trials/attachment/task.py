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
