#!/usr/bin/env python3
import re
import struct
import hashlib
import sys

def solve_pow(challenge_hex: str) -> str:
    """
    Compute nonce such that SHA256(challenge || nonce) has 24 leading zero bits,
    i.e. digest[0:3] == b'\\x00\\x00\\x00'.
    Brute-force a 4-byte nonce efficiently with a reusable buffer.
    """
    challenge = bytes.fromhex(challenge_hex)
    if len(challenge) != 16:
        raise ValueError("Expected 16-byte challenge")

    buf = bytearray(challenge + b"\x00" * 4)  # 20 bytes total
    mv = memoryview(buf)

    i = 0
    attempts = 0
    while True:
        # little-endian vs big-endian doesn't matter; just be consistent
        struct.pack_into("<I", buf, 16, i)
        d = hashlib.sha256(mv).digest()
        attempts += 1

        if d[0] == 0 and d[1] == 0 and d[2] == 0:
            print(f"Found nonce after {attempts:,} attempts")
            return buf[16:20].hex()
        i = (i + 1) & 0xFFFFFFFF

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 compute_nonce.py <challenge_hex>")
        print("Example: python3 compute_nonce.py 1234567890abcdef1234567890abcdef")
        sys.exit(1)

    challenge_hex = sys.argv[1]

    # Validate hex input
    if not re.match(r'^[0-9a-fA-F]+$', challenge_hex):
        print("Error: Challenge must be a valid hexadecimal string")
        sys.exit(1)

    if len(challenge_hex) != 32:
        print(f"Error: Challenge must be 32 hex characters (16 bytes), got {len(challenge_hex)}")
        sys.exit(1)

    print(f"Computing nonce for challenge: {challenge_hex}")
    print("Looking for SHA256 digest with 24 leading zero bits...")

    try:
        nonce_hex = solve_pow(challenge_hex)
        print(f"\nNonce (hex): {nonce_hex}")

        # Verify the solution
        challenge = bytes.fromhex(challenge_hex)
        nonce = bytes.fromhex(nonce_hex)
        digest = hashlib.sha256(challenge + nonce).digest()
        print(f"SHA256({challenge_hex} || {nonce_hex}) = {digest.hex()}")
        print(f"First 3 bytes: {digest[:3].hex()} (should be 000000)")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()