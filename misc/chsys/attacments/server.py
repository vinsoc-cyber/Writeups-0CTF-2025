import os
import socket
import subprocess
import hashlib
import secrets

HOST = "0.0.0.0"
PORT = 10001
POW_DIFFICULTY = 24
SPAWN_SCRIPT = "/root/spawn.sh"

def check_pow(challenge: bytes, nonce_hex: bytes, difficulty_bits: int) -> bool:
    try:
        nonce = bytes.fromhex(nonce_hex.strip().decode())
    except Exception:
        return False
    h = hashlib.sha256(challenge + nonce).digest()
    bits = ''.join(f'{b:08b}' for b in h)
    return bits.startswith('0' * difficulty_bits)

def handle_client(conn: socket.socket, addr):
    with conn:
        f = conn.makefile('rwb', buffering=0)
        challenge = secrets.token_bytes(16)
        f.write(b"Proof-of-Work: find nonce such that\n")
        f.write(b"SHA256(challenge || nonce) has %d leading zero bits\n" % POW_DIFFICULTY)
        f.write(b"challenge (hex): " + challenge.hex().encode() + b"\n")
        f.write(b"nonce (hex): ")
        nonce_hex = f.readline()
        if not nonce_hex:
            return
        if not check_pow(challenge, nonce_hex, POW_DIFFICULTY):
            f.write(b"Invalid PoW.\n")
            return

        # At this point, keep `conn` open and hand it to spawn script
        # Get a stable FD number for the socket
        fd = conn.fileno()

        # Important: ensure fd is inheritable (Python 3.4+ usually is, but be explicit)
        os.set_inheritable(fd, True)

        conn_id = secrets.token_hex(8)

        # spawn.sh expects: spawn.sh <ID> <FD>
        # and inside it, it will use that FD.
        proc = subprocess.Popen(
            [SPAWN_SCRIPT, conn_id, str(fd)],
            close_fds=False  # keep fd open for child
        )

        # Once spawned, this process should not use conn anymore;
        # the jail's /env_manager is talking to it directly.
        # Just wait for child to finish.
        proc.wait()

def main():
    with socket.create_server((HOST, PORT), reuse_port=True) as s:
        while True:
            conn, addr = s.accept()
            pid = os.fork()
            if pid == 0:
                s.close()
                handle_client(conn, addr)
                os._exit(0)
            else:
                conn.close()

if __name__ == "__main__":
    main()
