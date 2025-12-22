from pwn import *
import numpy as np
from hashlib import sha256, md5
import sys

# --- Configuration ---
HOST = 'instance.penguin.0ops.sjtu.cn'
PORT = 18588
# context.log_level = 'debug'

def solve_pow(r):
    r.recvuntil(b"sha256(")
    challenge = r.recvuntil(b" +", drop=True).decode()
    r.recvuntil(b"starts with ")
    zeros_str = r.recvline().strip().decode()
    difficulty = len(zeros_str)
    
    print(f"[*] Solving PoW: sha256({challenge} + ???) -> {difficulty} zeros")
    
    for i in range(100000000):
        suffix = str(i)
        if sha256((challenge + suffix).encode()).hexdigest().startswith('0' * difficulty):
            r.sendlineafter(b"answer: ", suffix.encode())
            print(f"[+] PoW Solved: {suffix}")
            return
    print("[-] PoW failed")
    exit()

def get_power_metric(vector):
    """
    METRIC V5: Power Sum (Sum of u^60)
    
    This acts as a "Soft Max". It strictly filters for values extremely close to 1.0.
    
    - Bit 1 (Random): u ~ Uniform[0,1].
      Expected Sum = 140 * integral(x^60) = 140/61 ≈ 2.3.
      Standard Deviation is low. Rarely exceeds 6.0.
      
    - Bit 0 (Signal): 
      Valid items have u ≈ 1.0. So u^60 ≈ 1.0.
      Noise items contribute ≈ 0.
      If we have K valid items (even if K is small, like 7), Score ≈ K.
      
    - Separation:
      Random ≈ 2.3 (Max ~5.5)
      Signal ≈ 7+ (Min ~6.5)
      
    This separates the "tail" of the distribution much better than counting.
    """
    total_power = 0
    window = 5
    
    for i in range(window, len(vector)):
        # 1. Recover seed (Assume Bit 0)
        seed_src = str(vector[i-window:i])
        seed_hash = md5(seed_src.encode()).hexdigest()
        seed_int = int(seed_hash, 16)
        
        # 2. Generate local random
        local_rng = np.random.default_rng(seed_int)
        us = local_rng.random(20000)
        
        # 3. Get u value
        chosen_index = vector[i]
        u_val = us[chosen_index]
        
        # 4. Power Sum
        total_power += u_val ** 60
            
    return total_power

def main():
    while True:
        try:
            r = remote(HOST, PORT)
            solve_pow(r)
            r.recvuntil(b"game")
            
            for round_num in range(200):
                r.recvuntil(b"Vector:  ")
                v_str = r.recvline().strip().decode()
                vector = eval(v_str)
                
                # Calculate Power Metric
                score = get_power_metric(vector)
                
                # Threshold: 6.0
                # Bit 1 usually scores < 4.0.
                # Bit 0 usually scores > 8.0 (even with high noise).
                prediction = 0 if score > 6.0 else 1
                
                print(f"[*] Round {round_num+1}/200: PowerScore {score:.2f} -> Predict: {prediction}")
                r.sendline(str(prediction).encode())
                
                # Optional: Check if we survived (server closes conn on fail)
                # This helps debugging but slows down slightly
                
            print("\n[!!!] FINISHED! Flag incoming...")
            r.interactive()
            break
            
        except EOFError:
            print("[-] Wrong Answer / Disconnected. Retrying...")
            r.close()
            continue
        except Exception as e:
            print(f"[-] Error: {e}")
            r.close()
            continue

if __name__ == "__main__":
    main()