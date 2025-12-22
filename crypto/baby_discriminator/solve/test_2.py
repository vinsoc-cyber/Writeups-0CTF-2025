from pwn import *
import numpy as np
from hashlib import sha256, md5
import sys

# --- Configuration ---
HOST = 'instance.penguin.0ops.sjtu.cn'
PORT = 18588
context.log_level = 'info'

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

def get_robust_metric(vector):
    """
    METRIC V4: Đếm số lượng u > 0.75
    
    Phân tích thống kê:
    - Bit 1 (Random): Kỳ vọng 140 * 0.25 = 35. 
      Độ lệch chuẩn (Sigma) ≈ 5. 
      99% trường hợp sẽ nhỏ hơn 35 + 3*5 = 50. Thực tế thường < 46.
      
    - Bit 0 (Signal): Là hỗn hợp của tín hiệu sạch (u ~ 1.0) và nhiễu.
      Ngay cả trong trường hợp xấu (chỉ còn 20 window sạch), metric vẫn cao:
      Score ≈ 20 (sạch) + 120 * 0.25 (nhiễu) = 20 + 30 = 50.
      Trường hợp trung bình, Score thường > 60.
    """
    count = 0
    window = 5
    
    for i in range(window, len(vector)):
        # 1. Recover seed (giả định Bit 0)
        seed_src = str(vector[i-window:i])
        seed_hash = md5(seed_src.encode()).hexdigest()
        seed_int = int(seed_hash, 16)
        
        # 2. Tạo số ngẫu nhiên cục bộ
        local_rng = np.random.default_rng(seed_int)
        us = local_rng.random(20000)
        
        # 3. Lấy giá trị u
        chosen_index = vector[i]
        u_val = us[chosen_index]
        
        # 4. Kiểm tra ngưỡng thấp hơn (0.75) để lấy mẫu rộng hơn
        if u_val > 0.75:
            count += 1
            
    return count

def main():
    while True: # Auto-retry nếu mất kết nối
        try:
            r = remote(HOST, PORT)
            solve_pow(r)
            r.recvuntil(b"game")
            
            for round_num in range(200):
                r.recvuntil(b"Vector:  ")
                v_str = r.recvline().strip().decode()
                vector = eval(v_str)
                
                # Tính điểm dựa trên số lượng phần tử > 0.75
                val_count = get_robust_metric(vector)
                
                # Threshold quyết định: 46
                # Đây là ranh giới an toàn nhất giữa Nhiễu (~35) và Tín hiệu yếu (~50+)
                prediction = 0 if val_count >= 46 else 1
                
                print(f"[*] Round {round_num+1}/200: Score {val_count} -> Predict: {prediction}")
                r.sendline(str(prediction).encode())
                
                # Đọc phản hồi để xem có sai không (optional)
                # line = r.recvline(timeout=0.5)
                # if line and b"Wrong" in line:
                #     print(f"[-] Sai ở round {round_num+1}")
                #     break
                
            print("\n[!!!] FINISHED! Flag incoming...")
            r.interactive()
            break
            
        except EOFError:
            print("[-] Disconnected/Wrong Answer. Retrying...")
            r.close()
            continue
        except Exception as e:
            print(f"[-] Error: {e}")
            return

if __name__ == "__main__":
    main()