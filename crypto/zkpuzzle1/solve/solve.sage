from sage.all import *
from pwn import *
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import queue

# Optimal anomalous prime with smooth p-1
p = 57896044618658097711785492504344103875898860550630966617243435388673817800277
inv24 = inverse_mod(24, p)

SMALL_PRIMES = list(primes(100000))

def trial_divide(n):
    """Fast trial division"""
    factors = []
    for pr in SMALL_PRIMES:
        if pr * pr > n:
            break
        while n % pr == 0:
            factors.append(pr)
            n //= pr
    return factors, n

def balance_factors(all_factors):
    """Balance factors into 3 buckets, return (a,b,c) or None if too large"""
    all_factors.sort(reverse=True)
    buckets = [1, 1, 1]
    
    for f in all_factors:
        min_idx = min(range(3), key=lambda i: buckets[i].bit_length())
        buckets[min_idx] *= f
        # Early termination if bucket gets too large
        if buckets[min_idx].bit_length() > 198:
            return None
    
    return tuple(buckets)

def try_factor_candidate(num):
    """Try to factor a candidate number, return factors list or None"""
    if num <= 0:
        return None
    
    factors, remainder = trial_divide(num)
    
    if remainder == 1:
        return factors
    elif remainder.bit_length() <= 170:
        try:
            for (fac, exp) in factor(remainder, proof=False):
                if fac.bit_length() > 190:
                    return None
                factors.extend([fac] * exp)
            return factors
        except:
            return None
    elif is_pseudoprime(remainder):
        return None
    else:
        try:
            for (fac, exp) in factor(remainder, proof=False, limit=5*10**6):
                if fac.bit_length() > 190:
                    return None
                factors.extend([fac] * exp)
            return factors
        except:
            return None

def compute_witness_from_factors(factors):
    """Given factors of 24abc, compute witness (w0,w1,w2,w3)"""
    if factors is None:
        return None
    
    if any(f.bit_length() > 190 for f in factors):
        return None
    
    result = balance_factors(factors)
    if result is None:
        return None
    
    a, b, c = result
    w = (a + b + c, a - b - c, -a + b - c, -a - b + c)
    
    if all(abs(wi).bit_length() < 200 for wi in w):
        return w
    return None

def get_witness_fast(r, k, max_l=3000):
    """Find witness with extended search"""
    base_pos = (r * pow(k, 3, p) * inv24) % p
    base_neg = ((-r % p) * pow(k, 3, p) * inv24) % p
    
    # Interleave positive and negative, prioritize small l
    for l in range(max_l):
        for base in [base_pos, base_neg]:
            num = base + l * p
            factors = try_factor_candidate(num)
            w = compute_witness_from_factors(factors)
            if w is not None:
                return w
    
    return None

class PredictiveFactorer:
    """Precompute factorizations for upcoming rounds"""
    
    def __init__(self, num_workers=4, lookahead=10):
        self.executor = ThreadPoolExecutor(max_workers=num_workers)
        self.lookahead = lookahead
        self.cache = {}  # (r, k) -> witness
        self.lock = Lock()
        self.pending = set()
        self.base_r = None
        
    def _compute_and_cache(self, r, k):
        """Worker function to compute and cache witness"""
        w = get_witness_fast(r, k)
        with self.lock:
            self.cache[(r, k)] = w
            self.pending.discard((r, k))
        return w
    
    def submit_task(self, r, k):
        """Submit a factorization task"""
        with self.lock:
            if (r, k) not in self.cache and (r, k) not in self.pending:
                self.pending.add((r, k))
                self.executor.submit(self._compute_and_cache, r, k)
    
    def get_witness(self, r, k):
        """Get witness, computing if not cached"""
        with self.lock:
            if (r, k) in self.cache:
                return self.cache.pop((r, k))
        
        # Not cached, compute synchronously
        return get_witness_fast(r, k)
    
    def cleanup_old(self, current_r):
        """Remove old cached entries"""
        with self.lock:
            old_keys = [key for key in self.cache if key[0] < current_r]
            for key in old_keys:
                del self.cache[key]

def main():
    host, port = 'instance.penguin.0ops.sjtu.cn', 18529
    
    io = remote(host, port)
    io.recvuntil(b"two primes: ")
    io.sendline(f"{p} {p}".encode())
    
    factorer = PredictiveFactorer(num_workers=4, lookahead=5)
    
    success = 0
    r_value = None
    k_history = []  # Store recent k values to look for patterns
    
    for round_idx in range(1000):
        try:
            line = io.recvuntil(b"witness: ").decode()
            r = int(line.split("Prove for ")[1].split(",")[0])
            k = int(line.split("mask: ")[1].split(",")[0])
            
            if r_value is None:
                r_value = r
            
            # Get witness (may be precomputed)
            w = factorer.get_witness(r, k)
            
            # Submit future tasks if we know r increments
            # We don't know future k values, but we can prepare
            factorer.cleanup_old(r)
            
            if w:
                io.sendline(str(w).encode())
                io.recvline()  # "pass the bit check"
                resp = io.recvline().decode().strip()
                if "Good" in resp:
                    success += 1
            else:
                print(f"Round {round_idx}: FAILED (r={r}, k={k})")
                # Try a fallback: w=(1,1,-1,-1) gives sum=0, won't work but satisfies format
                io.sendline(b"(1,1,-1,-1)")
                io.recvline()
                io.recvline()
            
            print(f"Round {round_idx}: success={success}/{round_idx+1}")
                
        except EOFError:
            print("Connection closed")
            break
    
    print(f"Final: {success}/1000")
    io.interactive()

if __name__ == "__main__":
    main()