# ZKpuzzle1

task.sage
```python
from sage.all import EllipticCurve, Zmod, is_prime, randint, inverse_mod
from ast import literal_eval
from secret import flag

class proofSystem:
    def __init__(self, p1, p2):
        assert is_prime(p1) and is_prime(p2)
        assert p1.bit_length() == p2.bit_length() == 256
        self.E1 = EllipticCurve(Zmod(p1), [0, 137])
        self.E2 = EllipticCurve(Zmod(p2), [0, 137])

    def myrand(self, E1, E2):
        F = Zmod(E1.order())
        r = F.random_element()
        P = r * E2.gens()[0]
        x = P.x()
        return int(r * x) & (2**128 - 1)

    def verify(self, E, r, k, w):
        G = E.gens()[0]
        P = (r*k) * G
        Q = (w[0]**3 + w[1]**3 + w[2]**3 + w[3]**3) * inverse_mod(k**2, G.order()) * G
        return P.x() == Q.x()


def task():
    ROUND = 1000
    threshold = 999
    print("hello hello")
    p1, p2 = map(int, input("Enter two primes: ").split())

    proofsystem = proofSystem(p1, p2)
    print(f"You need to succese {threshold} times in {ROUND} rounds.")
    r = proofsystem.myrand(proofsystem.E1, proofsystem.E2)
    success = 0
    for _ in range(ROUND):
        k = proofsystem.myrand(proofsystem.E2, proofsystem.E1)
        w = literal_eval(input(f"Prove for {r}, this is your mask: {k}, now give me your witness: "))
        assert len(w) == 4
        assert max(wi.bit_length() for wi in w) < 200
        print("pass the bit check")
        if proofsystem.verify(proofsystem.E1, r, k, w) and proofsystem.verify(proofsystem.E2, r, k, w):
            print(f"Good!")
            success += 1
        r += 1


    if success > threshold:
        print("You are master of math!")
        print(flag)


if __name__ == "__main__":
    try:
        task()
    except Exception:
        exit()
```


## Summary
We need to clear 1000 rounds and only receive the flag if we succeed in 999 of them.

The success condition is satisfying both `verify(E, r, k, w)` calls for E1 and E2. Both curves have the form $y^2 = x^3 + 137 \ mod \ p$, and we are allowed to choose p.

## Exploit
There are two crucial parts in this challenge:
* Choosing p1, p2
* Choosing $w = (w_1, w_2, w_3, w_4)$ that satisfies `verify`

For the first part - choosing p1, p2 - the statement does not forbid p1 = p2, so we set p = p1 = p2 and need it to satisfy `myrand`
```python
return int(r * x) & (2**128 - 1)
```

If r is in the field mod E.order and x is in the field mod p, but p != E.order(), Sage will throw an error.

Therefore we choose p so that p1 = E2.order and vice versa.

Use this paper to find such a prime: https://arxiv.org/pdf/0912.1831 

```python
def find_prime_for_fixed_b(target_b, bits=256):
    print(f"[*] Targeting b = {target_b} with ~{bits} bits...")
    
    # Estimate starting y for the desired bit length
    target_y = int(math.sqrt(4/3) * (2**(bits//2)))
    
    # Ensure y is odd
    if target_y % 2 == 0:
        target_y += 1
    
    y = target_y
    attempts = 0
    
    while True:
        attempts += 1
        if attempts % 1000 == 0:
            print(f"    Checked {attempts} candidates...")

        # Generate candidate p from y
        p = Integer((3 * y**2 + 1) // 4)
        
        # Check if p is prime and exactly bits
        if p.is_prime() and p.bit_length() == bits:
            F = GF(p)
            E = EllipticCurve(F, [0, target_b])
            
            # Check if trace is 1
            if E.trace_of_frobenius() == 1:
                return p
        
        # Move to next candidate
        y += 2

# Find the prime
b_fixed = 137
p = find_prime_for_fixed_b(b_fixed, bits=256)
print(f"Found anomalous prime p: {p}")
```

Next we find w such that each component is < 200 bits and $(w_1^3 + w_2^3 + w_3^3 + w_4^3) = r k^3 \ mod \ orderE$.

Split the components as:
```bash 
w1 = a + b + c
w2 = a - b - c
w3 = -a + b - c
w4 = -a - b + c
``` 
Then the sum of cubes becomes 24abc, so the problem reduces to finding a, b, c that satisfy $24abc = r k^3 \ mod \ orderE \leftrightarrow abc = r k^3 24^{-1}\ mod \ orderE$.

From here we factor the right side and distribute the factors into a, b, c so that a, b, c < 200 bits (since each $w_i$ is dominated by the largest of a, b, c).

## PoC
This script brute-forced for about 5 hours to get the flag:
```python 
from sage.all import *
from pwn import *
from ast import literal_eval
import math
from tqdm import *

# Generate the anomalous prime
def find_prime_for_fixed_b(target_b, bits=256):
    print(f"[*] Targeting b = {target_b} with ~{bits} bits...")
    
    # Estimate starting y for the desired bit length
    target_y = int(math.sqrt(4/3) * (2**(bits//2)))
    
    # Ensure y is odd
    if target_y % 2 == 0:
        target_y += 1
    
    y = target_y
    attempts = 0
    
    while True:
        attempts += 1
        if attempts % 1000 == 0:
            print(f"    Checked {attempts} candidates...")

        # Generate candidate p from y
        p = Integer((3 * y**2 + 1) // 4)
        
        # Check if p is prime and exactly bits
        if p.is_prime() and p.bit_length() == bits:
            F = GF(p)
            E = EllipticCurve(F, [0, target_b])
            
            # Check if trace is 1
            if E.trace_of_frobenius() == 1:
                return p
        
        # Move to next candidate
        y += 2

# Find the prime
b_fixed = 137
p = find_prime_for_fixed_b(b_fixed, bits=256)
print(f"Found anomalous prime p: {p}")

p1 = p
p2 = p

# Start the process
host = 'instance.penguin.0ops.sjtu.cn'
port = 18311
io = remote(host, port)

print(io.recv().decode())

io.sendline((str(p1) + ' ' + str(p2)).encode())

for round_num in trange(1000):
    line = io.recv().decode()
    print(round_num, line)
    parts = line.split(',')
    r_str = parts[0].split('for ')[1].strip()
    k_str = parts[1].split('mask: ')[1].strip()
    r = Integer(r_str)
    k = Integer(k_str)

    E1 = EllipticCurve(Zmod(p1), [0, 137])
    n1 = E1.order()  # Should be p1 since anomalous

    inv24 = inverse_mod(24, n1)
    rk3 = r * pow(k, 3, n1)
    d1 = (rk3 * inv24) % n1
    d2 = (-rk3 * inv24) % n1

    print('r =', r)
    print('k =', k)
    print('d1 =', d1)
    print('d2 =', d2)

    found = False
    for sign, d in enumerate([d1, d2], 1):
        l = 0
        max_l = 10000
        while l < max_l:
            print(l)
            number = d + l * n1
            try:
                factors = factor(number)
                print(f"Factors of number ({sign}, l={l}): {factors}")

                # Check if all fac**exp bit_length <=199
                all_small = all((fac ** exp).bit_length() <= 199 for fac, exp in factors)

                if not all_small:
                    l += 1
                    continue

                # Flatten to list of primes with multiplicity
                prime_list = []
                for fac, exp in factors:
                    for _ in range(exp):
                        prime_list.append(fac)

                # Sort descending
                prime_list.sort(reverse=True)

                # Greedy balance
                a = Integer(1)
                b = Integer(1)
                c = Integer(1)
                for f in prime_list:
                    products = [a, b, c]
                    min_idx = products.index(min(products))
                    if min_idx == 0:
                        a *= f
                    elif min_idx == 1:
                        b *= f
                    else:
                        c *= f

                # Compute w to check actual bit
                temp_a = -a if sign == 2 else a
                w1 = temp_a + b + c
                w2 = temp_a - b - c
                w3 = -temp_a + b - c
                w4 = -temp_a - b + c
                temp_w = (w1, w2, w3, w4)

                max_w_bit = max(wi.bit_length() for wi in temp_w)

                print(f"Max w bit for d{sign}, l={l}: {max_w_bit}")

                if max_w_bit < 200:
                    found = True
                    print(f'a = {temp_a}')
                    print(f'b = {b}')
                    print(f'c = {c}')

                    # Verify
                    computed = (24 * abs(temp_a) * b * c) % n1
                    expected = (rk3 if sign == 1 else -rk3) % n1
                    assert computed == expected

                    a = temp_a  # set for w computation below
                    break
            except Exception as e:
                print(f"Factoring failed for l={l}: {e}")
                l += 1
                continue

            l += 1

        if found:
            break

    if not found:
        print("Failed to find suitable factors after max_l")

    w1 = a + b + c
    w2 = a - b - c
    w3 = -a + b - c
    w4 = -a - b + c
    w = (w1, w2, w3, w4)

    assert len(w) == 4
    assert max(wi.bit_length() for wi in w) < 200

    io.sendline(str(w).encode())

# Get the flag
print(io.recv().decode())
print(io.recv().decode())
```

After optimizing with processes/threads it finished in about 20-30 minutes:
```python
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
    host, port = 'instance.penguin.0ops.sjtu.cn', 18219
    
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
```

`flag: 0ctf{NOt_A_zk_Bu7_a_1nteR3st1ng_PuzZle!!!o12bjk41dsapd;}`

## Additionally
I created another optimized script during solving (by bruteforcing a smoother prime with smooth bound 2^5x) that finishes in about 30 minutes:

```python
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
```
