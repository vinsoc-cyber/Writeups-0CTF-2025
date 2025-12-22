from pwn import *
from sage.all import *
from tqdm import trange
import subprocess, time, re, os
import multiprocessing as mp
from collections import Counter
os.environ.setdefault("OMP_NUM_THREADS", "1")

p = 86844398212127729389856047074289654044187498228644074447276846288751135031303
q = 86844398212127729389856047074289654044187498228644074447276846288751135031309
N = p*q

def worker_find_sm(N, tgt0, offset, stride, timeout_s, bits_limit, outq, stop_event):
    # Each worker searches tgt = tgt0 + (offset + stride*j)*N
    j = 0
    while not stop_event.is_set():
        tgt = tgt0 + (offset + stride * j) * 12 * N
        
        assert tgt % 12 == 6

        # Keep your congruence filter
        if tgt % 12 == 6:
            factors, cofactor = ecm_partial_factor(tgt, timeout_s=timeout_s)
            sm = max([*factors, cofactor])  # matches your code
            print(f'{sm.nbits() = }')
            df = tgt // 6 // sm
            u, v = (sm+df)//2, (sm-df)//2
            arr = [1+u,1-u,-1+v,-1-v]
            if u < 2**399:
                # return arr
            # if sm.nbits() < bits_limit:
                outq.put(arr)
                stop_event.set()
                return

        j += 1
        
       # factors, cofactor = ecm_partial_factor(tgt, timeout_s=5.0)
        # sm = max([*factors,cofactor])
        # print(f'{sm.nbits() = }')
        # df = tgt // 6 // sm
        # u, v = (sm+df)//2, (sm-df)//2
        # arr = [1+u,1-u,-1+v,-1-v]
        # if u < 2**399:
            # return arr

def parallel_search_sm(N, tgt_start, timeout_s=5.0, bits_limit=100, n_workers=8):
    """
    Returns sm from the first worker to succeed.
    """
    ctx = mp.get_context("spawn")  # safer in Sage/Jupyter than fork
    outq = ctx.Queue()
    stop_event = ctx.Event()

    procs = []
    for w in range(n_workers):
        proc = ctx.Process(
            target=worker_find_sm,
            args=(N, tgt_start, w, n_workers, timeout_s, bits_limit, outq, stop_event),
            daemon=True,
        )
        proc.start()
        procs.append(proc)

    try:
        sm = outq.get()  # blocks until a worker puts a result
        return sm
    finally:
        stop_event.set()
        for proc in procs:
            if proc.is_alive():
                proc.terminate()
        for proc in procs:
            proc.join(timeout=1.0)

def _run_gmp_ecm_one_factor(n, seconds, B1, curves, ecm_path="ecm"):
    """
    Try to find ONE nontrivial factor of n using GMP-ECM with given params.
    Returns Integer(factor) or None.
    Hard wall-clock timeout via subprocess.
    """
    n = Integer(n)
    if n <= 3:
        return None
    if is_prime(n):
        return None

    cmd = [ecm_path, "-q", "-one", "-c", str(curves), str(B1)]
    try:
        # print('RUNNING', curves, B1)
        cp = subprocess.run(
            cmd,
            input=str(n).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=float(seconds),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None

    out = cp.stdout.decode(errors="ignore")

    # Robust parsing: grab all "big-ish" integers in output, test divisibility.
    # (GMP-ECM output format varies by version/options.)
    for m in re.finditer(r"\d{2,}", out):
        d = Integer(m.group(0))
        if 1 < d < n and n % d == 0:
            return d

    return None

def ecm_partial_factor(N, timeout_s, ecm_path="ecm",
                       ladder=None,
                       do_small_trial_division=True,
                       trial_limit=10000):
    """
    Partially factor N using ECM for at most timeout_s seconds.

    Returns:
      (factors_counter, cofactor)
    where factors_counter is a Counter mapping factor -> multiplicity.
    Factors found may be composite (ECM gives nontrivial splits).
    """

    N = Integer(N)
    if N == 0:
        raise ValueError("N must be nonzero.")
    if N < 0:
        N = -N  # factor sign separately if you care

    # A reasonable default parameter ladder for ~512-bit inputs.
    # Each attempt tries to find *one* factor; we loop until time runs out.
    if ladder is None:
        ladder = [
            # (B1, curves, max_seconds_for_this_attempt)
            (20_000,     50,  0.15),
            (100_000,    80,  0.25),
            (500_000,   120,  0.40),
            (2_000_000, 180,  0.70),
            (10_000_000,250,  1.20),
        ]
        ladder = [
            (200_000, 50, 5.0)
        ]

    factors = Counter()
    start = time.time()

    # Optional: cheap trial division knocks out small primes quickly.
    if do_small_trial_division and N > 1:
        # trial_limit ~ 10k is cheap; adjust as you like
        # (still "ECM-focused", but this is just low-hanging fruit)
        from sage.all import prime_range
        for p in prime_range(trial_limit + 1):
            p = Integer(p)
            if N % p == 0:
                e = 0
                while N % p == 0:
                    N //= p
                    e += 1
                factors[p] += e
            if N == 1:
                return factors, Integer(1)

    # Main loop: keep splitting off factors while time remains.
    while N > 1 and not is_prime(N):
        elapsed = time.time() - start
        remaining_total = timeout_s - elapsed
        if remaining_total <= 0:
            break

        got_factor = False

        for (B1, curves, cap) in ladder:
            elapsed = time.time() - start
            remaining_total = timeout_s - elapsed
            if remaining_total <= 0:
                break

            attempt_time = min(float(cap), float(remaining_total))
            d = _run_gmp_ecm_one_factor(N, attempt_time, B1, curves, ecm_path=ecm_path)
            if d is None:
                continue

            # Split N by d; record d and continue (d may be composite)
            factors[d] += 1
            N //= d
            got_factor = True
            break  # go back to the while-loop on the reduced N

        if not got_factor:
            # No factor found with our ladder before the remaining budget ran out
            break

    # If leftover is >1 and prime, include it (we "found" it by finishing)
    if N > 1 and is_prime(N):
        factors[N] += 1
        N = Integer(1)

    return factors, N

def four_cubes_demjanenko(n: int):
    """
    Return (a,b,c,d) such that a^3 + b^3 + c^3 + d^3 == n,
    using the 5 explicit identities from Wikipedia's Sum of four cubes problem page.

    Preconditions for this construction:
      n % 9 not in {4,5}   (i.e. n not congruent to ±4 mod 9)
      n % 18 not in {2,16} (i.e. n not congruent to ±2 mod 18)

    Raises ValueError if n falls in excluded residue classes.

    Note: This is an *exact integer* decomposition, not just mod something.
    """
    r9 = n % 9
    r18 = n % 18

    if r9 in (4, 5):
        # raise ValueError("This Demjanenko formula set does not cover n ≡ ±4 (mod 9).")
        return
    if r18 in (2, 16):
        # raise ValueError("This Demjanenko formula set (as requested) excludes n ≡ ±2 (mod 18).")
        return

    # Handle "opposites": if we can do -n, then negate all outputs to get n.
    if r18 in (17, 11, 10):  # -1, -7, -8 mod 18
        a, b, c, d = four_cubes_demjanenko(-n)
        return (-a, -b, -c, -d)

    # Now r18 is one of: 0,1,3,6,7,8,9,12,15
    if r18 in (0, 6, 12):
        # 6x = (x+1)^3 + (x-1)^3 - x^3 - x^3
        x = n // 6
        return (x + 1, x - 1, -x, -x)

    if r18 in (3, 9, 15):
        # 6x+3 = x^3 + (-x+4)^3 + (2x-5)^3 + (-2x+4)^3
        x = (n - 3) // 6
        return (x, -x + 4, 2*x - 5, -2*x + 4)

    if r18 == 1:
        # 18x+1 = (2x+14)^3 + (-2x-23)^3 + (-3x-26)^3 + (3x+30)^3
        x = (n - 1) // 18
        return (2*x + 14, -2*x - 23, -3*x - 26, 3*x + 30)

    if r18 == 7:
        # 18x+7 = (x+2)^3 + (6x-1)^3 + (8x-2)^3 + (-9x+2)^3
        x = (n - 7) // 18
        return (x + 2, 6*x - 1, 8*x - 2, -9*x + 2)

    if r18 == 8:
        # 18x+8 = (x-5)^3 + (-x+14)^3 + (-3x+29)^3 + (3x-30)^3
        x = (n - 8) // 18
        return (x - 5, -x + 14, -3*x + 29, 3*x - 30)

def solve_round(r, k):
    
    if r % 3 != 0 and k % 3 == 0:
        r *= 27
        k //= 3
    arr = four_cubes_demjanenko(r)
    if arr:
        return [x*k for x in arr]
        
    # otherwise fail
    
    tgt = r*k**3%N
    while tgt % 12 != 6:
        tgt += N
    arr = parallel_search_sm(N, tgt, timeout_s=5.0, bits_limit=100, n_workers=8)
    return arr
    
    # while True:
        # tgt += N
        # if tgt % 12 != 6:
            # continue
        
        # factors, cofactor = ecm_partial_factor(tgt, timeout_s=5.0)
        # sm = max([*factors,cofactor])
        # print(f'{sm.nbits() = }')
        # df = tgt // 6 // sm
        # u, v = (sm+df)//2, (sm-df)//2
        # arr = [1+u,1-u,-1+v,-1-v]
        # if u < 2**399:
            # return arr

if __name__ == "__main__":
    # context.log_level = 'debug'
    # io = process(['sage', 'zk2.sage'])
    io = remote('instance.penguin.0ops.sjtu.cn', 18454)
    io.sendline(f'{p} {q}'.encode())

    w0 = walltime()
    for _ in range(954):
        r, k = [int(io.recvregex(b'([0-9]+),', capture=True).group(1)) for _ in 'rk']
        wt = walltime()
        sol = solve_round(r, k)
        total = walltime(w0)
        print(f'Completed round {_+1} in {walltime(wt)}. Total time {total}. Average time {total/(_+1)}')
        io.sendline(str(sol).encode())

    io.interactive()