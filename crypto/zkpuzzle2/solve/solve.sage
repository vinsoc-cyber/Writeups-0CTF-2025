import os
import re
import subprocess
import time
import multiprocessing as mp
from collections import Counter
from pwn import *
from sage.all import *

os.environ.setdefault("OMP_NUM_THREADS", "1")

p = 86844398212127729389856047074289654044187498228644074447276846288751135031303
q = 86844398212127729389856047074289654044187498228644074447276846288751135031309
N = p * q


def _run_gmp_ecm_one_factor(n, seconds, B1, curves, ecm_path="ecm"):
    n = Integer(n)
    if n <= 3 or is_prime(n):
        return None

    cmd = [ecm_path, "-q", "-one", "-c", str(curves), str(B1)]
    try:
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
    for match in re.finditer(r"\d{2,}", out):
        d = Integer(match.group(0))
        if 1 < d < n and n % d == 0:
            return d

    return None


def ecm_partial_factor(
    N,
    timeout_s,
    ecm_path="ecm",
    ladder=None,
    do_small_trial_division=True,
    trial_limit=10000,
):
    N = Integer(N)
    if N == 0:
        raise ValueError("N must be nonzero.")
    if N < 0:
        N = -N

    if ladder is None:
        ladder = [(200_000, 50, 5.0)]

    factors = Counter()
    start = time.time()

    if do_small_trial_division and N > 1:
        from sage.all import prime_range

        for p in prime_range(trial_limit + 1):
            p = Integer(p)
            if N % p != 0:
                continue
            exponent = 0
            while N % p == 0:
                N //= p
                exponent += 1
            factors[p] += exponent
            if N == 1:
                return factors, Integer(1)

    while N > 1 and not is_prime(N):
        elapsed = time.time() - start
        remaining_total = timeout_s - elapsed
        if remaining_total <= 0:
            break

        found = False
        for (B1, curves, cap) in ladder:
            elapsed = time.time() - start
            remaining_total = timeout_s - elapsed
            if remaining_total <= 0:
                break

            attempt_time = min(float(cap), float(remaining_total))
            d = _run_gmp_ecm_one_factor(N, attempt_time, B1, curves, ecm_path=ecm_path)
            if d is None:
                continue

            factors[d] += 1
            N //= d
            found = True
            break

        if not found:
            break

    if N > 1 and is_prime(N):
        factors[N] += 1
        N = Integer(1)

    return factors, N


def _target_candidates(tgt_start, offset, stride, modulus):
    step = offset
    while True:
        yield tgt_start + step * modulus
        step += stride


def _extract_solution(tgt, timeout_s):
    factors, cofactor = ecm_partial_factor(tgt, timeout_s=timeout_s)
    sm = max([*factors, cofactor])
    print(f"{sm.nbits() = }")

    df = tgt // 6 // sm
    u = (sm + df) // 2
    v = (sm - df) // 2
    arr = [1 + u, 1 - u, -1 + v, -1 - v]
    if u < 2**399:
        return arr
    return None


def worker_find_sm(N, tgt0, offset, stride, timeout_s, bits_limit, outq, stop_event):
    modulus = 12 * N
    for tgt in _target_candidates(tgt0, offset, stride, modulus):
        if stop_event.is_set():
            return

        if tgt % 12 != 6:
            continue

        arr = _extract_solution(tgt, timeout_s)
        if arr:
            outq.put(arr)
            stop_event.set()
            return


def parallel_search_sm(N, tgt_start, timeout_s=5.0, bits_limit=100, n_workers=8):
    ctx = mp.get_context("spawn")
    outq = ctx.Queue()
    stop_event = ctx.Event()

    procs = []
    for worker_id in range(n_workers):
        proc = ctx.Process(
            target=worker_find_sm,
            args=(N, tgt_start, worker_id, n_workers, timeout_s, bits_limit, outq, stop_event),
            daemon=True,
        )
        proc.start()
        procs.append(proc)

    try:
        return outq.get()
    finally:
        stop_event.set()
        for proc in procs:
            if proc.is_alive():
                proc.terminate()
        for proc in procs:
            proc.join(timeout=1.0)


def four_cubes_demjanenko(n: int):
    r9 = n % 9
    r18 = n % 18

    if r9 in (4, 5):
        return
    if r18 in (2, 16):
        return

    if r18 in (17, 11, 10):
        a, b, c, d = four_cubes_demjanenko(-n)
        return (-a, -b, -c, -d)

    if r18 in (0, 6, 12):
        x = n // 6
        return (x + 1, x - 1, -x, -x)

    if r18 in (3, 9, 15):
        x = (n - 3) // 6
        return (x, -x + 4, 2 * x - 5, -2 * x + 4)

    if r18 == 1:
        x = (n - 1) // 18
        return (2 * x + 14, -2 * x - 23, -3 * x - 26, 3 * x + 30)

    if r18 == 7:
        x = (n - 7) // 18
        return (x + 2, 6 * x - 1, 8 * x - 2, -9 * x + 2)

    if r18 == 8:
        x = (n - 8) // 18
        return (x - 5, -x + 14, -3 * x + 29, 3 * x - 30)


def _normalize_inputs(r, k):
    if r % 3 != 0 and k % 3 == 0:
        return r * 27, k // 3
    return r, k


def _align_target(tgt, modulus, residue, step):
    while tgt % modulus != residue:
        tgt += step
    return tgt


def solve_round(r, k):
    r, k = _normalize_inputs(r, k)
    arr = four_cubes_demjanenko(r)
    if arr:
        return [x * k for x in arr]

    tgt = _align_target(r * k**3 % N, 12, 6, N)
    return parallel_search_sm(N, tgt, timeout_s=5.0, bits_limit=100, n_workers=8)


def _read_round(io):
    return tuple(int(io.recvregex(b"([0-9]+),", capture=True).group(1)) for _ in "rk")


def run_solver():
    # context.log_level = 'debug'
    # io = process(['sage', 'zk2.sage'])
    io = remote("instance.penguin.0ops.sjtu.cn", 18383)
    io.sendline(f"{p} {q}".encode())

    w0 = walltime()
    for idx in range(954):
        r, k = _read_round(io)
        wt = walltime()
        sol = solve_round(r, k)
        total = walltime(w0)
        print(f"Completed round {idx + 1} in {walltime(wt)}. Total time {total}. Average time {total/(idx + 1)}")
        io.sendline(str(sol).encode())

    io.interactive()


if __name__ == "__main__":
    run_solver()
