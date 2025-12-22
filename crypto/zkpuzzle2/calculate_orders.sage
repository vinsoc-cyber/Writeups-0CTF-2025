#!/usr/bin/env sage -python
from sage.all import *

B = 137

# Provided primes
p1 = 85052124110058675234192833684845201763626067191829806899087820989019954446001
p2 = 85052124110058675234192833684845201763335450819044560821221615613950653836951

print(f"p1 popcount: {p1.bit_count()}")
print(f"p2 popcount: {p2.bit_count()}")
print(f"Sum popcount: {p1.bit_count() + p2.bit_count()}")

# Calculate n1 and n2 (generator orders)
F1 = GF(p1)
E1 = EllipticCurve(F1, [0, B])
G1 = E1.gens()[0]
n1 = G1.order()

F2 = GF(p2)
E2 = EllipticCurve(F2, [0, B])
G2 = E2.gens()[0]
n2 = G2.order()

print(f"p1 = {p1}")
print(f"n1 = {n1}")
print(f"n1 is prime: {n1.is_prime()}")
print(f"n1 > 2^128: {n1 > (1<<128)}")
print()
print(f"p2 = {p2}")
print(f"n2 = {n2}")
print(f"n2 is prime: {n2.is_prime()}")
print(f"n2 > 2^128: {n2 > (1<<128)}")
print()
print(f"ROUND count would be: {1000 - p1.bit_count() - p2.bit_count()}")