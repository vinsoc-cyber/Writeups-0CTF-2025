#!/bin/bash
set -e

rm -rf kyber
git clone https://github.com/pq-crystals/kyber.git

cd kyber
git checkout 4768bd37c02f9c40a46cb49d4d1f4d5e612bb882
git apply ../ntt.patch

echo "Patch applied!"

cd ref
mkdir -p lib

gcc -shared -fPIC -O3 -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith -DKYBER_K=12 kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c symmetric-shake.c fips202.c randombytes.c -o lib/libpqcrystals_kyber1024_ref.so

cd ../../

python3 task.py
