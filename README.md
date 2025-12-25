# 0CTF 2025 Writeups
VinSOC team's solutions for 0CTF 2025

<img width="1717" height="948" alt="image" src="https://github.com/user-attachments/assets/68cc984a-455c-4e66-a88a-0f5557596b9a" />


## Team Statistics
- **Total Solved**: 9 challenges (plus check-in and survey)
- **Ranking**: Top 20 out of 453 teams
- **Categories**:
  - **Crypto**: 4 challenges
  - **Misc**: 4 challenges
  - **Reverse**: 1 challenge
  - **Pwn**: 0 challenges
  - **Web**: 0 challenges

## Challenge Writeups

### Crypto

#### baby_discriminator
- **Category**: Cryptography
- **Solution**: Python script that uses power sum analysis to distinguish random vs signal vectors in a binary classification game
- **Key Technique**: Power sum metric with thresholding to identify bits with value 0 vs 1
- **File**: [crypto/baby_discriminator/solve/solve.py](crypto/baby_discriminator/solve/solve.py)

#### Nightfall Tempest Trials
- **Category**: Cryptography
- **Solution**: Kyber NTT (Number Theoretic Transform) attack implementation
- **Key Technique**: Reverse NTT stages to recover secret keys from leaked intermediate values
- **File**: [crypto/Nightfall Tempest Trials/solve/solve.py](crypto/Nightfall%20Tempest%20Trials/solve/solve.py)

#### zkpuzzle1
- **Category**: Cryptography / Zero-Knowledge Proofs
- **Solution**: SageMath implementation solving four-cubes decomposition with witness generation
- **Key Technique**: Factorization with smooth primes and predictive factor caching for performance
- **File**: [crypto/zkpuzzle1/solve/solve.sage](crypto/zkpuzzle1/solve/solve.sage)

#### zkpuzzle2
- **Category**: Cryptography / Zero-Knowledge Proofs
- **Solution**: Advanced four-cubes decomposition using ECM (Elliptic Curve Method) factorization
- **Key Technique**: Demjanenko formulas + parallel ECM search with GMP-ECM integration
- **File**: [crypto/zkpuzzle2/solve/solve.sage](crypto/zkpuzzle2/solve/solve.sage)

### Misc

#### chsys
- **Category**: Misc / System Administration
- **Solution**: Command injection exploit in a file system management interface
- **Key Technique**: Shell injection via `create` command to read the flag file
- **File**: [misc/chsys/solve/solve.py](misc/chsys/solve/solve.py)

#### GhostDB
- **Category**: Misc / Database
- **Solution**: BST (Binary Search Tree) bug exploitation causing orphaned nodes
- **Key Technique**: Create tree with 59,000 left subtree nodes, then delete root to trigger memory leak bug
- **File**: [misc/GhostDB/solve/solve.py](misc/GhostDB/solve/solve.py)

#### Motion Blur
- **Category**: Misc / Image Processing
- **Solution**: Reconstruct hidden image from motion-blurred frames using iterative reconstruction
- **Key Technique**: Grid-based mosaic detection + iterative mean reconstruction with alpha blending
- **File**: [misc/Motion Blur/solve/solve.py](misc/Motion%20Blur/solve/solve.py)

### Reverse

#### perspective
- **Category**: Reverse Engineering
- **Solution**: [Executable binary analysis - solve script not provided]
- **Challenge**: Windows executable analysis ([perspective.exe](re/perspective/attachments/perspective.exe))
- **File**: [re/perspective/attachments/perspective.exe](re/perspective/attachments/perspective.exe)

## About
Repository containing complete writeups and solutions for 0CTF 2025 challenges solved by the VinSOC team.
