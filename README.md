# Assignment #1: Performance Benchmarking of Cryptographic Mechanisms

Security and Privacy — FCUP 2025/2026

## Project Structure

```
src/
├── __init__.py
├── generate_files.py   # Random file generation (sizes: 8B to 2MB)
├── aes_ctr.py          # AES-256-CTR encryption/decryption
├── rsa_enc.py          # RSA-2048 based encryption/decryption scheme
├── sha_hash.py         # SHA-256 digest generation
├── benchmark.py        # Main benchmarking framework with statistical analysis
└── plot_results.py     # Plot generation from CSV results
results/                # CSV files with benchmark data (generated)
plots/                  # PNG plots (generated)
test_files/             # Random binary test files (generated)
```

## Requirements

- Python 3.10+
- Dependencies: `cryptography`, `matplotlib`, `numpy`

## Setup

```bash
pip install -r requirements.txt
```

## How to Run

### 1. Run all benchmarks

```bash
python -m src.benchmark
```

This will:
- Generate 10 random files for each of the 7 sizes (8, 64, 512, 4096, 32768, 262144, 2097152 bytes)
- Benchmark AES-256-CTR encryption and decryption
- Benchmark RSA-2048-based encryption and decryption (using the custom scheme with SHA-256)
- Benchmark SHA-256 digest generation
- Save results to `results/` as CSV files

### 2. Generate plots

```bash
python -m src.plot_results
```

This reads the CSV results and generates plots in the `plots/` directory.

## Benchmarking Methodology

- **Multiple files per size**: 10 independently generated random files per size to account for data-dependent variance.
- **Adaptive repetitions**: The number of repetitions per measurement is determined adaptively to ensure sufficient measurement time (target: 0.5s per file/operation combination, minimum 10 repetitions).
- **Precise timing**: Uses `time.perf_counter()` for high-resolution timing of individual operations.
- **Statistical reporting**: Mean, standard deviation, and 95% confidence intervals are computed across all measurements (files × repetitions).
- **Isolation**: Only the cryptographic operation is timed — file I/O, key generation, and setup are excluded.

## Cryptographic Implementations

### AES-CTR (Task B)
Uses the `cryptography` library's AES implementation in CTR mode with a 256-bit key and random 16-byte nonce.

### RSA-based Encryption (Task C)
Implements the scheme: `Enc(m; r) = (RSA(r), H(0,r) ⊕ m_0, ..., H(n,r) ⊕ m_n)`
- RSA key size: 2048 bits
- H = SHA-256 (output: 32 bytes per block)
- r: 256-byte random value (with leading zero byte to ensure r < n)
- Raw RSA (modular exponentiation) using the `cryptography` library's key internals

### SHA-256 (Task D)
Uses the `cryptography` library's SHA-256 hash implementation.
