# Assignment #1: Performance Benchmarking of Cryptographic Mechanisms

Security and Privacy — FCUP 2025/2026

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