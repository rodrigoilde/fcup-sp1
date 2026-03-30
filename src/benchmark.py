"""Benchmarking framework for cryptographic operations.

Methodology:
- For each file size, we run the operation over multiple independently generated
  random files (to account for data-dependent variance).
- For each file, we run the operation multiple times (repetitions) to account
  for system noise and obtain stable measurements.
- We use timeit for precise timing of only the cryptographic operation.
- We report mean, standard deviation, and 95% confidence intervals.
- Results are saved to CSV for later plotting.
"""

import os
import sys
import csv
import time
import timeit
import statistics
import math

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.aes_ctr import aes_ctr_encrypt, aes_ctr_decrypt
from src.rsa_enc import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from src.sha_hash import sha256_digest
from src.generate_files import FILE_SIZES, OUTPUT_DIR, generate_files

# Number of independent random files per size
NUM_FILES = 10
# Minimum number of repetitions per file
MIN_REPETITIONS = 10
# Target total measurement time per (size, file) combination in seconds
TARGET_TIME = 0.5

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")


def adaptive_repetitions(func, min_reps=MIN_REPETITIONS, target_time=TARGET_TIME):
    """Determine number of repetitions to get reliable timing.

    Runs func once to estimate time, then calculates repetitions needed
    to reach target_time total, with a minimum of min_reps.
    """
    # Warm-up run
    t = timeit.timeit(func, number=1)
    if t == 0:
        t = 1e-7
    reps = max(min_reps, int(target_time / t))
    # Cap at a reasonable maximum to avoid very long runs
    return min(reps, 100000)


def measure_operation(func, num_reps):
    """Measure execution time of func over num_reps repetitions.

    Returns list of individual timings in microseconds.
    """
    times = []
    for _ in range(num_reps):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append((end - start) * 1e6)  # Convert to microseconds
    return times


def compute_stats(times):
    """Compute mean, std dev, and 95% CI from a list of times."""
    n = len(times)
    mean = statistics.mean(times)
    if n > 1:
        stdev = statistics.stdev(times)
        # 95% CI using t-distribution approximation (for large n, ~1.96)
        t_value = 1.96 if n >= 30 else 2.576  # conservative for small n
        ci = t_value * stdev / math.sqrt(n)
    else:
        stdev = 0.0
        ci = 0.0
    return mean, stdev, ci


def load_file(size, file_idx):
    """Load a test file."""
    filepath = os.path.join(OUTPUT_DIR, f"random_{size}_{file_idx}.bin")
    with open(filepath, "rb") as f:
        return f.read()


def benchmark_aes(sizes=FILE_SIZES, num_files=NUM_FILES):
    """Benchmark AES-CTR encryption and decryption."""
    key = os.urandom(32)  # 256-bit key
    results = []

    print("\n=== AES-CTR Benchmark ===")
    for size in sizes:
        all_enc_times = []
        all_dec_times = []

        for fi in range(num_files):
            data = load_file(size, fi)

            # Determine repetitions adaptively
            enc_reps = adaptive_repetitions(lambda: aes_ctr_encrypt(data, key))

            # Measure encryption
            enc_times = measure_operation(lambda: aes_ctr_encrypt(data, key), enc_reps)
            all_enc_times.extend(enc_times)

            # Encrypt once to get nonce/ciphertext for decryption
            nonce, ciphertext = aes_ctr_encrypt(data, key)

            dec_reps = adaptive_repetitions(lambda: aes_ctr_decrypt(ciphertext, key, nonce))
            dec_times = measure_operation(lambda: aes_ctr_decrypt(ciphertext, key, nonce), dec_reps)
            all_dec_times.extend(dec_times)

        enc_mean, enc_std, enc_ci = compute_stats(all_enc_times)
        dec_mean, dec_std, dec_ci = compute_stats(all_dec_times)

        results.append({
            "size": size,
            "enc_mean": enc_mean, "enc_std": enc_std, "enc_ci": enc_ci,
            "dec_mean": dec_mean, "dec_std": dec_std, "dec_ci": dec_ci,
            "enc_n": len(all_enc_times), "dec_n": len(all_dec_times),
        })

        print(f"  Size {size:>8d} B | Enc: {enc_mean:>12.2f} ± {enc_ci:.2f} us "
              f"(std={enc_std:.2f}, n={len(all_enc_times)}) | "
              f"Dec: {dec_mean:>12.2f} ± {dec_ci:.2f} us "
              f"(std={dec_std:.2f}, n={len(all_dec_times)})")

    return results


def benchmark_rsa(sizes=FILE_SIZES, num_files=NUM_FILES):
    """Benchmark RSA-based encryption and decryption."""
    private_key, public_key = generate_rsa_keypair()
    results = []

    print("\n=== RSA-based Encryption Benchmark ===")
    for size in sizes:
        all_enc_times = []
        all_dec_times = []

        for fi in range(num_files):
            data = load_file(size, fi)

            # For RSA, fewer repetitions since it's much slower
            enc_reps = adaptive_repetitions(
                lambda: rsa_encrypt(data, public_key),
                min_reps=5, target_time=0.3
            )

            enc_times = measure_operation(
                lambda: rsa_encrypt(data, public_key), enc_reps
            )
            all_enc_times.extend(enc_times)

            # Encrypt once for decryption benchmark
            rsa_r, enc_blocks = rsa_encrypt(data, public_key)

            dec_reps = adaptive_repetitions(
                lambda: rsa_decrypt(rsa_r, enc_blocks, private_key),
                min_reps=5, target_time=0.3
            )

            dec_times = measure_operation(
                lambda: rsa_decrypt(rsa_r, enc_blocks, private_key), dec_reps
            )
            all_dec_times.extend(dec_times)

        enc_mean, enc_std, enc_ci = compute_stats(all_enc_times)
        dec_mean, dec_std, dec_ci = compute_stats(all_dec_times)

        results.append({
            "size": size,
            "enc_mean": enc_mean, "enc_std": enc_std, "enc_ci": enc_ci,
            "dec_mean": dec_mean, "dec_std": dec_std, "dec_ci": dec_ci,
            "enc_n": len(all_enc_times), "dec_n": len(all_dec_times),
        })

        print(f"  Size {size:>8d} B | Enc: {enc_mean:>12.2f} ± {enc_ci:.2f} us "
              f"(std={enc_std:.2f}, n={len(all_enc_times)}) | "
              f"Dec: {dec_mean:>12.2f} ± {dec_ci:.2f} us "
              f"(std={dec_std:.2f}, n={len(all_dec_times)})")

    return results


def benchmark_sha(sizes=FILE_SIZES, num_files=NUM_FILES):
    """Benchmark SHA-256 hash generation."""
    results = []

    print("\n=== SHA-256 Benchmark ===")
    for size in sizes:
        all_times = []

        for fi in range(num_files):
            data = load_file(size, fi)

            reps = adaptive_repetitions(lambda: sha256_digest(data))
            times = measure_operation(lambda: sha256_digest(data), reps)
            all_times.extend(times)

        mean, std, ci = compute_stats(all_times)

        results.append({
            "size": size,
            "mean": mean, "std": std, "ci": ci,
            "n": len(all_times),
        })

        print(f"  Size {size:>8d} B | Hash: {mean:>12.2f} ± {ci:.2f} us "
              f"(std={std:.2f}, n={len(all_times)})")

    return results


def save_results(aes_results, rsa_results, sha_results):
    """Save results to CSV files."""
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # AES results
    with open(os.path.join(RESULTS_DIR, "aes_results.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "size", "enc_mean", "enc_std", "enc_ci",
            "dec_mean", "dec_std", "dec_ci", "enc_n", "dec_n"
        ])
        writer.writeheader()
        writer.writerows(aes_results)

    # RSA results
    with open(os.path.join(RESULTS_DIR, "rsa_results.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "size", "enc_mean", "enc_std", "enc_ci",
            "dec_mean", "dec_std", "dec_ci", "enc_n", "dec_n"
        ])
        writer.writeheader()
        writer.writerows(rsa_results)

    # SHA results
    with open(os.path.join(RESULTS_DIR, "sha_results.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["size", "mean", "std", "ci", "n"])
        writer.writeheader()
        writer.writerows(sha_results)

    print(f"\nResults saved to {RESULTS_DIR}/")


def print_system_info():
    """Print system information for the report."""
    import platform
    print("=== System Information ===")
    print(f"  Platform: {platform.platform()}")
    print(f"  Processor: {platform.processor()}")
    print(f"  Python: {platform.python_version()}")
    try:
        import cryptography
        print(f"  cryptography: {cryptography.__version__}")
    except Exception:
        pass
    print(f"  Machine: {platform.machine()}")
    print()


def main():
    print_system_info()

    # Generate test files
    print("Generating test files...")
    generate_files(num_sets=NUM_FILES)
    print()

    # Run benchmarks
    aes_results = benchmark_aes()
    rsa_results = benchmark_rsa()
    sha_results = benchmark_sha()

    # Save results
    save_results(aes_results, rsa_results, sha_results)

    print("\nBenchmarking complete. Run 'python src/plot_results.py' to generate plots.")


if __name__ == "__main__":
    main()
