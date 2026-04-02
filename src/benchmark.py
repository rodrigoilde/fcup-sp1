"""
Benchmarking framework for AES-CTR, RSA-based encryption and SHA-256.

For each file size, runs the operation over multiple random files and
multiple repetitions, reporting mean, std dev and 95% confidence intervals.
"""

import os
import sys
import csv
import time
import timeit
import statistics
import math

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.aes_ctr import aes_ctr_encrypt, aes_ctr_decrypt
from src.rsa_enc import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from src.sha_hash import sha256_digest
from src.generate_files import FILE_SIZES, OUTPUT_DIR, generate_files

NUM_FILES = 10
MIN_REPETITIONS = 10
TARGET_TIME = 0.5

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")


def adaptive_repetitions(func, min_reps=MIN_REPETITIONS, target_time=TARGET_TIME):
    """Warm-up run to estimate time, then set reps to reach target_time."""
    t = timeit.timeit(func, number=1)
    if t == 0:
        t = 1e-7
    reps = max(min_reps, int(target_time / t))
    return min(reps, 100000)


def measure_operation(func, num_reps):
    """Time func individually num_reps times. Returns list in microseconds."""
    times = []
    for _ in range(num_reps):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append((end - start) * 1e6)
    return times


def compute_stats(times):
    n = len(times)
    mean = statistics.mean(times)
    if n > 1:
        stdev = statistics.stdev(times)
        t_value = 1.96 # n is always large, no need for statements
        ci = t_value * stdev / math.sqrt(n)
    else:
        stdev = 0.0
        ci = 0.0
    return mean, stdev, ci


def load_file(size, file_idx):
    filepath = os.path.join(OUTPUT_DIR, f"random_{size}_{file_idx}.bin")
    with open(filepath, "rb") as f:
        return f.read()


def benchmark_aes(sizes=FILE_SIZES, num_files=NUM_FILES):
    key = os.urandom(32)  # 256-bit
    results = []

    print("\n=== AES-CTR Benchmark ===")
    for size in sizes:
        all_enc_times = []
        all_dec_times = []

        for fi in range(num_files):
            data = load_file(size, fi)

            enc_reps = adaptive_repetitions(lambda: aes_ctr_encrypt(data, key))
            enc_times = measure_operation(lambda: aes_ctr_encrypt(data, key), enc_reps)
            all_enc_times.extend(enc_times)

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
    private_key, public_key = generate_rsa_keypair()
    results = []

    print("\n=== RSA-based Encryption Benchmark ===")
    for size in sizes:
        all_enc_times = []
        all_dec_times = []

        for fi in range(num_files):
            data = load_file(size, fi)

            enc_reps = adaptive_repetitions(
                lambda: rsa_encrypt(data, public_key),
                min_reps=5, target_time=0.3
            )
            enc_times = measure_operation(
                lambda: rsa_encrypt(data, public_key), enc_reps
            )
            all_enc_times.extend(enc_times)

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
    os.makedirs(RESULTS_DIR, exist_ok=True)

    with open(os.path.join(RESULTS_DIR, "aes_results.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "size", "enc_mean", "enc_std", "enc_ci",
            "dec_mean", "dec_std", "dec_ci", "enc_n", "dec_n"
        ])
        writer.writeheader()
        writer.writerows(aes_results)

    with open(os.path.join(RESULTS_DIR, "rsa_results.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "size", "enc_mean", "enc_std", "enc_ci",
            "dec_mean", "dec_std", "dec_ci", "enc_n", "dec_n"
        ])
        writer.writeheader()
        writer.writerows(rsa_results)

    with open(os.path.join(RESULTS_DIR, "sha_results.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["size", "mean", "std", "ci", "n"])
        writer.writeheader()
        writer.writerows(sha_results)

    print(f"\nResults saved to {RESULTS_DIR}/")


def print_system_info():
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

    print("Generating test files...")
    generate_files(num_sets=NUM_FILES)
    print()

    aes_results = benchmark_aes()
    rsa_results = benchmark_rsa()
    sha_results = benchmark_sha()

    save_results(aes_results, rsa_results, sha_results)
    print("\nDone. Run 'python src/plot_results.py' to generate plots.")


if __name__ == "__main__":
    main()
