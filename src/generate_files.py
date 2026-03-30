"""Generate random binary files of specified sizes for benchmarking."""

import os

FILE_SIZES = [8, 64, 512, 4096, 32768, 262144, 2097152]
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_files")


def generate_files(num_sets=10):
    """Generate multiple sets of random files for statistical significance.

    Args:
        num_sets: Number of independent random files per size.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for size in FILE_SIZES:
        for i in range(num_sets):
            filepath = os.path.join(OUTPUT_DIR, f"random_{size}_{i}.bin")
            with open(filepath, "wb") as f:
                f.write(os.urandom(size))
            print(f"Generated {filepath} ({size} bytes)")


if __name__ == "__main__":
    generate_files()
