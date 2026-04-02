import os
import csv
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")
PLOTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "plots")


def load_csv(filename):
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            rows.append({k: float(v) for k, v in row.items()})
        return rows


def plot_aes(aes_data):
    sizes = [d["size"] for d in aes_data]
    enc_means = [d["enc_mean"] for d in aes_data]
    enc_cis = [d["enc_ci"] for d in aes_data]
    dec_means = [d["dec_mean"] for d in aes_data]
    dec_cis = [d["dec_ci"] for d in aes_data]

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(sizes))
    width = 0.35

    ax.bar(x - width / 2, enc_means, width, yerr=enc_cis, label="AES-CTR Encryption",
           capsize=5, color="#2196F3", alpha=0.8)
    ax.bar(x + width / 2, dec_means, width, yerr=dec_cis, label="AES-CTR Decryption",
           capsize=5, color="#FF9800", alpha=0.8)

    ax.set_xlabel("File Size (bytes)")
    ax.set_ylabel("Time (μs)")
    ax.set_title("AES-256-CTR Encryption/Decryption Times")
    ax.set_xticks(x)
    ax.set_xticklabels([str(int(s)) for s in sizes], rotation=45)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "aes_times.png"), dpi=150)
    plt.close()
    print("  Saved aes_times.png")


def plot_rsa(rsa_data):
    sizes = [d["size"] for d in rsa_data]
    enc_means = [d["enc_mean"] for d in rsa_data]
    enc_cis = [d["enc_ci"] for d in rsa_data]
    dec_means = [d["dec_mean"] for d in rsa_data]
    dec_cis = [d["dec_ci"] for d in rsa_data]

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(sizes))
    ax.bar(x, enc_means, yerr=enc_cis, capsize=5, color="#4CAF50", alpha=0.8)
    ax.set_xlabel("File Size (bytes)")
    ax.set_ylabel("Time (μs)")
    ax.set_title("RSA-2048 Based Encryption Times")
    ax.set_xticks(x)
    ax.set_xticklabels([str(int(s)) for s in sizes], rotation=45)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "rsa_enc_times.png"), dpi=150)
    plt.close()
    print("  Saved rsa_enc_times.png")

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x, dec_means, yerr=dec_cis, capsize=5, color="#F44336", alpha=0.8)
    ax.set_xlabel("File Size (bytes)")
    ax.set_ylabel("Time (μs)")
    ax.set_title("RSA-2048 Based Decryption Times")
    ax.set_xticks(x)
    ax.set_xticklabels([str(int(s)) for s in sizes], rotation=45)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "rsa_dec_times.png"), dpi=150)
    plt.close()
    print("  Saved rsa_dec_times.png")


def plot_sha(sha_data):
    sizes = [d["size"] for d in sha_data]
    means = [d["mean"] for d in sha_data]
    cis = [d["ci"] for d in sha_data]

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(sizes))
    ax.bar(x, means, yerr=cis, capsize=5, color="#9C27B0", alpha=0.8)
    ax.set_xlabel("File Size (bytes)")
    ax.set_ylabel("Time (μs)")
    ax.set_title("SHA-256 Digest Generation Times")
    ax.set_xticks(x)
    ax.set_xticklabels([str(int(s)) for s in sizes], rotation=45)
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "sha_times.png"), dpi=150)
    plt.close()
    print("  Saved sha_times.png")


def plot_comparison(aes_data, rsa_data, sha_data):
    sizes = [d["size"] for d in aes_data]
    x = np.arange(len(sizes))
    width = 0.35

    aes_enc = [d["enc_mean"] for d in aes_data]
    rsa_enc = [d["enc_mean"] for d in rsa_data]
    rsa_dec = [d["dec_mean"] for d in rsa_data]
    sha_means = [d["mean"] for d in sha_data]
    aes_dec = [d["dec_mean"] for d in aes_data]

    # AES vs RSA encryption
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width / 2, aes_enc, width, label="AES-CTR Encryption",
           color="#2196F3", alpha=0.8)
    ax.bar(x + width / 2, rsa_enc, width, label="RSA-based Encryption",
           color="#4CAF50", alpha=0.8)
    ax.set_xlabel("File Size (bytes)")
    ax.set_ylabel("Time (μs)")
    ax.set_title("AES-CTR vs RSA-based Encryption Times")
    ax.set_xticks(x)
    ax.set_xticklabels([str(int(s)) for s in sizes], rotation=45)
    ax.legend()
    ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "comparison_aes_vs_rsa.png"), dpi=150)
    plt.close()
    print("  Saved comparison_aes_vs_rsa.png")

    # AES vs SHA
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width / 2, aes_enc, width, label="AES-CTR Encryption",
           color="#2196F3", alpha=0.8)
    ax.bar(x + width / 2, sha_means, width, label="SHA-256 Digest",
           color="#9C27B0", alpha=0.8)
    ax.set_xlabel("File Size (bytes)")
    ax.set_ylabel("Time (μs)")
    ax.set_title("AES-CTR Encryption vs SHA-256 Digest Generation Times")
    ax.set_xticks(x)
    ax.set_xticklabels([str(int(s)) for s in sizes], rotation=45)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "comparison_aes_vs_sha.png"), dpi=150)
    plt.close()
    print("  Saved comparison_aes_vs_sha.png")

    # RSA enc vs dec
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width / 2, rsa_enc, width, label="RSA Encryption",
           color="#4CAF50", alpha=0.8)
    ax.bar(x + width / 2, rsa_dec, width, label="RSA Decryption",
           color="#F44336", alpha=0.8)
    ax.set_xlabel("File Size (bytes)")
    ax.set_ylabel("Time (μs)")
    ax.set_title("RSA-based Encryption vs Decryption Times")
    ax.set_xticks(x)
    ax.set_xticklabels([str(int(s)) for s in sizes], rotation=45)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "comparison_rsa_enc_vs_dec.png"), dpi=150)
    plt.close()
    print("  Saved comparison_rsa_enc_vs_dec.png")

    # All combined (log scale)
    fig, ax = plt.subplots(figsize=(12, 7))
    w = 0.15
    ax.bar(x - 1.5 * w, aes_enc, w, label="AES-CTR Enc", color="#2196F3", alpha=0.8)
    ax.bar(x - 0.5 * w, aes_dec, w, label="AES-CTR Dec", color="#FF9800", alpha=0.8)
    ax.bar(x + 0.5 * w, rsa_enc, w, label="RSA Enc", color="#4CAF50", alpha=0.8)
    ax.bar(x + 1.5 * w, sha_means, w, label="SHA-256", color="#9C27B0", alpha=0.8)
    ax.bar(x + 2.5 * w, rsa_dec, w, label="RSA Dec", color="#F44336", alpha=0.8)
    ax.set_xlabel("File Size (bytes)")
    ax.set_ylabel("Time (μs) — log scale")
    ax.set_title("All Cryptographic Operations — Performance Comparison")
    ax.set_xticks(x)
    ax.set_xticklabels([str(int(s)) for s in sizes], rotation=45)
    ax.legend()
    ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, "comparison_all.png"), dpi=150)
    plt.close()
    print("  Saved comparison_all.png")


def main():
    os.makedirs(PLOTS_DIR, exist_ok=True)

    print("Loading results...")
    aes_data = load_csv("aes_results.csv")
    rsa_data = load_csv("rsa_results.csv")
    sha_data = load_csv("sha_results.csv")

    print("Generating plots...")
    plot_aes(aes_data)
    plot_rsa(rsa_data)
    plot_sha(sha_data)
    plot_comparison(aes_data, rsa_data, sha_data)

    print(f"\nAll plots saved to {PLOTS_DIR}/")


if __name__ == "__main__":
    main()
