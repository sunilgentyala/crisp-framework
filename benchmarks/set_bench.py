"""
CRISP Framework — Benchmark 2: SET Channel Handshake Overhead
=============================================================
Paper: "The Weaponization of Deepfakes: A Novel Cryptographic Framework
        Mitigating Biometric Injection and Identity Gaps"
Target Journal: IEEE Transactions on Information Forensics and Security

Description:
    Measures the additional TLS 1.3 handshake latency introduced by
    the X25519MLKEM768 post-quantum hybrid key agreement (SET component)
    versus a baseline X25519-only handshake. Runs 100 loopback handshakes
    per variant and reports P50, P95, and the P95 overhead delta.

Platform tested: x86-64 Ubuntu 22.04 (sunil@Quantumlabs)
OpenSSL version: 3.x with OQS provider (liboqs 0.10, oqs-provider 0.7)
Method:          100 loopback TLS 1.3 handshakes per variant via
                 subprocess calls to openssl s_client

Hardware note:
    Results are from loopback (localhost) measurement. ARM Cortex-A76
    class devices are expected to exhibit 1.5 to 2 times higher absolute
    latency, with a proportionally similar overhead delta.

Prerequisites:
    Build and install liboqs and oqs-provider. See BENCHMARK_GUIDE.md
    for full installation commands.

    Generate a self-signed test certificate:
        openssl req -x509 -newkey rsa:2048 -keyout ~/key.pem \\
          -out ~/cert.pem -days 365 -nodes -subj "/CN=localhost"

Usage:
    Step 1 — In Terminal 1, start the server:
        openssl s_server \\
          -provider-path /usr/lib/x86_64-linux-gnu/ossl-modules \\
          -provider oqsprovider -provider default \\
          -cert ~/cert.pem -key ~/key.pem \\
          -port 4433 -tls1_3 -groups X25519MLKEM768:X25519

    Step 2 — In Terminal 2, run this script:
        python3 set_bench.py
"""

import subprocess
import time
import sys
import numpy as np

ITERATIONS   = 100
SERVER_ADDR  = "localhost:4433"
PROVIDER_PATH = "/usr/lib/x86_64-linux-gnu/ossl-modules"

PROVIDER_ARGS = [
    "-provider-path", PROVIDER_PATH,
    "-provider", "oqsprovider",
    "-provider", "default",
]


def handshake(groups: str = None) -> float:
    """
    Perform one TLS 1.3 handshake and return elapsed time in milliseconds.
    If groups is None, the default negotiation applies (X25519 baseline).
    """
    cmd = ["openssl", "s_client"] + PROVIDER_ARGS + [
        "-connect", SERVER_ADDR,
        "-tls1_3",
    ]
    if groups:
        cmd += ["-groups", groups]

    t0 = time.perf_counter()
    result = subprocess.run(cmd, input=b"", capture_output=True, timeout=10)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    if result.returncode not in (0, 1):
        print(f"WARNING: s_client returned code {result.returncode}. "
              "Ensure the server is running in Terminal 1.", file=sys.stderr)

    return elapsed_ms


def run_variant(label: str, groups: str = None) -> np.ndarray:
    print(f"Running {label} ({ITERATIONS} handshakes)...")
    times = []
    for i in range(ITERATIONS):
        times.append(handshake(groups))
        if (i + 1) % 25 == 0:
            print(f"  Completed {i + 1}/{ITERATIONS}")
    return np.array(times)


def main():
    print("CRISP Benchmark 2: SET Channel Handshake Overhead")
    print(f"Platform : x86-64 Ubuntu 22.04")
    print(f"Server   : {SERVER_ADDR} (loopback)")
    print(f"Provider : OQS provider ({PROVIDER_PATH})")
    print(f"Iterations per variant: {ITERATIONS}")
    print("-" * 55)
    print("IMPORTANT: Ensure the OpenSSL server is running in Terminal 1.")
    print("See script header for the exact server command.")
    print("-" * 55)

    baseline = run_variant("Baseline X25519", groups="X25519")
    hybrid   = run_variant("PQ-Hybrid X25519MLKEM768", groups="X25519MLKEM768")

    b, h = baseline, hybrid
    overhead_p50 = np.percentile(h, 50) - np.percentile(b, 50)
    overhead_p95 = np.percentile(h, 95) - np.percentile(b, 95)

    print("-" * 55)
    print("Results:")
    print(f"\n  Baseline X25519:")
    print(f"    P50 : {np.percentile(b, 50):.1f} ms")
    print(f"    P95 : {np.percentile(b, 95):.1f} ms")
    print(f"    Mean: {np.mean(b):.1f} ms")

    print(f"\n  PQ-Hybrid X25519MLKEM768:")
    print(f"    P50 : {np.percentile(h, 50):.1f} ms")
    print(f"    P95 : {np.percentile(h, 95):.1f} ms")
    print(f"    Mean: {np.mean(h):.1f} ms")

    print(f"\n  SET Overhead (paper headline figures):")
    print(f"    P50 delta : {overhead_p50:.1f} ms")
    print(f"    P95 delta : {overhead_p95:.1f} ms  <-- paper headline figure")
    print("-" * 55)
    print("Paper disclosure statement:")
    print("  SET channel handshake overhead was measured on an x86-64")
    print("  Ubuntu 22.04 host via 100 loopback TLS 1.3 handshakes per")
    print("  variant using OpenSSL 3.x with the OQS provider.")
    print("  ARM Cortex-A76 class devices are expected to show 1.5 to 2x")
    print("  higher absolute latency with a proportionally similar delta.")


if __name__ == "__main__":
    main()
