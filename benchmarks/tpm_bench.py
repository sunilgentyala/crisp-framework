"""
CRISP Framework — Benchmark 1: TPM Quote Generation Latency
============================================================
Paper: "The Weaponization of Deepfakes: A Novel Cryptographic Framework
        Mitigating Biometric Injection and Identity Gaps"
Target Journal: IEEE Transactions on Information Forensics and Security

Description:
    Measures TPM 2.0 attestation quote generation latency over 1,000
    iterations using tpm2-tools against a software TPM (swtpm) endpoint.
    Reports P50, P95, and P99 latency in milliseconds.

Platform tested: x86-64 Ubuntu 22.04 (sunil@Quantumlabs)
TPM backend:     swtpm 0.7 (software TPM emulator)
Tool version:    tpm2-tools 5.4

Hardware note:
    swtpm results represent a lower bound. Dedicated hardware TPMs
    (e.g., Infineon SLB 9672) are expected to yield P95 latency of
    80 to 180 ms due to SPI bus communication overhead.

Prerequisites:
    sudo apt install -y swtpm tpm2-tools python3-numpy

Setup (run once before executing this script):
    mkdir -p /tmp/vtpm
    swtpm socket --tpmstate dir=/tmp/vtpm --tpm2 \\
      --server type=unixio,path=/tmp/vtpm/sock \\
      --ctrl type=unixio,path=/tmp/vtpm/sock.ctrl \\
      --flags not-need-init,startup-clear &
    export TPM2TOOLS_TCTI="swtpm:path=/tmp/vtpm/sock"
    tpm2_createprimary -C e -c /tmp/vtpm/primary.ctx
    tpm2_evictcontrol -C o -c /tmp/vtpm/primary.ctx 0x81000001

Usage:
    export TPM2TOOLS_TCTI="swtpm:path=/tmp/vtpm/sock"
    python3 tpm_bench.py
"""

import subprocess
import time
import sys
import numpy as np

ITERATIONS = 1000
TPM_HANDLE = "0x81000001"
PCR_LIST   = "sha256:0,1,2"
NONCE      = "cafebabe"


def run_tpm_quote() -> float:
    """
    Execute a single tpm2_quote command and return elapsed wall-clock
    time in milliseconds.
    """
    cmd = [
        "tpm2_quote",
        "-c", TPM_HANDLE,
        "-l", PCR_LIST,
        "-q", NONCE,
    ]
    t0 = time.perf_counter()
    result = subprocess.run(cmd, capture_output=True)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    if result.returncode != 0:
        print("ERROR: tpm2_quote failed. Ensure swtpm is running and the "
              "key handle exists. See script header for setup instructions.",
              file=sys.stderr)
        print(result.stderr.decode(), file=sys.stderr)
        sys.exit(1)

    return elapsed_ms


def main():
    print(f"CRISP Benchmark 1: TPM Quote Generation Latency")
    print(f"Platform : x86-64 Ubuntu 22.04")
    print(f"Backend  : swtpm 0.7 (software TPM)")
    print(f"Handle   : {TPM_HANDLE}")
    print(f"PCR list : {PCR_LIST}")
    print(f"Nonce    : {NONCE}")
    print(f"Iterations: {ITERATIONS}")
    print("-" * 50)
    print("Running benchmark... (this takes approximately 60 seconds)")

    times = []
    for i in range(ITERATIONS):
        times.append(run_tpm_quote())
        if (i + 1) % 100 == 0:
            print(f"  Completed {i + 1}/{ITERATIONS} iterations")

    arr = np.array(times)

    print("-" * 50)
    print("Results:")
    print(f"  P50 (median)  : {np.percentile(arr, 50):.1f} ms")
    print(f"  P95           : {np.percentile(arr, 95):.1f} ms  <-- paper headline figure")
    print(f"  P99           : {np.percentile(arr, 99):.1f} ms")
    print(f"  Mean          : {np.mean(arr):.1f} ms")
    print(f"  Std dev       : {np.std(arr):.1f} ms")
    print(f"  Min           : {np.min(arr):.1f} ms")
    print(f"  Max           : {np.max(arr):.1f} ms")
    print("-" * 50)
    print("Paper disclosure statement:")
    print("  TPM quote generation latency was measured using swtpm 0.7")
    print("  on an x86-64 Ubuntu 22.04 host. Dedicated hardware TPMs")
    print("  such as the Infineon SLB 9672 are expected to yield 80-180 ms")
    print("  at P95 due to SPI bus communication overhead.")


if __name__ == "__main__":
    main()
