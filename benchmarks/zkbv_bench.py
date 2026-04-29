"""
CRISP Framework — Benchmark 3: ZKBV Groth16 Proving and Verification Time
==========================================================================
Paper: "The Weaponization of Deepfakes: A Novel Cryptographic Framework
        Mitigating Biometric Injection and Identity Gaps"
Target Journal: IEEE Transactions on Information Forensics and Security

Description:
    Measures Groth16 zkSNARK proving and verification time for the ZKBV
    biometric distance circuit over 100 iterations. The circuit encodes
    a Hamming distance check over a 2048-bit feature vector with
    BCH(2047, 1723) error correction, comprising approximately 48,000
    R1CS constraints.

    Two sub-benchmarks are reported:
      (a) Proving time   — performed client-side on the authenticating device
      (b) Verification time — performed server-side (authentication module)

    Paper headline figure: Groth16 verification time on x86-64 (target: <2 ms).
    ARM Cortex-A76 proving time is the open measurement item (Section VII).

Circuit:
    The ZKBV circuit is defined in src/zkbv/hamming_distance.circom.
    It proves knowledge of a biometric probe b' such that:
        hamming_distance(b', committed_value) <= tau
    without revealing b'.

Prerequisites:
    node >= 18, snarkjs (npm install -g snarkjs)
    circom >= 2.1  (see https://docs.circom.io/getting-started/installation/)
    Python 3.12+, numpy

    A compiled circuit proving key (zkey) must exist at:
        src/zkbv/hamming_distance_final.zkey
    Run `python3 benchmarks/zkbv_bench.py --setup` for a one-time trusted
    setup using a pre-existing powers-of-tau file.

Usage:
    # One-time circuit compilation and trusted setup:
    python3 benchmarks/zkbv_bench.py --setup --ptau pot18_final.ptau

    # Benchmark prove + verify cycles:
    python3 benchmarks/zkbv_bench.py

    # Benchmark verify only (faster, relevant for server-side):
    python3 benchmarks/zkbv_bench.py --verify-only

Hardware note:
    Proving time scales roughly linearly with constraint count and inversely
    with CPU clock speed. x86-64 Zen 4 or Apple M-series results are not
    representative of ARM Cortex-A76 class devices; run on the target platform
    for paper-quality figures.
"""

import argparse
import subprocess
import time
import json
import sys
import os
import tempfile
import numpy as np

ITERATIONS     = 100
CIRCUIT_DIR    = os.path.join(os.path.dirname(__file__), '..', 'src', 'zkbv')
ZKEY_PATH      = os.path.join(CIRCUIT_DIR, 'hamming_distance_final.zkey')
VKEY_PATH      = os.path.join(CIRCUIT_DIR, 'verification_key.json')
WASM_PATH      = os.path.join(CIRCUIT_DIR, 'hamming_distance_js',
                               'hamming_distance.wasm')
# Feature vector length matching BCH(2047, 1723) scheme (2048 bits = 256 bytes)
FEATURE_BITS   = 2048
TAU            = 307  # ~15% Hamming error tolerance


def _run(cmd, **kwargs):
    """Run a shell command, exit on failure."""
    result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        print(f"ERROR running: {' '.join(cmd)}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result


def generate_input(seed: int = 42) -> dict:
    """
    Generate a synthetic witness input for the ZKBV circuit.
    In production, b_prime is derived from an actual biometric capture.
    """
    rng = np.random.default_rng(seed)
    enrolled = rng.integers(0, 2, size=FEATURE_BITS).tolist()

    # Introduce TAU random bit-flips to simulate a genuine but slightly
    # different capture of the same biometric subject.
    probe = enrolled.copy()
    flip_indices = rng.choice(FEATURE_BITS, size=TAU, replace=False)
    for idx in flip_indices:
        probe[idx] ^= 1

    return {
        "enrolled": [str(b) for b in enrolled],
        "probe":    [str(b) for b in probe],
        "tau":      str(TAU),
    }


def prove_once(input_path: str, proof_path: str, public_path: str) -> float:
    """Generate one Groth16 proof. Returns elapsed ms."""
    t0 = time.perf_counter()
    _run([
        "snarkjs", "groth16", "prove",
        ZKEY_PATH, input_path, proof_path, public_path,
    ])
    return (time.perf_counter() - t0) * 1000


def verify_once(proof_path: str, public_path: str) -> float:
    """Verify one Groth16 proof. Returns elapsed ms."""
    t0 = time.perf_counter()
    result = _run([
        "snarkjs", "groth16", "verify",
        VKEY_PATH, public_path, proof_path,
    ])
    elapsed = (time.perf_counter() - t0) * 1000
    if "OK" not in result.stdout:
        print("WARNING: Proof verification returned non-OK", file=sys.stderr)
    return elapsed


def run_setup(ptau_path: str):
    """One-time circuit compilation and Groth16 trusted setup."""
    print("ZKBV trusted setup — this may take several minutes...")
    circom_src = os.path.join(CIRCUIT_DIR, 'hamming_distance.circom')
    r1cs_path  = os.path.join(CIRCUIT_DIR, 'hamming_distance.r1cs')
    zkey_0     = os.path.join(CIRCUIT_DIR, 'hamming_distance_0000.zkey')

    print("  Step 1/4: Compiling circom circuit...")
    _run(["circom", circom_src, "--r1cs", "--wasm", "--sym",
          "-o", CIRCUIT_DIR])

    print("  Step 2/4: Groth16 setup phase 1...")
    _run(["snarkjs", "groth16", "setup", r1cs_path, ptau_path, zkey_0])

    print("  Step 3/4: Contributing to phase 2 ceremony...")
    _run(["snarkjs", "zkey", "contribute", zkey_0, ZKEY_PATH,
          "--name=CRISP benchmark setup", "-e=random entropy"])

    print("  Step 4/4: Exporting verification key...")
    _run(["snarkjs", "zkey", "export", "verificationkey", ZKEY_PATH, VKEY_PATH])

    print(f"Setup complete. Proving key: {ZKEY_PATH}")


def main():
    parser = argparse.ArgumentParser(description='CRISP ZKBV Groth16 Benchmark')
    parser.add_argument('--setup', action='store_true',
                        help='Run one-time circuit compilation and trusted setup')
    parser.add_argument('--ptau', default='pot18_final.ptau',
                        help='Path to powers-of-tau file (for --setup)')
    parser.add_argument('--verify-only', action='store_true',
                        help='Benchmark verify time only (pre-generate proofs)')
    parser.add_argument('--iterations', type=int, default=ITERATIONS)
    args = parser.parse_args()

    if args.setup:
        run_setup(args.ptau)
        return

    for req in [ZKEY_PATH, VKEY_PATH, WASM_PATH]:
        if not os.path.exists(req):
            print(f"ERROR: Required file not found: {req}", file=sys.stderr)
            print("Run with --setup first.", file=sys.stderr)
            sys.exit(1)

    print("CRISP Benchmark 3: ZKBV Groth16 Proving + Verification Time")
    print(f"Circuit       : hamming_distance.circom (~48K R1CS constraints)")
    print(f"Feature bits  : {FEATURE_BITS}")
    print(f"Error threshold (tau): {TAU} bits (~{TAU/FEATURE_BITS:.0%})")
    print(f"Iterations    : {args.iterations}")
    print("-" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path  = os.path.join(tmpdir, 'input.json')
        proof_path  = os.path.join(tmpdir, 'proof.json')
        public_path = os.path.join(tmpdir, 'public.json')

        inp = generate_input()
        with open(input_path, 'w') as f:
            json.dump(inp, f)

        prove_times  = []
        verify_times = []

        if not args.verify_only:
            print("Phase 1: Proving...")
            for i in range(args.iterations):
                t = prove_once(input_path, proof_path, public_path)
                prove_times.append(t)
                if (i + 1) % 10 == 0:
                    print(f"  Proving: {i+1}/{args.iterations} "
                          f"(last: {t:.0f} ms)")
        else:
            # Pre-generate one proof for verify-only mode
            prove_once(input_path, proof_path, public_path)

        print("Phase 2: Verifying...")
        for i in range(args.iterations):
            t = verify_once(proof_path, public_path)
            verify_times.append(t)
            if (i + 1) % 25 == 0:
                print(f"  Verifying: {i+1}/{args.iterations} (last: {t:.2f} ms)")

    print("-" * 60)
    print("Results:")

    if prove_times:
        pt = np.array(prove_times)
        print(f"\n  Groth16 Proving (client-side):")
        print(f"    P50  : {np.percentile(pt, 50):.0f} ms")
        print(f"    P95  : {np.percentile(pt, 95):.0f} ms  <-- paper headline figure")
        print(f"    P99  : {np.percentile(pt, 99):.0f} ms")
        print(f"    Mean : {np.mean(pt):.0f} ms")
        print(f"    Std  : {np.std(pt):.0f} ms")

    vt = np.array(verify_times)
    print(f"\n  Groth16 Verification (server-side):")
    print(f"    P50  : {np.percentile(vt, 50):.2f} ms")
    print(f"    P95  : {np.percentile(vt, 95):.2f} ms  <-- paper headline figure")
    print(f"    P99  : {np.percentile(vt, 99):.2f} ms")
    print(f"    Mean : {np.mean(vt):.2f} ms")

    print("-" * 60)
    print("Paper disclosure statement:")
    print("  Proving time is hardware-dependent and should be measured on")
    print("  the target ARM Cortex-A76 class device for paper-quality figures.")
    print("  Verification time reported above is for x86-64; ARM figures")
    print("  should be obtained separately.")


if __name__ == '__main__':
    main()
