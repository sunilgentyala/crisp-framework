"""
ZKBV — Groth16 Prover
======================
Generates a Groth16 zkSNARK proof demonstrating that probe b' lies
within Hamming distance τ of the committed biometric, without revealing b'.

The proof is generated client-side on the authenticating device and
transmitted (along with a session nonce) to the authentication module.
No biometric template content is transmitted.

Circuit: src/zkbv/hamming_distance.circom
  Inputs (private witness): enrolled[], probe[], tau
  Public inputs:             commitment_hash, session_nonce
  Statement: ∃ b' such that hamming(b', b) ≤ τ AND H(b' ⊕ c) = δ

Requires: snarkjs 0.7+, circom 2.1+
          npm install -g snarkjs
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import numpy as np


DEFAULT_ZKEY  = Path(__file__).parent / "hamming_distance_final.zkey"
DEFAULT_WASM  = Path(__file__).parent / "hamming_distance_js" / "hamming_distance.wasm"


class ZKBVProver:
    """
    Client-side Groth16 prover for the ZKBV biometric distance circuit.

    Usage:
        prover = ZKBVProver()

        # After fuzzy commitment opens successfully:
        proof, public_inputs = prover.prove(
            probe_bits    = b_prime,      # np.ndarray, shape (FEATURE_BITS,)
            enrolled_bits = b_enrolled,   # np.ndarray, shape (FEATURE_BITS,)
            session_nonce = nonce,        # 32-byte hex string from auth module
            tau           = 307,
        )
        # Transmit proof + public_inputs to auth module (no biometric content)
    """

    def __init__(
        self,
        zkey_path:  Optional[str] = None,
        wasm_path:  Optional[str] = None,
    ):
        self.zkey_path = str(zkey_path or DEFAULT_ZKEY)
        self.wasm_path = str(wasm_path or DEFAULT_WASM)
        self._check_prerequisites()

    def prove(
        self,
        probe_bits:    np.ndarray,
        enrolled_bits: np.ndarray,
        session_nonce: str,
        tau:           int = 307,
    ) -> tuple[dict, dict]:
        """
        Generate a Groth16 proof.

        Parameters
        ----------
        probe_bits:    Binary array (FEATURE_BITS,) from live biometric capture.
        enrolled_bits: Binary array (FEATURE_BITS,) from enrolled template.
        session_nonce: 32-byte hex nonce from the auth module (binds proof to session).
        tau:           Hamming distance threshold.

        Returns
        -------
        (proof_dict, public_inputs_dict)
          proof_dict:         Groth16 proof (pi_a, pi_b, pi_c) — safe to transmit.
          public_inputs_dict: Public circuit inputs (session_nonce, tau) — no biometrics.

        Privacy guarantee:
          proof_dict and public_inputs_dict contain NO biometric template data.
          Transmitting them to the server does not leak b or b'.
        """
        witness_input = self._build_witness_input(
            probe_bits, enrolled_bits, session_nonce, tau
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path   = os.path.join(tmpdir, "input.json")
            witness_path = os.path.join(tmpdir, "witness.wtns")
            proof_path   = os.path.join(tmpdir, "proof.json")
            public_path  = os.path.join(tmpdir, "public.json")

            with open(input_path, "w") as f:
                json.dump(witness_input, f)

            # Step 1: generate witness
            self._snarkjs([
                "wtns", "calculate",
                self.wasm_path, input_path, witness_path,
            ])

            # Step 2: Groth16 prove
            self._snarkjs([
                "groth16", "prove",
                self.zkey_path, witness_path, proof_path, public_path,
            ])

            with open(proof_path)  as f: proof         = json.load(f)
            with open(public_path) as f: public_inputs = json.load(f)

        return proof, public_inputs

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _build_witness_input(
        probe:    np.ndarray,
        enrolled: np.ndarray,
        nonce:    str,
        tau:      int,
    ) -> dict:
        """
        Build the circom input.json witness.
        Private inputs (enrolled, probe) are passed here but are NOT
        included in the proof or public inputs output.
        """
        return {
            "enrolled":     [str(int(b)) for b in enrolled],
            "probe":        [str(int(b)) for b in probe],
            "tau":          str(tau),
            "session_nonce": nonce,
        }

    def _check_prerequisites(self) -> None:
        """Check that snarkjs, wasm, and zkey are available."""
        try:
            result = subprocess.run(
                ["snarkjs", "--version"], capture_output=True, text=True
            )
            if result.returncode != 0:
                raise RuntimeError("snarkjs not found or returned error.")
        except FileNotFoundError:
            raise ImportError(
                "snarkjs not found. Install with: npm install -g snarkjs\n"
                "See benchmarks/BENCHMARK_GUIDE.md for full setup."
            )

        if not os.path.exists(self.zkey_path):
            raise FileNotFoundError(
                f"Proving key not found: {self.zkey_path}\n"
                "Run: python3 benchmarks/zkbv_bench.py --setup --ptau pot18_final.ptau"
            )

    @staticmethod
    def _snarkjs(args: list) -> None:
        result = subprocess.run(
            ["snarkjs"] + args, capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"snarkjs error: {result.stderr}\n"
                f"Command: snarkjs {' '.join(args)}"
            )
