"""
ZKBV — Groth16 Verifier
========================
Server-side Groth16 proof verification for the ZKBV component.
Runs on the authentication module (~2 ms P95 on x86-64).

Accepts: proof_dict + public_inputs_dict transmitted by the prover.
Rejects: any proof that fails Groth16 verification or carries an
         incorrect session nonce.

Privacy guarantee:
  The verifier never receives or stores biometric template data.
  It only sees the proof (pi_a, pi_b, pi_c) and public inputs (nonce, tau).
  Session-specific nonces ensure proofs are non-replayable (SG-4).
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


DEFAULT_VKEY  = Path(__file__).parent / "verification_key.json"


class ZKBVVerifier:
    """
    Server-side Groth16 verifier for ZKBV biometric proofs.

    Usage:
        verifier = ZKBVVerifier()

        ok = verifier.verify(
            proof          = proof_dict,
            public_inputs  = public_inputs_dict,
            session_nonce  = expected_nonce,
        )
        if not ok:
            raise AuthenticationError("ZKBV: proof verification failed")
    """

    def __init__(self, vkey_path: Optional[str] = None):
        self.vkey_path = str(vkey_path or DEFAULT_VKEY)
        if not os.path.exists(self.vkey_path):
            raise FileNotFoundError(
                f"Verification key not found: {self.vkey_path}\n"
                "Run: snarkjs zkey export verificationkey "
                "src/zkbv/hamming_distance_final.zkey "
                "src/zkbv/verification_key.json"
            )

    def verify(
        self,
        proof:          dict,
        public_inputs:  dict,
        session_nonce:  str,
    ) -> bool:
        """
        Verify a Groth16 proof from the ZKBV prover.

        Parameters
        ----------
        proof:          Groth16 proof dict (pi_a, pi_b, pi_c).
        public_inputs:  Public circuit inputs from the prover.
        session_nonce:  The nonce issued for this session (freshness check).

        Returns
        -------
        True if the proof is valid and the session nonce matches.
        False (or raises) otherwise.

        Security note:
          A valid proof guarantees (under Groth16 soundness) that the prover
          knows a biometric probe b' within distance τ of the enrolled template.
          The nonce check additionally ensures the proof was generated for
          THIS session and cannot be replayed from a prior session (SG-4).
        """
        # Nonce freshness check (SG-4)
        if not self._check_nonce(public_inputs, session_nonce):
            return False

        # Groth16 proof verification via snarkjs
        return self._snarkjs_verify(proof, public_inputs)

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _check_nonce(public_inputs: dict, expected_nonce: str) -> bool:
        """
        Verify the session nonce embedded in the public inputs matches
        the nonce issued by the authentication module for this session.
        """
        proof_nonce = public_inputs.get("session_nonce", "")
        return proof_nonce == expected_nonce

    def _snarkjs_verify(self, proof: dict, public_inputs: dict) -> bool:
        """Run snarkjs groth16 verify and return True if OK."""
        with tempfile.TemporaryDirectory() as tmpdir:
            proof_path  = os.path.join(tmpdir, "proof.json")
            public_path = os.path.join(tmpdir, "public.json")

            with open(proof_path,  "w") as f: json.dump(proof,         f)
            with open(public_path, "w") as f: json.dump(public_inputs, f)

            result = subprocess.run(
                ["snarkjs", "groth16", "verify",
                 self.vkey_path, public_path, proof_path],
                capture_output=True, text=True,
            )

        return result.returncode == 0 and "OK" in result.stdout
