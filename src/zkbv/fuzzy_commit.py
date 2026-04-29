"""
ZKBV — Fuzzy Commitment Scheme
================================
Implements the error-tolerant biometric commitment described in Section IV.C.

Construction (Juels & Wattenberg, 1999 [8]):
  Enrollment:
    1. Extract feature vector b ∈ {0,1}^n from biometric sample.
    2. Select random codeword c from BCH(2047, 1723).
    3. Compute commitment δ = b ⊕ c.
    4. Store (δ, H(c)) server-side. Do NOT store b.

  Verification (client side, input to ZKBV circuit):
    1. Capture probe b' (slightly different from b due to sensor noise).
    2. Compute c' = b' ⊕ δ = b' ⊕ b ⊕ c.
    3. If hamming(b, b') ≤ τ, then hamming(c, c') ≤ τ, and BCH can recover c.
    4. Recover c̃ = BCH_decode(c').
    5. If H(c̃) == H(c), the biometric is verified.
    6. Use c̃ as the witness for the ZKBV Groth16 proof.

Privacy guarantee:
  δ reveals no information about b beyond what can be derived from b ⊕ c
  where c is a uniformly random codeword. The server only stores δ and H(c).
  Template unlinkability follows from Definition 3 / Equation (3).

BCH parameters (paper, Section IV.C and VI.A):
  n=2047, k=1723 → t=46 error-correcting capacity.
  With τ=307 bit Hamming tolerance (15% of 2048), use t=154 BCH
  or a concatenated scheme; exact parameters match the circuit definition
  in src/zkbv/hamming_distance.circom.

Note on BCH implementation:
  This module uses a pure-Python BCH library for portability.
  Install: pip install bchlib
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Tuple, Optional

import numpy as np

try:
    import bchlib
    BCH_AVAILABLE = True
except ImportError:
    BCH_AVAILABLE = False


FEATURE_BITS = 2048      # Length of the biometric feature vector
BCH_N        = 2047      # BCH codeword length (bits)
BCH_T        = 46        # BCH error-correcting capacity (bits)
TAU          = 307       # Hamming distance threshold (15% of 2048)


@dataclass
class CommitmentParams:
    """Enrollment-time commitment. Stored server-side."""
    delta:       bytes    # b ⊕ c  (n bits, stored as bytes)
    hash_c:      str      # SHA-256(c) hex — server-side verification anchor
    feature_len: int      # Must match FEATURE_BITS at verification time

    def to_dict(self) -> dict:
        return {
            "delta":       self.delta.hex(),
            "hash_c":      self.hash_c,
            "feature_len": self.feature_len,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CommitmentParams":
        return cls(
            delta       = bytes.fromhex(d["delta"]),
            hash_c      = d["hash_c"],
            feature_len = d["feature_len"],
        )


class FuzzyCommitment:
    """
    BCH-based fuzzy commitment for biometric template protection.

    Example:
        fc = FuzzyCommitment()

        # Enrollment (run once, store params server-side)
        b_enrolled = extract_feature_vector(biometric_sample)
        params = fc.commit(b_enrolled)

        # Verification (run at each authentication, client side)
        b_probe = extract_feature_vector(new_biometric_sample)
        c_recovered, ok = fc.open(b_probe, params)
        if ok:
            # Use c_recovered as ZKBV circuit witness
            proof = zkbv_prover.prove(b_probe, c_recovered, params)
    """

    def commit(self, feature_vector: np.ndarray) -> CommitmentParams:
        """
        Generate a fuzzy commitment for an enrolled biometric feature vector.

        Parameters
        ----------
        feature_vector: Binary array of length FEATURE_BITS (dtype uint8, values 0/1).

        Returns
        -------
        CommitmentParams to be stored server-side.
        """
        if len(feature_vector) != FEATURE_BITS:
            raise ValueError(f"Feature vector must be {FEATURE_BITS} bits, "
                             f"got {len(feature_vector)}")

        b = np.asarray(feature_vector, dtype=np.uint8)

        # Generate random BCH codeword
        c = self._random_codeword()

        # δ = b ⊕ c (XOR commitment)
        delta_bits = np.bitwise_xor(b[:BCH_N], c)
        delta_bytes = np.packbits(delta_bits).tobytes()

        # Store H(c) for verification
        c_bytes  = np.packbits(c).tobytes()
        hash_c   = hashlib.sha256(c_bytes).hexdigest()

        return CommitmentParams(
            delta       = delta_bytes,
            hash_c      = hash_c,
            feature_len = FEATURE_BITS,
        )

    def open(
        self,
        probe_vector: np.ndarray,
        params:       CommitmentParams,
    ) -> Tuple[Optional[np.ndarray], bool]:
        """
        Attempt to recover the committed codeword c from a probe vector.

        Parameters
        ----------
        probe_vector: Binary array of length FEATURE_BITS from probe capture.
        params:       CommitmentParams from enrollment.

        Returns
        -------
        (c_recovered, success) where c_recovered is the BCH codeword if
        successful (for use as ZKBV circuit witness), or None if failed.
        """
        b_prime  = np.asarray(probe_vector[:BCH_N], dtype=np.uint8)
        delta_bits = np.unpackbits(np.frombuffer(params.delta, dtype=np.uint8))

        # c' = b' ⊕ δ = b' ⊕ (b ⊕ c)
        c_prime  = np.bitwise_xor(b_prime, delta_bits[:BCH_N])
        c_prime_bytes = np.packbits(c_prime).tobytes()

        # BCH error correction: recover c from c'
        c_recovered_bytes = self._bch_decode(c_prime_bytes)
        if c_recovered_bytes is None:
            return None, False

        # Verify: H(c_recovered) == H(c)
        actual_hash = hashlib.sha256(c_recovered_bytes).hexdigest()
        if actual_hash != params.hash_c:
            return None, False

        c_recovered = np.unpackbits(np.frombuffer(c_recovered_bytes, dtype=np.uint8))
        return c_recovered[:BCH_N], True

    # ── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _random_codeword() -> np.ndarray:
        """Generate a random valid BCH(2047, 1723) codeword."""
        if not BCH_AVAILABLE:
            # Fallback: use random bits (no error correction — for testing only)
            return np.frombuffer(os.urandom(BCH_N // 8 + 1),
                                  dtype=np.uint8)[:BCH_N // 8 * 8][:BCH_N]

        bch    = bchlib.BCH(BCH_T, prim_poly=None, m=11)  # GF(2^11) for n=2047
        # Random information bits (k=1723)
        info   = np.frombuffer(os.urandom(bch.k // 8 + 1),
                                dtype=np.uint8)[:bch.k]
        # Encode to get systematic codeword
        parity = bch.encode(info.tobytes())
        codeword = np.unpackbits(np.frombuffer(info.tobytes() + parity,
                                                dtype=np.uint8))
        return codeword[:BCH_N]

    @staticmethod
    def _bch_decode(c_prime_bytes: bytes) -> Optional[bytes]:
        """Attempt BCH(2047, 1723, t=46) error correction."""
        if not BCH_AVAILABLE:
            # Without bchlib, return as-is (no correction)
            return c_prime_bytes

        try:
            bch = bchlib.BCH(BCH_T, prim_poly=None, m=11)
            data, ecc = c_prime_bytes[:bch.k // 8], c_prime_bytes[bch.k // 8:]
            bitflips  = bch.decode(data, ecc)
            if bitflips < 0:
                return None   # Uncorrectable error (too many bit-flips; non-match)
            bch.correct(data, ecc)
            return data
        except Exception:
            return None
