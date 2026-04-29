"""
ZKBV — Zero-Knowledge Biometric Verification
=============================================
Component 3 of the CRISP framework.

Eliminates biometric template transmission from the authentication protocol.
The prover demonstrates knowledge of a biometric probe b' within distance τ
of an enrolled template b, without revealing b' or enabling recovery of b.

Security property: Template Unlinkability (SG-2)
  Unlink-Adv_ZKBV(D, λ) = | Pr[D(π₁, π₂) = b] - 1/2 | ≤ negl(λ)
  Under DDH over the Groth16 bilinear group (Equation 3).

ZK scheme:        Groth16 (succinct non-interactive argument of knowledge)
Circuit:          BCH(2047, 1723) Hamming distance over 2048-bit feature vector
Constraints:      ~48,000 R1CS constraints
Commitment:       Fuzzy commitment (Juels & Wattenberg, 1999)

References:
  [8]  A. Juels & M. Wattenberg, "A Fuzzy Commitment Scheme," CCS 1999.
  [9]  J. Groth, "On the Size of Pairing-Based NIAs," EUROCRYPT 2016.
  [10] C. Guo et al., "Biometric Auth via SVM and ZKP," Comput. Secur., 2024.
  [11] M. Gomez-Barrero et al., "Template Unlinkability Framework," TIFS 2018.
"""

from .fuzzy_commit import FuzzyCommitment, CommitmentParams
from .prover       import ZKBVProver
from .verifier     import ZKBVVerifier

__all__ = ["FuzzyCommitment", "CommitmentParams", "ZKBVProver", "ZKBVVerifier"]
