"""
BEM — Behavioral Entropy Monitor
==================================
Component 4 of the CRISP framework.

Provides a detection layer independent of the SA cryptographic checks.
Operates on the statistical properties of biometric frame sequences,
exploiting the observation that synthetically generated video exhibits
distinct distributional signatures even when visually indistinguishable
from authentic sensor output.

Features computed per frame sequence:
  (1) Inter-frame KL divergence of DCT coefficient frequency distributions
  (2) Spectral flatness measure (Wiener entropy) of the frame sequence
  (3) Hardware performance counter readings (Linux perf_event_open)

Security property: Synthetic stream detection (complements SA/SG-3)
  BEM raises an anomaly flag when entropy diverges from the
  authenticated-sensor baseline by more than calibrated threshold ε_BEM.

The BEM adversarial detection bound ε_BEM is the probability that BEM
fails to flag a synthetic stream, and appears in Theorem 1 (Equation 4).
"""

from .monitor  import BEMMonitor, BEMResult
from .entropy  import EntropyFeatures

__all__ = ["BEMMonitor", "BEMResult", "EntropyFeatures"]
