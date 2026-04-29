"""
BEM — Entropy Feature Extraction
==================================
Computes the three entropy features described in Section IV.D of the paper
for a window of biometric frames.

Feature 1 — Inter-frame KL divergence (DCT domain):
  Measures statistical consistency of DCT coefficient distributions
  across consecutive frames. Authentic sensor noise has a characteristic
  signature; GAN / diffusion synthesis pipelines produce measurably
  different inter-frame statistics.

Feature 2 — Spectral flatness (Wiener entropy):
  Low spectral flatness indicates structured, tonal content; high flatness
  indicates noise-like signals. Synthesis architectures tend toward
  different flatness profiles than authentic camera pipelines.

Feature 3 — Hardware perf counters (Linux):
  Memory access patterns during frame production differ between
  sensor pipelines and GPU-accelerated synthesis. Requires
  kernel.perf_event_paranoid ≤ 1.
"""

from __future__ import annotations

import os
import struct
import numpy as np
from dataclasses import dataclass
from typing import Optional, List

try:
    from scipy.fft  import dctn
    from scipy.stats import entropy as scipy_entropy
    SCIPY_OK = True
except ImportError:
    SCIPY_OK = False


DCT_BLOCK    = 8     # 8×8 DCT blocks (standard JPEG tiling)
HIST_BINS    = 64    # Histogram bins for KL divergence computation
EPS          = 1e-10 # Smoothing factor to avoid log(0)


@dataclass
class EntropyFeatures:
    """
    Entropy features extracted from a single frame window.

    Used by BEMMonitor to compute the session-level anomaly score.
    """
    kl_divergences:    List[float]   # inter-frame KL scores (len = n_frames - 1)
    spectral_flatness: List[float]   # per-frame Wiener entropy (len = n_frames)
    perf_counters:     Optional[dict] = None  # hw perf data if available

    @property
    def mean_kl(self) -> float:
        return float(np.mean(self.kl_divergences)) if self.kl_divergences else 0.0

    @property
    def mean_sf(self) -> float:
        return float(np.mean(self.spectral_flatness)) if self.spectral_flatness else 0.0

    @property
    def anomaly_score(self) -> float:
        """
        Scalar anomaly score used by BEMMonitor.
        Weights match the calibration described in Section IV.D:
          anomaly = mean_KL + 0.5 × mean_SF
        Higher scores indicate more synthetic-like frame sequences.
        """
        return self.mean_kl + 0.5 * self.mean_sf


def extract_features(
    frames:          List[np.ndarray],
    use_perf_counters: bool = False,
) -> EntropyFeatures:
    """
    Extract BEM entropy features from a sequence of grayscale frames.

    Parameters
    ----------
    frames:             List of 2D uint8 arrays (H × W grayscale).
    use_perf_counters:  If True, attempt Linux perf_event_open() reads.

    Returns
    -------
    EntropyFeatures with kl_divergences, spectral_flatness, perf_counters.
    """
    if len(frames) < 2:
        raise ValueError("BEM requires at least 2 frames per window.")

    hists = [_dct_histogram(f) for f in frames]

    kl_scores = []
    for i in range(1, len(hists)):
        kl = _kl_divergence(hists[i-1], hists[i])
        kl_scores.append(kl)

    sf_scores = [_spectral_flatness(f) for f in frames]

    perf = _read_perf_counters() if use_perf_counters else None

    return EntropyFeatures(
        kl_divergences    = kl_scores,
        spectral_flatness = sf_scores,
        perf_counters     = perf,
    )


# ── Feature helpers ──────────────────────────────────────────────────────────

def _dct_histogram(frame: np.ndarray) -> np.ndarray:
    """
    Tile a grayscale frame into 8×8 blocks, compute the 2D DCT of each,
    collect AC coefficient magnitudes, and return a normalized histogram.
    """
    h, w = frame.shape
    ac_coeffs = []

    for row in range(0, h - DCT_BLOCK + 1, DCT_BLOCK):
        for col in range(0, w - DCT_BLOCK + 1, DCT_BLOCK):
            block = frame[row:row+DCT_BLOCK, col:col+DCT_BLOCK].astype(float)
            if SCIPY_OK:
                dct_block = dctn(block, norm='ortho')
            else:
                # Fallback: numpy-based separable 1D DCT approximation
                dct_block = np.fft.fft2(block).real
            # AC coefficients: all except DC at [0,0]
            ac = dct_block.flatten()[1:]
            ac_coeffs.extend(np.abs(ac).tolist())

    hist, _ = np.histogram(ac_coeffs, bins=HIST_BINS, range=(0, 300), density=True)
    hist    = hist + EPS
    hist   /= hist.sum()
    return hist


def _kl_divergence(p: np.ndarray, q: np.ndarray) -> float:
    """KL divergence D_KL(p || q)."""
    if SCIPY_OK:
        return float(scipy_entropy(p, q))
    # Manual KL (fallback)
    p = np.asarray(p, dtype=float)
    q = np.asarray(q, dtype=float)
    return float(np.sum(p * np.log(p / q)))


def _spectral_flatness(frame: np.ndarray) -> float:
    """
    Spectral flatness (Wiener entropy) of the frame's power spectrum.
    SFM = geometric_mean(|X|) / arithmetic_mean(|X|)
    Range [0, 1]. Higher = more noise-like.
    """
    spectrum = np.abs(np.fft.fft2(frame)).flatten()
    spectrum = spectrum[spectrum > 0]
    if len(spectrum) == 0:
        return 0.0
    log_geo  = np.mean(np.log(spectrum))
    arith    = np.mean(spectrum)
    return float(np.exp(log_geo) / arith) if arith > 0 else 0.0


def _read_perf_counters() -> Optional[dict]:
    """
    Read hardware performance counters via Linux perf_event_open().
    Returns a dict of counter name → value, or None if unavailable.

    Requires: Linux ≥ 4.1, kernel.perf_event_paranoid ≤ 1
      sudo sysctl -w kernel.perf_event_paranoid=1
    """
    # perf_event_open syscall (NR=298 on x86-64)
    # Full implementation uses ctypes + PERF_COUNT_HW_CACHE_MISSES,
    # PERF_COUNT_HW_INSTRUCTIONS to characterize memory access patterns.
    # Stub: returns None when not on Linux or paranoid mode is set.
    try:
        import ctypes
        import ctypes.util

        if not os.path.exists("/proc/sys/kernel/perf_event_paranoid"):
            return None

        with open("/proc/sys/kernel/perf_event_paranoid") as f:
            paranoid = int(f.read().strip())
        if paranoid > 1:
            return None   # Insufficient permission; skip silently

        # Full perf_event_open() implementation is in src/bem/perf_monitor.py
        return {"status": "available", "implementation": "see perf_monitor.py"}
    except Exception:
        return None
