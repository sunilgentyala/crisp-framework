"""
BEM — Session Monitor
======================
Continuous session-level anomaly detection using entropy features.

The BEMMonitor maintains a rolling window of frame entropy scores
across an authentication session. It raises an anomaly flag when the
measured entropy diverges from the authenticated-sensor baseline by
more than the calibrated threshold ε_BEM.

The threshold is calibrated offline against authentic sensor frames
and adversary simulator output (StyleGAN3, Stable Diffusion XL) to
achieve BPCER < 1.5% while keeping APCER < 0.3% (Section VI.C).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

import numpy as np

from .entropy import EntropyFeatures, extract_features


# Default threshold calibrated against StyleGAN3 + SDXL adversary simulators.
# Recalibrate for new synthesis architectures (Section VII.A limitation).
DEFAULT_THRESHOLD = 0.85

# Number of frames per analysis window (30 frames ≈ 1 second at 30 fps)
WINDOW_SIZE = 30


@dataclass
class BEMResult:
    """
    Result of a single BEM window analysis.

    is_anomalous: True if the window is flagged as potentially synthetic.
    anomaly_score: Scalar score; higher = more synthetic-like.
    threshold:     Calibrated decision threshold (stored for audit logging).
    window_index:  Sequential window number within the session.
    features:      Detailed entropy features (for logging / debugging).
    """
    is_anomalous:  bool
    anomaly_score: float
    threshold:     float
    window_index:  int
    features:      Optional[EntropyFeatures] = None
    timestamp:     float = field(default_factory=time.time)


class BEMMonitor:
    """
    Continuous behavioral entropy monitor for an authentication session.

    Typical usage (called from the authentication module):

        monitor = BEMMonitor(threshold=0.85)
        session_ok = True

        for frame_batch in stream_biometric_frames(window_size=30):
            result = monitor.analyze_window(frame_batch)
            if result.is_anomalous:
                session_ok = False
                audit_log(result)
                break   # or accumulate for majority vote

        if not session_ok:
            reject_authentication()
    """

    def __init__(
        self,
        threshold:          float = DEFAULT_THRESHOLD,
        window_size:        int   = WINDOW_SIZE,
        use_perf_counters:  bool  = False,
    ):
        self.threshold         = threshold
        self.window_size       = window_size
        self.use_perf_counters = use_perf_counters
        self._results:  List[BEMResult] = []
        self._window_count: int = 0

    def analyze_window(self, frames: List[np.ndarray]) -> BEMResult:
        """
        Analyze a window of biometric frames for synthetic-stream signatures.

        Parameters
        ----------
        frames: List of grayscale 2D uint8 arrays, len ≥ 2.

        Returns
        -------
        BEMResult with is_anomalous=True if the window exceeds the threshold.
        """
        features = extract_features(frames, use_perf_counters=self.use_perf_counters)
        score    = features.anomaly_score
        flagged  = score > self.threshold

        result = BEMResult(
            is_anomalous  = flagged,
            anomaly_score = score,
            threshold     = self.threshold,
            window_index  = self._window_count,
            features      = features,
        )
        self._results.append(result)
        self._window_count += 1
        return result

    def session_verdict(self, majority_vote: bool = True) -> bool:
        """
        Return True if the session is clean (no anomaly detected).

        Parameters
        ----------
        majority_vote: If True, flag only if >50% of windows are anomalous.
                       If False, flag on ANY anomalous window (stricter).

        Returns
        -------
        True = session is clean. False = session flagged as potentially synthetic.
        """
        if not self._results:
            return True   # No data — assume clean (SA/SET already validated)

        n_flagged = sum(1 for r in self._results if r.is_anomalous)

        if majority_vote:
            return (n_flagged / len(self._results)) <= 0.5
        else:
            return n_flagged == 0

    def reset(self) -> None:
        """Reset monitor state for a new authentication session."""
        self._results      = []
        self._window_count = 0

    def summary(self) -> dict:
        """Return a JSON-serializable session summary for audit logging."""
        if not self._results:
            return {"windows_analyzed": 0, "verdict": "clean"}

        scores = [r.anomaly_score for r in self._results]
        return {
            "windows_analyzed": len(self._results),
            "windows_flagged":  sum(1 for r in self._results if r.is_anomalous),
            "mean_score":       float(np.mean(scores)),
            "max_score":        float(np.max(scores)),
            "threshold":        self.threshold,
            "verdict":          "clean" if self.session_verdict() else "flagged",
        }
