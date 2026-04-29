"""
CRISP Framework — Benchmark 4: BEM Behavioral Entropy Monitor Throughput
=========================================================================
Paper: "The Weaponization of Deepfakes: A Novel Cryptographic Framework
        Mitigating Biometric Injection and Identity Gaps"
Target Journal: IEEE Transactions on Information Forensics and Security

Description:
    Measures the per-frame processing throughput of the Behavioral Entropy
    Monitor (BEM), which operates as a continuous session-level synthetic
    stream detector. BEM computes three features per frame:

      (1) Inter-frame Kullback-Leibler divergence of DCT coefficient
          frequency distributions across 8×8 blocks.
      (2) Spectral flatness measure (Wiener entropy) of the frame sequence.
      (3) (Optional) Hardware performance counter readings for memory
          access pattern characterization during frame production.

    This benchmark measures:
      (a) Per-frame BEM latency at P50, P95, and P99.
      (b) APCER and BPCER against StyleGAN3 and SDXL synthetic frames vs.
          authentic camera frames (if frame directories are provided).
      (c) Anomaly threshold calibration (D-EER operating point).

    Target: Per-frame BEM processing < 2 ms P95, ensuring it does not
    materially constrain the 47 ms end-to-end authentication budget.

Prerequisites:
    pip install numpy scipy Pillow
    For hardware perf counters: Linux ≥ 4.1, kernel.perf_event_paranoid ≤ 1

    Authentic frame directory: real camera captures (PNG/JPG, 30+ frames)
    Synthetic frame directory: StyleGAN3 or SDXL portrait output frames

Usage:
    # Latency benchmark only (uses synthetic Gaussian noise frames):
    python3 benchmarks/bem_bench.py

    # Full APCER/BPCER evaluation with real frames:
    python3 benchmarks/bem_bench.py \\
        --authentic /path/to/real_frames/ \\
        --synthetic /path/to/synth_frames/ \\
        --iterations 1000

    # With hardware perf counters (Linux only, requires root or sysctl):
    sudo sysctl -w kernel.perf_event_paranoid=1
    python3 benchmarks/bem_bench.py --perf-counters
"""

import argparse
import time
import sys
import os
import numpy as np
from pathlib import Path

try:
    from scipy import fft as sfft
    from scipy.stats import entropy as kl_divergence
    SCIPY_AVAILABLE = True
except ImportError:
    print("WARNING: scipy not found. Install with: pip install scipy", file=sys.stderr)
    SCIPY_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# BEM configuration (mirrors paper description)
BEM_DCT_BLOCK  = 8       # 8×8 DCT block size
BEM_HIST_BINS  = 64      # Histogram bins for KL divergence
BEM_THRESHOLD  = None    # Calibrated at runtime; set to a float to fix it

# Paper-reported error rates (targets)
APCER_TARGET   = 0.003   # 0.3%
BPCER_TARGET   = 0.015   # 1.5%


def dct2(block: np.ndarray) -> np.ndarray:
    """2D DCT via separable 1D DCT."""
    if SCIPY_AVAILABLE:
        return sfft.dctn(block, norm='ortho')
    # Fallback: manual via numpy (slower)
    M = np.zeros_like(block, dtype=float)
    N = block.shape[0]
    for u in range(N):
        for v in range(N):
            s = 0.0
            for x in range(N):
                for y in range(N):
                    s += block[x, y] * np.cos(np.pi*u*(2*x+1)/(2*N)) * \
                         np.cos(np.pi*v*(2*y+1)/(2*N))
            M[u, v] = s
    return M


def frame_dct_histogram(frame_gray: np.ndarray) -> np.ndarray:
    """
    Tile a grayscale frame into 8x8 blocks, compute DCT of each block,
    and return a histogram of the AC coefficient magnitudes.
    """
    h, w = frame_gray.shape
    bh, bw = BEM_DCT_BLOCK, BEM_DCT_BLOCK
    coeffs = []
    for i in range(0, h - bh + 1, bh):
        for j in range(0, w - bw + 1, bw):
            block = frame_gray[i:i+bh, j:j+bw].astype(float)
            dct_block = dct2(block)
            # Collect AC coefficients (exclude DC at [0,0])
            ac = dct_block.flatten()[1:]
            coeffs.extend(np.abs(ac).tolist())

    hist, _ = np.histogram(coeffs, bins=BEM_HIST_BINS, range=(0, 500),
                            density=True)
    # Smooth to avoid zero bins in KL
    hist += 1e-10
    hist /= hist.sum()
    return hist


def spectral_flatness(frame_gray: np.ndarray) -> float:
    """
    Compute spectral flatness (Wiener entropy) of the frame's power spectrum.
    Values near 1 indicate noise-like signals; values near 0 indicate tonal content.
    Authentic sensor frames tend toward lower flatness than synthetic frames.
    """
    spectrum = np.abs(np.fft.fft2(frame_gray)).flatten()
    spectrum = spectrum[spectrum > 0]
    geom_mean = np.exp(np.mean(np.log(spectrum)))
    arith_mean = np.mean(spectrum)
    return float(geom_mean / arith_mean) if arith_mean > 0 else 0.0


def compute_bem_features(frames: list[np.ndarray]) -> dict:
    """
    Compute BEM features for a sequence of frames.
    Returns a dict with 'kl_divergences', 'spectral_flatness', 'anomaly_score'.
    """
    if len(frames) < 2:
        raise ValueError("BEM requires at least 2 frames for inter-frame KL.")

    hists = [frame_dct_histogram(f) for f in frames]
    kl_scores = []
    for i in range(1, len(hists)):
        if SCIPY_AVAILABLE:
            kl = float(kl_divergence(hists[i-1], hists[i]))
        else:
            kl = float(np.sum(hists[i-1] * np.log(hists[i-1] / hists[i])))
        kl_scores.append(kl)

    sf_scores = [spectral_flatness(f) for f in frames]

    # Anomaly score: linear combination (weights calibrated empirically)
    anomaly = np.mean(kl_scores) + 0.5 * np.mean(sf_scores)
    return {
        'kl_divergences': kl_scores,
        'spectral_flatness': sf_scores,
        'anomaly_score': anomaly,
    }


def generate_synthetic_frame(seed: int, size: tuple = (224, 224)) -> np.ndarray:
    """Synthetic Gaussian noise frame for latency benchmarking."""
    rng = np.random.default_rng(seed)
    return rng.integers(0, 256, size=size, dtype=np.uint8)


def load_frames_from_dir(directory: str, limit: int = 100) -> list[np.ndarray]:
    """Load grayscale frames from a directory of PNG/JPG files."""
    if not PIL_AVAILABLE:
        print("ERROR: Pillow required for frame loading. pip install Pillow",
              file=sys.stderr)
        sys.exit(1)
    frames = []
    p = Path(directory)
    for fp in sorted(p.glob('*'))[:limit]:
        if fp.suffix.lower() in ('.png', '.jpg', '.jpeg'):
            img = Image.open(fp).convert('L').resize((224, 224))
            frames.append(np.array(img))
    return frames


def benchmark_latency(n_frames: int = 30, iterations: int = 200) -> np.ndarray:
    """Measure per-frame BEM processing latency using synthetic noise frames."""
    frames_per_run = [generate_synthetic_frame(i) for i in range(n_frames)]
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        compute_bem_features(frames_per_run)
        elapsed_ms = (time.perf_counter() - t0) * 1000 / n_frames
        times.append(elapsed_ms)
    return np.array(times)


def evaluate_detection(authentic_dir: str, synthetic_dir: str,
                       threshold: float = None) -> dict:
    """
    Evaluate APCER and BPCER against authentic and synthetic frame sets.
    """
    print("Loading authentic frames...")
    auth_frames = load_frames_from_dir(authentic_dir)
    print(f"  Loaded {len(auth_frames)} authentic frames.")

    print("Loading synthetic frames...")
    synth_frames = load_frames_from_dir(synthetic_dir)
    print(f"  Loaded {len(synth_frames)} synthetic frames.")

    # Score both in sliding windows of 30 frames
    WIN = 30
    auth_scores  = []
    synth_scores = []

    for start in range(0, len(auth_frames) - WIN + 1, WIN // 2):
        feat = compute_bem_features(auth_frames[start:start+WIN])
        auth_scores.append(feat['anomaly_score'])

    for start in range(0, len(synth_frames) - WIN + 1, WIN // 2):
        feat = compute_bem_features(synth_frames[start:start+WIN])
        synth_scores.append(feat['anomaly_score'])

    if not auth_scores or not synth_scores:
        print("ERROR: Insufficient frames for evaluation (need >= 30 per class).",
              file=sys.stderr)
        return {}

    # Calibrate threshold at D-EER if not provided
    all_scores  = auth_scores + synth_scores
    all_labels  = [0]*len(auth_scores) + [1]*len(synth_scores)
    thresholds  = np.linspace(min(all_scores), max(all_scores), 1000)
    best_eer    = 1.0
    best_thresh = thresholds[len(thresholds)//2]

    for th in thresholds:
        tn = sum(s < th for s, l in zip(all_scores, all_labels) if l == 0)
        fp = sum(s >= th for s, l in zip(all_scores, all_labels) if l == 0)
        fn = sum(s < th for s, l in zip(all_scores, all_labels) if l == 1)
        tp = sum(s >= th for s, l in zip(all_scores, all_labels) if l == 1)
        n_auth  = tn + fp or 1
        n_synth = fn + tp or 1
        bpcer = fp / n_auth
        apcer = fn / n_synth
        eer = abs(bpcer - apcer)
        if eer < best_eer:
            best_eer = eer
            best_thresh = th
            best_apcer  = apcer
            best_bpcer  = bpcer

    return {
        'threshold': best_thresh,
        'apcer': best_apcer,
        'bpcer': best_bpcer,
        'n_authentic_windows': len(auth_scores),
        'n_synthetic_windows': len(synth_scores),
    }


def main():
    parser = argparse.ArgumentParser(description='CRISP BEM Benchmark')
    parser.add_argument('--authentic', default=None,
                        help='Path to authentic frame directory')
    parser.add_argument('--synthetic', default=None,
                        help='Path to synthetic frame directory')
    parser.add_argument('--iterations', type=int, default=200,
                        help='Number of latency benchmark iterations')
    parser.add_argument('--perf-counters', action='store_true',
                        help='Attempt to read Linux hardware perf counters')
    args = parser.parse_args()

    print("CRISP Benchmark 4: BEM Behavioral Entropy Monitor")
    print(f"DCT block size   : {BEM_DCT_BLOCK}x{BEM_DCT_BLOCK}")
    print(f"Histogram bins   : {BEM_HIST_BINS}")
    print(f"Frame size       : 224x224 (grayscale)")
    print(f"Latency iters    : {args.iterations}")
    print("-" * 55)

    # ── Latency benchmark ────────────────────────────────────
    print("Phase 1: Per-frame latency (synthetic noise frames, 30-frame windows)")
    times = benchmark_latency(iterations=args.iterations)
    print(f"  P50  : {np.percentile(times, 50):.2f} ms/frame")
    print(f"  P95  : {np.percentile(times, 95):.2f} ms/frame  <-- paper headline")
    print(f"  P99  : {np.percentile(times, 99):.2f} ms/frame")
    print(f"  Mean : {np.mean(times):.2f} ms/frame")
    print(f"  Std  : {np.std(times):.2f} ms/frame")

    # ── APCER / BPCER evaluation ─────────────────────────────
    if args.authentic and args.synthetic:
        print("\nPhase 2: APCER/BPCER evaluation with real frame sets")
        results = evaluate_detection(args.authentic, args.synthetic)
        if results:
            print(f"  Calibrated threshold  : {results['threshold']:.4f}")
            print(f"  APCER (D-EER)         : {results['apcer']*100:.2f}%  "
                  f"(target: <{APCER_TARGET*100:.1f}%)")
            print(f"  BPCER (D-EER)         : {results['bpcer']*100:.2f}%  "
                  f"(target: <{BPCER_TARGET*100:.1f}%)")
            print(f"  Authentic windows     : {results['n_authentic_windows']}")
            print(f"  Synthetic windows     : {results['n_synthetic_windows']}")
    else:
        print("\nPhase 2: APCER/BPCER evaluation skipped.")
        print("  Provide --authentic and --synthetic paths to evaluate error rates.")

    if args.perf_counters:
        print("\nPhase 3: Hardware perf counter integration (stub)")
        print("  Perf counter reading via perf_event_open() is implemented in")
        print("  src/bem/perf_monitor.py — run on Linux with kernel.perf_event_paranoid=1")

    print("-" * 55)
    print("Paper disclosure statement:")
    print("  BEM latency measured using synthetic Gaussian noise frames as input.")
    print("  Real-frame APCER/BPCER evaluation requires authentic and synthetic")
    print("  frame directories. Hardware perf counter integration (Phase 3)")
    print("  requires Linux kernel >= 4.1 and appropriate kernel.perf_event_paranoid.")


if __name__ == '__main__':
    main()
