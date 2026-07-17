"""
CRISP — Prepare a real authentic-vs-synthetic frame dataset for BEM evaluation.
=================================================================================
Downloads a small, bounded subset of two publicly documented, citable
datasets (streamed via Hugging Face, no full-dataset download):

  Authentic: bitmind/lfw — a Hugging Face mirror of Labeled Faces in the
    Wild (Huang et al., 2007), real photographs.

  Synthetic: OpenRL/DeepFakeFace — diffusion-model-generated face images,
    from Song et al., "Robustness and Generalizability of Deepfake
    Detection: A Study with Diffusion Models" (2023).

Methodology note (disclosed, not hidden):
  BEM's entropy features are inter-frame statistics computed over a
  30-frame sliding window, designed for short video bursts from a single
  sensor session. Neither source dataset provides genuine video frame
  sequences. To exercise BEM's actual feature pipeline rather than skip
  the evaluation, each class is built from N_BASE_IMAGES base photos, and
  each base photo is expanded into FRAMES_PER_BASE frames via small
  camera-burst-like jitter (±1.5px translation, ±1.5deg rotation, mild
  Gaussian sensor noise, minor JPEG-quality resampling) — approximating a
  short handheld/webcam burst of the same subject rather than true video.
  This is a single-frame spectral/texture signature test (the DCT-
  histogram and spectral-flatness features BEM computes are exactly the
  per-frame artifacts the deepfake-detection literature associates with
  GAN/diffusion synthesis), not a genuine temporal-motion test. This
  substitution is disclosed in the paper text, not presented as video.
"""

from __future__ import annotations

import io
import os
import random
import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter

N_BASE_IMAGES   = 15
FRAMES_PER_BASE = 30
OUT_DIR = Path("/tmp/bem_dataset")
AUTH_DIR = OUT_DIR / "authentic"
SYNTH_DIR = OUT_DIR / "synthetic"

random.seed(1234)
np.random.seed(1234)


def jitter_burst(base_img: Image.Image, n: int, prefix: str, out_dir: Path):
    base_img = base_img.convert("RGB").resize((256, 256))
    for i in range(n):
        img = base_img
        # small rotation
        angle = np.random.uniform(-1.5, 1.5)
        img = img.rotate(angle, resample=Image.BILINEAR, fillcolor=(0, 0, 0))
        # small translation via crop-pad
        dx, dy = np.random.randint(-2, 3, size=2)
        arr = np.array(img)
        arr = np.roll(arr, (dy, dx), axis=(0, 1))
        # mild Gaussian sensor noise
        noise = np.random.normal(0, 3.0, arr.shape)
        arr = np.clip(arr.astype(np.float32) + noise, 0, 255).astype(np.uint8)
        img = Image.fromarray(arr)
        # minor JPEG-quality resampling (simulates capture compression variance)
        buf = io.BytesIO()
        quality = np.random.randint(85, 98)
        img.save(buf, format="JPEG", quality=int(quality))
        buf.seek(0)
        img = Image.open(buf).convert("RGB")
        img.save(out_dir / f"{prefix}_{i:03d}.png")


def main():
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    SYNTH_DIR.mkdir(parents=True, exist_ok=True)

    from datasets import load_dataset

    print(f"Streaming {N_BASE_IMAGES} authentic images from bitmind/lfw ...")
    lfw = load_dataset("bitmind/lfw", split="train", streaming=True)
    n = 0
    for row in lfw:
        img = row.get("image")
        if img is None:
            continue
        jitter_burst(img, FRAMES_PER_BASE, f"auth{n:03d}", AUTH_DIR)
        n += 1
        print(f"  [{n}/{N_BASE_IMAGES}] authentic base image processed")
        if n >= N_BASE_IMAGES:
            break

    print(f"Streaming {N_BASE_IMAGES} synthetic images from OpenRL/DeepFakeFace ...")
    fake = load_dataset("OpenRL/DeepFakeFace", split="train", streaming=True)
    n = 0
    for row in fake:
        img = row.get("image")
        if img is None:
            continue
        jitter_burst(img, FRAMES_PER_BASE, f"synth{n:03d}", SYNTH_DIR)
        n += 1
        print(f"  [{n}/{N_BASE_IMAGES}] synthetic base image processed")
        if n >= N_BASE_IMAGES:
            break

    print(f"\nDone. {len(list(AUTH_DIR.glob('*.png')))} authentic frames in {AUTH_DIR}")
    print(f"      {len(list(SYNTH_DIR.glob('*.png')))} synthetic frames in {SYNTH_DIR}")


if __name__ == "__main__":
    main()
