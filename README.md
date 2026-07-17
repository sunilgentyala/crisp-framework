
# crisp-framework# CRISP: Cryptographic Root-of-trust Identity and Sensor Provenance

[![Paper Status](https://img.shields.io/badge/Paper-Under_Review-blue)](https://github.com/sunilgentyala/crisp-framework/blob/main/PAPER_STATUS.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue)](https://www.python.org/)

---

## Overview

This repository accompanies the paper:

> **The Weaponization of Deepfakes: A Novel Cryptographic Framework Mitigating Biometric Injection and Identity Gaps**  
> *Under review.*

CRISP is a four-component cryptographic framework that closes the hardware-to-authentication chain-of-trust gap exploited by OS-level biometric injection attacks — a class of attack that bypasses every existing liveness and presentation-attack detection mechanism by impersonating the camera itself rather than spoofing it.

---

## The Problem

Modern biometric authentication assumes sensor input can be trusted. It cannot.

OS-level injection tools (v4l2loopback, OBS Virtual Camera, LD_PRELOAD hooks) insert synthetic deepfake video directly into the OS media pipeline — **upstream of every PAD, liveness, and anti-spoofing check**. By 2024, injection attacks surged 9× year-over-year. ISO/IEC 30107-3-compliant systems offer zero protection against this attack class by design.

---

## CRISP Architecture

```
Physical Sensor Hardware  ──[SHA-256 frame hash + session nonce]──▶
    │
    ▼
SA: TPM 2.0 Sensor Attestation          ← Blocks AC-2 (driver injection)
    │  AIK-signed PCR quote                  Blocks AC-3 (virtual camera)
    ▼
SET: Post-Quantum Hybrid Telemetry       ← Blocks AC-4 (SDK hook / LD_PRELOAD)
    │  X25519MLKEM768 + AES-256-GCM
    ▼
ZKBV: Zero-Knowledge Biometric Verify    ← Template unlinkability
    │  Groth16 / BCH(2047,1723) fuzzy commit
    ▼
BEM: Behavioral Entropy Monitor          ← Synthetic-stream anomaly detection
    │  KL-divergence + spectral flatness
    ▼
Authentication Decision Module           ← ACCEPT only if all four pass
```

| Component | Function | Blocks |
|-----------|----------|--------|
| **SA** | TPM 2.0-anchored sensor attestation | AC-2, AC-3 |
| **SET** | X25519MLKEM768 post-quantum hybrid channel | AC-4 |
| **ZKBV** | Groth16 zkSNARK biometric verification (no template transmitted) | Replay |
| **BEM** | Entropy-based synthetic-stream detection | Novel synthesis variants |

---

## Repository Structure

```
crisp-framework/
├── benchmarks/
│   ├── BENCHMARK_GUIDE.md       # Full setup and reproduction instructions
│   ├── tpm_bench.py             # SA: TPM quote generation latency
│   ├── set_bench.py             # SET: PQ-hybrid handshake overhead
│   ├── zkbv_bench.py            # ZKBV: Groth16 proving + verification time
│   ├── bem_bench.py             # BEM: entropy monitor throughput + real APCER/BPCER
│   ├── prepare_bem_dataset.py   # Downloads real authentic/synthetic frame sets for BEM
│   ├── sa_rejection_test.py     # SA/SET: real protocol-level attack rejection test
│   └── results/
│       ├── tpm_results.txt              # SA results  — P95: 8.7 ms (swtpm baseline)
│       ├── set_results.txt              # SET results — P95 Δ: 11.6 ms (x86-64 loopback)
│       ├── zkbv_results.txt             # ZKBV results (verify measured; ARM proving pending)
│       ├── bem_results.txt              # BEM results — measured APCER/BPCER (see below)
│       └── sa_set_rejection_results.txt # Real AC-2/3/4 rejection rates (see below)
├── src/
│   ├── sa/                      # Sensor Attestation module
│   ├── set/                     # Secure Telemetry Channel module
│   ├── zkbv/                    # ZK Biometric Verification module (circom circuits)
│   └── bem/                     # Behavioral Entropy Monitor module
├── CITATION.cff                 # Citation metadata
├── PAPER_STATUS.md              # Submission status
├── CONTRIBUTING.md              # Contribution guidelines
├── SECURITY.md                  # Vulnerability disclosure policy
├── LICENSE                      # MIT License
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

---

## Benchmark Results Summary

> **Disclosure:** SA results use swtpm 0.7 (software emulator) — a performance **lower bound**.  
> Dedicated hardware TPMs (Infineon SLB 9672) are expected to yield 80–180 ms P95 due to SPI bus overhead.  
> SET results are from x86-64 loopback; ARM Cortex-A76 expected 1.5–2× higher.

| Component | Metric | Platform | Result | Paper Headline |
|-----------|--------|----------|--------|----------------|
| **SA** | TPM Quote P95 | x86-64, swtpm 0.7 | 8.7 ms | ✅ |
| **SA** | TPM Quote P95 (hardware est.) | Infineon SLB 9672 | 80–180 ms | Disclosed in §VI |
| **SA/SET** | Real AC-2/3/4 rejection rate | x86-64, swtpm | 0/60 forgeries accepted (n=20 each) | ✅ Measured |
| **SA** | Bona fide acceptance (BPCER) | x86-64, swtpm | 20/20 | ✅ Measured |
| **SET** | Handshake overhead P95 Δ | x86-64 loopback | 11.6 ms | ✅ |
| **SA + SET combined** | Total overhead P95 | x86-64 | 20.3 ms | ✅ |
| **ZKBV** | Groth16 proving time | ARM Cortex-A76 | Pending | ⏳ |
| **ZKBV** | Groth16 verification time | x86-64 | ~2 ms | ✅ |
| **BEM** | Per-frame latency P95 | x86-64 (WSL2) | 10.05 ms | ✅ Measured (was placeholder) |
| **BEM** | APCER / BPCER (D-EER) | x86-64, LFW + OpenRL/DeepFakeFace | 0.00% / 0.00% (n=29 windows/class) | ✅ Measured, small-sample |
| **End-to-end** | Auth latency target (P95) | ARM Cortex-A76 | < 47 ms | Target — see note below |

**Remaining overhead budget:** the previously assumed 26.7 ms remaining for ZKBV + BEM after SA+SET (20.3 ms) no longer holds now that BEM has a *measured* P95 of 10.05 ms on x86-64 (the earlier ~1.3 ms figure was an unverified placeholder, never actually run). Combined SA+SET+BEM alone is already ~30 ms on x86-64 before ZKBV proving; the 47 ms end-to-end target should be treated as at-risk pending ARM measurement, not settled. See `benchmarks/results/bem_results.txt` for the full disclosure.

---

## Reproduction

See [`benchmarks/BENCHMARK_GUIDE.md`](benchmarks/BENCHMARK_GUIDE.md) for full prerequisites and step-by-step setup.

**Quick start (SA benchmark):**
```bash
# Install prerequisites
sudo apt install -y swtpm tpm2-tools python3-pip
pip install -r requirements.txt

# Set up software TPM
mkdir -p /tmp/vtpm
swtpm socket --tpmstate dir=/tmp/vtpm --tpm2 \
  --server type=unixio,path=/tmp/vtpm/sock \
  --ctrl type=unixio,path=/tmp/vtpm/sock.ctrl \
  --flags not-need-init,startup-clear &
export TPM2TOOLS_TCTI="swtpm:path=/tmp/vtpm/sock"
tpm2_createprimary -C e -c /tmp/vtpm/primary.ctx
tpm2_evictcontrol -C o -c /tmp/vtpm/primary.ctx 0x81000001

python3 benchmarks/tpm_bench.py
```

**Quick start (SET benchmark):**
```bash
# See BENCHMARK_GUIDE.md for OpenSSL OQS provider build instructions

# Terminal 1 — start server:
openssl s_server \
  -provider-path /usr/lib/x86_64-linux-gnu/ossl-modules \
  -provider oqsprovider -provider default \
  -cert ~/cert.pem -key ~/key.pem \
  -port 4433 -tls1_3 -groups X25519MLKEM768:X25519

# Terminal 2 — run benchmark:
python3 benchmarks/set_bench.py
```

---

## Key Security Properties (Formal)

| Property | Definition | Reduction |
|----------|-----------|-----------|
| **Sensor Binding** (SG-1) | Auth module can verify data came from attested physical sensor | ECDSA unforgeability |
| **Template Unlinkability** (SG-2) | No biometric template traverses any external boundary | DDH over Groth16 bilinear group |
| **Injection Resistance** (SG-3) | No PPT adversary causes acceptance of fabricated stream except w/ negl. prob. | Theorem 1 (ROM) |
| **Freshness** (SG-4) | Attestation quotes bound to session nonces; no replay | Nonce uniqueness |

**Theorem 1 (informal):** Under ROM, CRISP injection resistance is bounded by:

```
Adv_BIA(A, λ) ≤ Adv_ECDSA(A) + Adv_ZK-Sound(A) + ε_BEM + negl(λ)
```

---

## Paper Citation

```bibtex
@unpublished{gentyala2026crisp,
  author = {Gentyala, Sunil},
  title  = {The Weaponization of Deepfakes: A Novel Cryptographic Framework
            Mitigating Biometric Injection and Identity Gaps},
  year   = {2026},
  note   = {Manuscript under review},
  url    = {https://github.com/sunilgentyala/crisp-framework}
}
```

Or see [`CITATION.cff`](CITATION.cff) for CFF format.

---

## Open Items / Roadmap

- [x] BEM throughput + real APCER/BPCER benchmark (`benchmarks/bem_bench.py`, `prepare_bem_dataset.py`)
- [x] Real SA/SET protocol-level attack rejection test (`benchmarks/sa_rejection_test.py`)
- [x] circom circuit source for ZKBV (`src/zkbv/`)
- [x] Full SA + SET prototype source (`src/sa/`, `src/set/`)
- [x] BEM implementation source (`src/bem/`)
- [ ] ZKBV benchmark on ARM Cortex-A76 hardware (`benchmarks/zkbv_bench.py`)
- [ ] SA benchmark on Infineon SLB 9672 hardware (replaces swtpm lower bound)
- [ ] SET benchmark on ARM Cortex-A76 (replaces x86-64 loopback figure)
- [ ] BEM latency + APCER/BPCER on ARM Cortex-A76 (current results are x86-64/WSL2 only)
- [ ] Larger-scale BEM evaluation (more identities, multiple synthesis architectures, genuine video capture — current n=29 windows/class is a small-sample proof of signal, not a deployment-grade error-rate estimate)
- [ ] Docker container for reproducible benchmark environment
- [ ] GitHub Actions CI for benchmark regression tests

---

## License

MIT — see [LICENSE](LICENSE).

---

## Contact / Issues

For questions about the benchmarks or reproduction, open a GitHub Issue.  
For the manuscript, see [PAPER_STATUS.md](PAPER_STATUS.md).  
For security vulnerabilities, see [SECURITY.md](SECURITY.md).
