# Security Policy

## Scope

This repository contains benchmark scripts and supporting material for the CRISP academic paper. There is no production deployment of CRISP in this repository. However, the benchmark scripts involve TPM operations, cryptographic key material (test certificates), and ZK circuit artifacts — please follow responsible disclosure if you identify issues.

## Supported Versions

| Component | Status |
|-----------|--------|
| Benchmark scripts (v1.0.0) | Active |
| Paper (submitted) | Under review |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing: **[your-security-email@example.com]**

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to respond within 72 hours and will coordinate disclosure timing with you.

## Known Limitations Documented in the Paper

The following are explicitly stated limitations in the paper (Section VII), not vulnerabilities:

1. **swtpm vs. hardware TPM:** SA benchmark results use swtpm (software emulator). Hardware TPMs (Infineon SLB 9672) are expected to be significantly slower due to SPI bus overhead.
2. **x86-64 loopback SET results:** SET handshake overhead is measured on localhost, not a real network path. ARM and production network figures will differ.
3. **BEM threshold calibration:** BEM thresholds are calibrated against StyleGAN3 and SDXL adversary simulators only; novel synthesis architectures may evade detection.
4. **Physically compromised TPMs:** CRISP does not protect against supply-chain attacks on sensor firmware or physical TPM tampering. This is a stated scope boundary.

## Test Credentials

The benchmark guide instructs users to generate self-signed test certificates (`cert.pem`, `key.pem`) for localhost TLS testing. These are **not** for production use and should never be committed to the repository (see `.gitignore`).
