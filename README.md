# CRISP: Cryptographic Root-of-trust Identity and Sensor Provenance

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue)](https://www.python.org/)

CRISP is an open-source research prototype for defending biometric authentication against **injection attacks**. Instead of asking whether a face or iris stream looks real, it asks whether the stream provably came from the physical sensor and whether the final match refers to the correct enrolled identity.

> **Status:** research prototype. The repository contains component implementations and benchmark scripts. It is not a production authentication system and has not been evaluated end to end on deployment hardware.

---

## The Problem

Most biometric systems assume the camera data reaching the authentication module came from the camera. Injection tools such as virtual cameras (v4l2loopback, OBS Virtual Camera), malicious drivers, and library hooks (LD_PRELOAD) replace that stream inside the operating system, after the sensor and before liveness or deepfake checks run. Presentation attack detection (the ISO/IEC 30107 family) targets artifacts held up to a sensor, so it was not designed to prove where a stream originated.

CRISP addresses this by binding the capture path, the session, and the enrollment record together cryptographically.

---

## Architecture

```
Physical sensor  ──[frame hash + session nonce]──▶
    │
    ▼
SA   TPM 2.0 sensor attestation        driver-level and virtual-camera injection
    │  AIK-signed quote over the frame data
    ▼
SET  Post-quantum hybrid telemetry     tampering with data in transit
    │  X25519MLKEM768 + AES-256-GCM
    ▼
ZKBV Zero-knowledge biometric check    template stays local, no raw template sent
    │  Groth16 proof of a distance relation
    ▼
BEM  Behavioral entropy monitor        statistical signal for synthetic streams
    │  KL divergence, spectral flatness
    ▼
Decision module                        accept only if every mandatory check passes
```

| Component | Function |
|-----------|----------|
| **SA** | TPM 2.0-anchored attestation of sensor data with a verifier nonce |
| **SET** | TLS 1.3 channel using the X25519MLKEM768 hybrid key exchange |
| **ZKBV** | Groth16 zk-SNARK showing a probe is close to an enrolled template without revealing either |
| **BEM** | Optional entropy-based detector; a risk signal, not a cryptographic guarantee |

### Design goals

- **Sensor binding:** data accepted by the verifier should originate from an attested capture path.
- **Freshness:** attestation is bound to a single-use session nonce, so old evidence cannot be replayed.
- **Template privacy:** biometric templates do not leave the device; only a proof does.
- **Fail closed:** missing, stale, or unverifiable evidence causes rejection.

These are design goals of the prototype. The benchmarks below measure individual components and do not constitute a security proof or a deployment evaluation.

---

## Repository Structure

```
crisp-framework/
├── benchmarks/
│   ├── BENCHMARK_GUIDE.md       # Setup and reproduction instructions
│   ├── tpm_bench.py             # SA: TPM quote latency
│   ├── set_bench.py             # SET: hybrid handshake overhead
│   ├── zkbv_bench.py            # ZKBV: Groth16 proving and verification time
│   ├── bem_bench.py             # BEM: entropy monitor throughput and error rates
│   ├── prepare_bem_dataset.py   # Downloads authentic and synthetic frame sets for BEM
│   ├── sa_rejection_test.py     # SA/SET: protocol-level forged-input rejection test
│   ├── sa_set_attack_matrix.py  # SA/SET: 14 attack conditions, 100 trials each, with ablation
│   ├── tpm_hw_quote_windows.py  # SA: hardware TPM quote latency on Windows (TBS)
│   └── results/                 # Raw output from each benchmark
├── src/
│   ├── sa/                      # Sensor attestation module
│   ├── set/                     # Secure telemetry channel module
│   ├── zkbv/                    # ZK biometric verification (circom circuit, prover, verifier)
│   ├── bem/                     # Behavioral entropy monitor
│   └── crisp_pipeline.py        # Component wiring
├── CITATION.cff                 # Software citation metadata
├── CONTRIBUTING.md              # Contribution guidelines
├── SECURITY.md                  # Vulnerability disclosure policy
├── LICENSE                      # MIT License
└── requirements.txt             # Python dependencies
```

---

## Benchmark Results Summary

> **Disclosure:** the swtpm results are a software-emulator **lower bound**. The hardware TPM figure comes from one laptop and includes Windows driver overhead. SET results come from an x86-64 loopback and say nothing about wide-area latency. ZKBV proving was measured on x86-64 only and is preliminary.

| Component | Metric | Platform | Result |
|-----------|--------|----------|--------|
| **SA** | TPM quote P95 | x86-64, swtpm 0.7 | 8.7 ms |
| **SA** | TPM quote P50 / P95 / P99 | Hardware TPM 2.0 (Nuvoton), Windows | 85 / 112 / 123 ms (100 trials, one platform) |
| **SA/SET** | Attack matrix: 14 conditions, 100 trials each | x86-64, swtpm | 0 of 1,400 attacks accepted (95% upper bound 3.6% per condition); 200 of 200 genuine accepted |
| **SA** | Ablation: hash and nonce check only (no signature check) | x86-64, swtpm | accepts 6 of 8 attestation attacks in every trial |
| **SET** | Handshake overhead P95 (hybrid minus classical) | x86-64 loopback | 11.6 ms |
| **SA + SET** | Combined overhead P95 | x86-64 | 20.3 ms |
| **ZKBV** | Groth16 verification | x86-64 | about 2 ms |
| **ZKBV** | Groth16 proving P95 | x86-64 (Zen 4 class) | about 390 ms (preliminary) |
| **ZKBV** | Groth16 proving | ARM hardware | Pending |
| **BEM** | Per-frame latency P95 | x86-64 (WSL2) | 10.05 ms |
| **BEM** | APCER / BPCER | x86-64, LFW vs. OpenRL/DeepFakeFace, 29 windows per class | 0.00% / 0.00% (small sample, a signal check and not a deployment-grade estimate) |

Not yet measured: hardware TPM latency, mobile or ARM latency, end-to-end authentication latency, and error rates with live subjects. See the files in `benchmarks/results/` for full disclosures.

---

## Reproduction

See [`benchmarks/BENCHMARK_GUIDE.md`](benchmarks/BENCHMARK_GUIDE.md) for prerequisites and step-by-step setup.

**Quick start (SA benchmark):**
```bash
sudo apt install -y swtpm tpm2-tools python3-pip
pip install -r requirements.txt

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

# Terminal 1: start the server
openssl s_server \
  -provider-path /usr/lib/x86_64-linux-gnu/ossl-modules \
  -provider oqsprovider -provider default \
  -cert ~/cert.pem -key ~/key.pem \
  -port 4433 -tls1_3 -groups X25519MLKEM768:X25519

# Terminal 2: run the benchmark
python3 benchmarks/set_bench.py
```

---

## Roadmap

- [x] SA, SET, ZKBV, and BEM component implementations
- [x] Attack matrix with ablation for SA and SET (14 conditions, 100 trials each)
- [x] Hardware TPM quote latency on one platform
- [x] BEM throughput and error-rate benchmark
- [ ] ZKBV proving benchmark on ARM hardware
- [ ] Hardware TPM results on more than one platform
- [ ] SET benchmark on ARM hardware
- [ ] Larger BEM evaluation with more identities, several synthesis methods, and genuine video capture
- [ ] Trusted capture implementation (protected sensor path)
- [ ] Docker container for a reproducible benchmark environment
- [ ] GitHub Actions CI for benchmark regression tests

---

## Citation

See [`CITATION.cff`](CITATION.cff) for software citation metadata.

## License

MIT, see [LICENSE](LICENSE).

## Contact and Issues

For questions about the benchmarks or reproduction, open a GitHub Issue. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
