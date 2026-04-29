# CRISP Benchmark Guide

Full installation and reproduction instructions for all four CRISP benchmark scripts.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Benchmark 1 — SA: TPM Quote Latency](#benchmark-1--sa-tpm-quote-latency)
3. [Benchmark 2 — SET: PQ-Hybrid Handshake Overhead](#benchmark-2--set-pq-hybrid-handshake-overhead)
4. [Benchmark 3 — ZKBV: Groth16 Proving and Verification Time](#benchmark-3--zkbv-groth16-proving-and-verification-time)
5. [Benchmark 4 — BEM: Entropy Monitor Throughput](#benchmark-4--bem-entropy-monitor-throughput)
6. [Hardware Disclosure](#hardware-disclosure)

---

## Prerequisites

**System:** Ubuntu 22.04 LTS (tested). Other Debian-based distros should work with minor adjustments.

**Python:**
```bash
sudo apt install -y python3.12 python3-pip python3-numpy python3-scipy
pip install -r requirements.txt   # from repo root
```

---

## Benchmark 1 — SA: TPM Quote Latency

**Script:** `benchmarks/tpm_bench.py`  
**Results:** `benchmarks/results/tpm_results.txt`

### Option A — Software TPM (swtpm) — lower bound

```bash
# Install
sudo apt install -y swtpm swtpm-tools tpm2-tools

# Setup (run once)
mkdir -p /tmp/vtpm
swtpm socket --tpmstate dir=/tmp/vtpm --tpm2 \
  --server type=unixio,path=/tmp/vtpm/sock \
  --ctrl type=unixio,path=/tmp/vtpm/sock.ctrl \
  --flags not-need-init,startup-clear &
sleep 3
export TPM2TOOLS_TCTI="swtpm:path=/tmp/vtpm/sock"
tpm2_createprimary -C e -c /tmp/vtpm/primary.ctx
tpm2_evictcontrol -C o -c /tmp/vtpm/primary.ctx 0x81000001

# Run benchmark
python3 benchmarks/tpm_bench.py
```

> **Note:** swtpm results are a **lower bound** (~8.7 ms P95). Hardware TPMs (Infineon SLB 9672)
> yield 80–180 ms P95 due to SPI bus latency. See `tpm_results.txt` for full disclosure.

### Option B — Hardware TPM (Raspberry Pi 5 + Infineon SLB 9672)

```bash
# On the Pi, install tpm2-tools
sudo apt install -y tpm2-tools

# Verify TPM is detected
tpm2_getcap handles-persistent

# Create and persist a primary key
tpm2_createprimary -C e -c /tmp/primary.ctx
tpm2_evictcontrol -C o -c /tmp/primary.ctx 0x81000001

# Run benchmark (no TCTI override needed — uses device /dev/tpmrm0)
python3 benchmarks/tpm_bench.py
```

---

## Benchmark 2 — SET: PQ-Hybrid Handshake Overhead

**Script:** `benchmarks/set_bench.py`  
**Results:** `benchmarks/results/set_results.txt`

### Step 1 — Build liboqs and oqs-provider

```bash
# Install build dependencies
sudo apt install -y cmake ninja-build libssl-dev

# Build liboqs
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON
cmake --build build --parallel $(nproc)
sudo cmake --install build
cd ..

# Build oqs-provider
git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -B build \
  -DCMAKE_INSTALL_PREFIX=/usr/local \
  -Dliboqs_DIR=/usr/local/lib/cmake/liboqs \
  -DOPENSSL_ROOT_DIR=/usr
cmake --build build --parallel $(nproc)
sudo cmake --install build

# Verify
openssl list -providers -provider-path /usr/local/lib/x86_64-linux-gnu/ossl-modules \
  -provider oqsprovider -provider default | grep oqsprovider
```

> Update `PROVIDER_PATH` in `set_bench.py` if your install path differs from
> `/usr/lib/x86_64-linux-gnu/ossl-modules`.

### Step 2 — Generate test certificate

```bash
openssl req -x509 -newkey rsa:2048 -keyout ~/key.pem -out ~/cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

### Step 3 — Run benchmark (two terminals)

**Terminal 1 — server:**
```bash
openssl s_server \
  -provider-path /usr/lib/x86_64-linux-gnu/ossl-modules \
  -provider oqsprovider -provider default \
  -cert ~/cert.pem -key ~/key.pem \
  -port 4433 -tls1_3 \
  -groups X25519MLKEM768:X25519
```

**Terminal 2 — benchmark:**
```bash
python3 benchmarks/set_bench.py
```

---

## Benchmark 3 — ZKBV: Groth16 Proving and Verification Time

**Script:** `benchmarks/zkbv_bench.py`  
**Results:** `benchmarks/results/zkbv_results.txt` *(pending ARM hardware run)*

### Prerequisites

```bash
# Node.js 18+ required
node --version

# Install snarkjs and circom
npm install -g snarkjs
npm install -g @iden3/circom   # or build from source; see https://docs.circom.io

# Install Python wrapper dependencies
pip install py-snarkjs  # or use subprocess calls as in zkbv_bench.py
```

### Running the benchmark

```bash
# Trusted setup (Powers of Tau — run once, or use an existing ptau file)
snarkjs powersoftau new bn128 18 pot18_0000.ptau -v
snarkjs powersoftau contribute pot18_0000.ptau pot18_0001.ptau --name="CRISP setup" -v -e="random entropy"
snarkjs powersoftau prepare phase2 pot18_0001.ptau pot18_final.ptau -v

# Run benchmark (compiles circuit, generates proving key, runs 100 prove+verify cycles)
python3 benchmarks/zkbv_bench.py --ptau pot18_final.ptau
```

> **Target:** Groth16 verification time < 2 ms on x86-64 (achieved).  
> Proving time on ARM Cortex-A76 is the **open measurement item** for the paper.

---

## Benchmark 4 — BEM: Entropy Monitor Throughput

**Script:** `benchmarks/bem_bench.py`  
**Results:** `benchmarks/results/bem_results.txt` *(pending)*

### Prerequisites

```bash
pip install numpy scipy
# Hardware perf counters require Linux kernel ≥ 4.1 and:
sudo sysctl -w kernel.perf_event_paranoid=1
```

### Running the benchmark

```bash
# Generate synthetic and authentic frame sequences for comparison
# Authentic: supply path to a directory of real camera frames (PNG/JPG)
# Synthetic: supply path to StyleGAN3 or SDXL output frames

python3 benchmarks/bem_bench.py \
  --authentic /path/to/real_frames/ \
  --synthetic /path/to/synthetic_frames/ \
  --iterations 1000
```

> **Target:** BEM per-frame processing < 2 ms at P95 (ensuring it fits within the
> overall 47 ms end-to-end latency budget without blocking the authentication path).

---

## Hardware Disclosure

All benchmark headline figures carry explicit hardware disclosure. A summary:

| Benchmark | Platform Used | Known Limitation | Paper Disclosure |
|-----------|--------------|-----------------|-----------------|
| SA (TPM) | x86-64, swtpm 0.7 | Software emulator; hardware TPM 10–20× slower | §VI, tpm_results.txt |
| SET | x86-64, loopback | Loopback ≠ production network; ARM 1.5–2× higher | §VI, set_results.txt |
| ZKBV | x86-64 (verification) | Proving time on ARM Cortex-A76 not yet measured | §VII open item |
| BEM | — | Not yet measured | §VII open item |

See individual `*_results.txt` files in `benchmarks/results/` for complete raw output
and disclosure statements as they appear in the submitted paper.
