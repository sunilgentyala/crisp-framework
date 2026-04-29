# Contributing to crisp-framework

Thank you for your interest in contributing. This repository accompanies a paper under peer review; contributions are welcome in the following areas.

## What You Can Contribute

- **Benchmark improvements:** Corrected or extended benchmark results, especially on new hardware platforms (ARM Cortex-A76, Apple M-series, RISC-V). Hardware-specific results with full platform disclosure are especially valuable.
- **Bug fixes:** Errors in benchmark scripts, incorrect formulas, broken setup instructions.
- **New benchmark platforms:** If you run `tpm_bench.py` on dedicated Infineon SLB 9672 hardware, or `set_bench.py` on ARM hardware, please open a PR with your `*_results.txt` following the existing disclosure format.
- **Circuit improvements:** More efficient circom circuits for ZKBV (lower constraint count, PLONK/STARK variants).
- **Documentation:** Clearer setup instructions, additional platform guides.

## What Is Out of Scope

- Modifications to the core security claims or formal proofs — these are fixed by the submitted paper.
- Changes that affect reproducibility of published benchmark figures without full disclosure.

## How to Contribute

1. **Fork** this repository and create a feature branch (`git checkout -b feat/arm-benchmark`).
2. Make your changes, following the style of existing files.
3. If adding benchmark results, include the full hardware disclosure block (see `tpm_results.txt` for the template).
4. **Open a pull request** with a clear description of what changed and why.

## Benchmark Disclosure Standard

All benchmark result files must include:
- Date, platform (OS, CPU, RAM), tool versions
- Clear statement of whether results are from hardware or emulator
- Known limitations relative to paper-claimed hardware
- Raw terminal output where applicable
- Reproduction commands

## Code Style

- Python: PEP 8, docstrings on all functions, type hints where practical.
- No external dependencies beyond `requirements.txt` unless clearly necessary and documented.
- Use `argparse` for CLI scripts.

## Security Issues

Do **not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md).
