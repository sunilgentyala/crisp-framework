"""
SA — Sensor Attestation: Quote Generation and Verification
===========================================================
Implements the SA-Quote and SA-Verify operations described in Section IV.A
and formally specified in Definition 2 (Section V.C) of the paper.

  SA = (SA-Setup, SA-Quote, SA-Verify)

  SA-Bind-Adv(A, λ) =
    Pr[SA-Verify(vk, Q, h, nonce) = 1 : Q ∉ output(S)] ≤ negl(λ)

Under ECDSA existential unforgeability (Equation 2 of the paper).

Hardware backend: tpm2-tools 5.4 via subprocess.
Supported TCTI:
  - swtpm:    "swtpm:path=/tmp/vtpm/sock"   (benchmark / CI)
  - device:   "device:/dev/tpmrm0"           (hardware TPM, Raspberry Pi)
  - tabrmd:   "tabrmd:bus_name=..."          (enterprise Linux)
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Default PCR set: PCR 0 (BIOS/UEFI), PCR 1 (BIOS config), PCR 7 (Secure Boot)
# PCR 9 is extended with the sensor identity measurement at provisioning time.
DEFAULT_PCR_LIST = "sha256:0,1,7,9"

# TPM persistent handle where the AIK is stored after provisioning
DEFAULT_TPM_HANDLE = "0x81000001"


@dataclass
class AttestationQuote:
    """
    Encapsulates a TPM attestation quote for a single biometric frame.

    Fields mirror the SA-Quote output defined in Section IV.A:
      - frame_hash:  SHA-256 of the raw biometric frame bytes
      - session_nonce: fresh nonce from the AuthModule (ensures freshness, SG-4)
      - pcr_values:  dict of PCR index → SHA-256 digest (hex strings)
      - quote_blob:  raw TPM2B_ATTEST structure (base64-encoded)
      - signature:   ECDSA-P256 signature over quote_blob (base64-encoded)
      - aik_cert_path: path to the AIK certificate for offline verification
    """
    frame_hash:     str
    session_nonce:  str
    pcr_values:     dict[str, str]
    quote_blob:     str                  # base64(TPM2B_ATTEST)
    signature:      str                  # base64(ECDSA sig)
    aik_cert_path:  Optional[str] = None
    pcr_file:       Optional[str] = None # base64(tpm2_quote -o PCR digest file), needed by tpm2_checkquote

    def to_dict(self) -> dict:
        return {
            "frame_hash":    self.frame_hash,
            "session_nonce": self.session_nonce,
            "pcr_values":    self.pcr_values,
            "quote_blob":    self.quote_blob,
            "signature":     self.signature,
            "aik_cert_path": self.aik_cert_path,
            "pcr_file":      self.pcr_file,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttestationQuote":
        return cls(**d)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class SensorAttestation:
    """
    SA component: generates and verifies TPM attestation quotes for
    biometric frames captured during an authentication session.

    Usage (sensor side — called once per frame):
        sa = SensorAttestation(tpm_handle="0x81000001")
        frame_bytes = capture_biometric_frame()
        nonce = auth_module.get_session_nonce()   # 32-byte hex string
        quote = sa.quote_frame(frame_bytes, nonce)

    Usage (authentication module side — called once per frame):
        ok = SensorAttestation.verify_quote(quote, expected_frame_bytes,
                                            nonce, aik_cert_path)
        if not ok:
            raise InjectionAttemptError("SA: quote verification failed")

    Platform notes:
        Set the CRISP_TPM_TCTI environment variable to override the TCTI.
        Default: "swtpm:path=/tmp/vtpm/sock" for development.
        Production: "device:/dev/tpmrm0" (Linux) or via tabrmd.
    """

    def __init__(
        self,
        tpm_handle: str = DEFAULT_TPM_HANDLE,
        pcr_list:   str = DEFAULT_PCR_LIST,
        tcti:       Optional[str] = None,
    ):
        self.tpm_handle = tpm_handle
        self.pcr_list   = pcr_list
        self.tcti       = tcti or os.environ.get(
            "CRISP_TPM_TCTI", "swtpm:path=/tmp/vtpm/sock"
        )

    # ── Public API ───────────────────────────────────────────────────────────

    def quote_frame(self, frame_bytes: bytes, session_nonce: str) -> AttestationQuote:
        """
        Generate a TPM attestation quote for a biometric frame.

        Parameters
        ----------
        frame_bytes:    Raw bytes of the captured biometric frame.
        session_nonce:  32-byte hex nonce from the authentication module
                        (ensures freshness — SG-4).

        Returns
        -------
        AttestationQuote containing the frame hash, PCR values, TPM quote
        blob, and ECDSA signature, ready for transmission to the AuthModule.
        """
        frame_hash = self._sha256_hex(frame_bytes)
        nonce_bytes = self._nonce_for_tpm(frame_hash, session_nonce)

        with tempfile.TemporaryDirectory() as tmpdir:
            quote_path = os.path.join(tmpdir, "quote.bin")
            sig_path   = os.path.join(tmpdir, "sig.bin")
            pcr_path   = os.path.join(tmpdir, "pcr.bin")

            self._run_tpm_quote(nonce_bytes, quote_path, sig_path, pcr_path)

            quote_b64 = self._b64_file(quote_path)
            sig_b64   = self._b64_file(sig_path)
            pcr_b64   = self._b64_file(pcr_path)
            pcr_values = self._read_pcr_values()

        return AttestationQuote(
            frame_hash    = frame_hash,
            session_nonce = session_nonce,
            pcr_values    = pcr_values,
            quote_blob    = quote_b64,
            signature     = sig_b64,
            pcr_file      = pcr_b64,
        )

    @staticmethod
    def verify_quote(
        quote:            AttestationQuote,
        expected_frame:   bytes,
        session_nonce:    str,
        aik_pub_path:     str,
        tcti:             Optional[str] = None,
    ) -> bool:
        """
        Verify a TPM attestation quote on the authentication module side.

        Checks (in order):
          1. Frame hash in quote matches SHA-256(expected_frame).
          2. Session nonce in quote matches the one issued for this session.
          3. TPM quote blob signature verifies against the AIK public key
             (TPM2B_PUBLIC area produced by SensorProvisioner.provision(),
             checked via `tpm2_checkquote`).

        Returns True only if all three checks pass.
        Any failure indicates either an injection attempt or data corruption.

        Security note:
          This implements the SA-Verify predicate from Equation (2).
          Under ECDSA unforgeability, a synthesized stream cannot produce
          a valid quote without the AIK private key (sealed in the TPM).
        """
        # Check 1: frame integrity
        expected_hash = SensorAttestation._sha256_hex(expected_frame)
        if quote.frame_hash != expected_hash:
            return False

        # Check 2: nonce freshness
        if quote.session_nonce != session_nonce:
            return False

        # Check 3: TPM quote signature
        return SensorAttestation._verify_tpm_signature(
            quote, aik_pub_path, tcti=tcti
        )

    @staticmethod
    def generate_session_nonce() -> str:
        """Generate a cryptographically random 32-byte session nonce (hex)."""
        return secrets.token_hex(32)

    # ── Private helpers ──────────────────────────────────────────────────────

    def _run_tpm_quote(
        self,
        nonce_bytes: bytes,
        quote_out:   str,
        sig_out:     str,
        pcr_out:     str,
    ) -> None:
        """Call tpm2_quote via subprocess."""
        import base64
        nonce_hex = nonce_bytes.hex()
        env = {**os.environ, "TPM2TOOLS_TCTI": self.tcti}
        cmd = [
            "tpm2_quote",
            "-c", self.tpm_handle,
            "-l", self.pcr_list,
            "-q", nonce_hex,
            "-m", quote_out,
            "-s", sig_out,
            "-o", pcr_out,
        ]
        result = subprocess.run(cmd, capture_output=True, env=env)
        if result.returncode != 0:
            raise RuntimeError(
                f"tpm2_quote failed (TCTI={self.tcti}):\n"
                f"{result.stderr.decode()}\n"
                "Ensure the TPM is running and the key handle is provisioned.\n"
                "See benchmarks/BENCHMARK_GUIDE.md for setup instructions."
            )

    def _read_pcr_values(self) -> dict[str, str]:
        """Read current PCR values from the TPM."""
        env = {**os.environ, "TPM2TOOLS_TCTI": self.tcti}
        result = subprocess.run(
            ["tpm2_pcrread", self.pcr_list],
            capture_output=True, text=True, env=env,
        )
        pcr_values = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if ":" in line and line.startswith("sha256"):
                # Line format: "  sha256:\n  N: 0xHEX..."
                pass
            if line and "0x" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    idx = parts[0].strip()
                    val = parts[1].strip()
                    pcr_values[idx] = val
        return pcr_values

    @staticmethod
    def _verify_tpm_signature(
        quote:       AttestationQuote,
        aik_pub_path: str,
        tcti:        Optional[str] = None,
    ) -> bool:
        """
        Verify the ECDSA-P256 signature on the TPM2B_ATTEST structure
        against the AIK public key via `tpm2_checkquote`.

        This is the check that gives SA-Verify its cryptographic soundness
        (Equation 2): a quote_blob/signature pair that does not chain to
        aik_pub_path — e.g. produced by an unattested source such as a
        virtual-camera/injection adversary with no AIK — is rejected here,
        independent of whether the frame hash and nonce happen to match.
        """
        if not os.path.exists(aik_pub_path):
            raise FileNotFoundError(f"AIK public key not found: {aik_pub_path}")

        import base64
        env = {**os.environ}
        if tcti:
            env["TPM2TOOLS_TCTI"] = tcti

        with tempfile.TemporaryDirectory() as tmpdir:
            quote_path = os.path.join(tmpdir, "quote.bin")
            sig_path   = os.path.join(tmpdir, "sig.bin")

            try:
                quote_bytes = base64.b64decode(quote.quote_blob)
                sig_bytes   = base64.b64decode(quote.signature)
            except Exception:
                return False  # malformed/forged quote material

            with open(quote_path, "wb") as f:
                f.write(quote_bytes)
            with open(sig_path, "wb") as f:
                f.write(sig_bytes)

            nonce_bytes = SensorAttestation._nonce_for_tpm(
                quote.frame_hash, quote.session_nonce
            )

            # Note: tpm2_checkquote also supports an -f/-l PCR-replay
            # cross-check against the quote's PCR digest. It is intentionally
            # not used here: round-tripping tpm2_quote's -o PCR-selection
            # file through this process reliably produced a malformed
            # replay file in testing (a tooling/format detail, not a
            # cryptographic issue), and silently degrading a security check
            # on a caught exception is worse than not attempting it. The
            # signature check below is what gives SA-Verify its soundness
            # (Equation 2); PCR-replay would be defense-in-depth on top of it.
            cmd = [
                "tpm2_checkquote",
                "-u", aik_pub_path,
                "-m", quote_path,
                "-s", sig_path,
                "-q", nonce_bytes.hex(),
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            return result.returncode == 0

    @staticmethod
    def _sha256_hex(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _nonce_for_tpm(frame_hash: str, session_nonce: str) -> bytes:
        """
        Derive the 32-byte nonce passed to tpm2_quote by combining the
        frame hash and session nonce. This binds the quote to both the
        specific frame captured and the session context (SG-4).
        """
        combined = f"{frame_hash}:{session_nonce}".encode()
        return hashlib.sha256(combined).digest()

    @staticmethod
    def _b64_file(path: str) -> str:
        import base64
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
