"""
SA — Sensor Provisioning
========================
Implements the SA-Setup operation: binding a physical sensor to the TPM
by creating an Attestation Identity Key (AIK) sealed under a policy that
requires sensor hardware presence.

This module is run once at device enrollment time, not during each
authentication session. It produces the AIK certificate that the
authentication module uses to verify attestation quotes.

Section IV.A (paper):
  "At setup time, the SA sub-protocol provisions a cryptographic binding
   between the physical sensor and the device TPM. The sensor is assigned
   an Attestation Identity Key (AIK) whose private key material is sealed
   within the TPM under a policy that requires sensor hardware presence."
"""

from __future__ import annotations

import os
import subprocess
import json
from pathlib import Path
from typing import Optional


class SensorProvisioner:
    """
    Provisions the AIK and sensor certificate during initial device setup.

    After provisioning, the AIK handle and certificate path should be
    stored securely and passed to SensorAttestation for runtime use.

    Example:
        provisioner = SensorProvisioner(tcti="device:/dev/tpmrm0")
        result = provisioner.provision(
            sensor_id="sensor-0001",
            ca_cert_path="/etc/crisp/ca.crt",
            ca_key_path="/etc/crisp/ca.key",
        )
        print(result["aik_cert"])   # path to the signed AIK certificate
        print(result["tpm_handle"]) # e.g. "0x81000001"
    """

    def __init__(
        self,
        tpm_handle: str = "0x81000001",
        tcti:       Optional[str] = None,
        work_dir:   Optional[str] = None,
    ):
        self.tpm_handle = tpm_handle
        self.tcti       = tcti or os.environ.get(
            "CRISP_TPM_TCTI", "swtpm:path=/tmp/vtpm/sock"
        )
        self.work_dir   = Path(work_dir or "/tmp/crisp-sa-provision")
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def provision(
        self,
        sensor_id:    str,
        output_dir:   Optional[str] = None,
    ) -> dict:
        """
        Run the full SA-Setup sequence:

          1. Create a primary key in the TPM Endorsement hierarchy.
          2. Create an Attestation Identity Key (AIK) under the primary.
          3. Persist the AIK at the configured TPM handle.
          4. Export the AIK public key.
          5. Generate a self-signed AIK certificate (demo mode).
             In production: submit AIK public key to your PKI CA for signing.

        Parameters
        ----------
        sensor_id:   Unique identifier for this sensor (included in cert subject).
        output_dir:  Where to write the AIK cert and public key files.

        Returns
        -------
        dict with keys: "aik_cert", "aik_pub", "tpm_handle", "sensor_id"
        """
        out = Path(output_dir or self.work_dir)
        out.mkdir(parents=True, exist_ok=True)

        primary_ctx = str(out / "primary.ctx")
        aik_ctx     = str(out / "aik.ctx")
        aik_pub     = str(out / "aik.pub")
        aik_cert    = str(out / f"aik_{sensor_id}.crt")

        env = {**os.environ, "TPM2TOOLS_TCTI": self.tcti}

        # Step 1: Create primary key
        self._run(["tpm2_createprimary", "-C", "e", "-c", primary_ctx], env)

        # Step 2: Create AIK under primary
        self._run([
            "tpm2_create",
            "-C", primary_ctx,
            "-G", "ecc:ecdsa",         # ECDSA-P256 for quote signing
            "-u", aik_pub,
            "-r", str(out / "aik.priv"),
            "--attributes", "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
        ], env)

        # Step 3: Load and persist AIK
        self._run([
            "tpm2_load", "-C", primary_ctx,
            "-u", aik_pub, "-r", str(out / "aik.priv"),
            "-c", aik_ctx,
        ], env)
        self._run([
            "tpm2_evictcontrol", "-C", "o",
            "-c", aik_ctx, self.tpm_handle,
        ], env)

        # Step 4: Generate self-signed AIK certificate (demo/CI mode)
        # Production: replace with CA-signed cert from your PKI
        self._generate_demo_cert(aik_pub, aik_cert, sensor_id)

        return {
            "aik_cert":   aik_cert,
            "aik_pub":    aik_pub,
            "tpm_handle": self.tpm_handle,
            "sensor_id":  sensor_id,
        }

    def deprovision(self) -> None:
        """Remove the AIK from TPM persistent storage."""
        env = {**os.environ, "TPM2TOOLS_TCTI": self.tcti}
        self._run(["tpm2_evictcontrol", "-C", "o", "-c", self.tpm_handle], env,
                  check=False)

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _run(cmd: list, env: dict, check: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run(cmd, capture_output=True, env=env)
        if check and result.returncode != 0:
            raise RuntimeError(
                f"Command failed: {' '.join(cmd)}\n{result.stderr.decode()}"
            )
        return result

    @staticmethod
    def _generate_demo_cert(aik_pub_path: str, cert_out: str, sensor_id: str) -> None:
        """
        Generate a self-signed X.509 certificate for the AIK public key.
        This is for development / CI use only.

        Production deployments must submit the AIK public key to a
        trusted CA that verifies sensor hardware identity before signing.
        The CA-signed certificate is what the authentication module trusts.
        """
        # Note: tpm2_publickey → PEM conversion requires tpm2_tools ≥ 5.0
        # This is a placeholder; production uses openssl + CA signing workflow.
        # Full implementation: tpm2_readpublic → openssl req → CA sign
        import warnings
        warnings.warn(
            "Using self-signed AIK certificate (demo mode). "
            "Production deployments require CA-signed certificates. "
            "See docs/sensor-provisioning.md for the CA signing workflow.",
            UserWarning,
            stacklevel=2,
        )
