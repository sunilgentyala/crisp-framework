"""
SA — TPM 2.0 Sensor Attestation
================================
Component 1 of the CRISP framework.

Provides hardware-bound cryptographic attestation of biometric sensor
frames using TPM 2.0 Attestation Identity Keys (AIK) and PCR quotes.
Blocks attack classes AC-2 (driver-layer injection) and AC-3 (virtual camera).

Security property: Sensor Binding (SG-1)
  The authentication module can verify, with cryptographic soundness,
  that received biometric data originated from an attested physical
  sensor within the current session.

References:
  [15] TCG TPM 2.0 Library Specification, Family 2.0, Rev 01.59, 2019.
  [12] RFC 9683 — Remote Integrity Verification, IETF, Nov 2024.
  [16] Microsoft Windows Biometric Framework, Sensor Requirements, 2023.
"""

from .attestation import SensorAttestation, AttestationQuote
from .provisioning import SensorProvisioner

__all__ = ["SensorAttestation", "AttestationQuote", "SensorProvisioner"]
