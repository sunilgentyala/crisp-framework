"""
SET — Post-Quantum Secure Telemetry Channel
============================================
Component 2 of the CRISP framework.

Establishes an authenticated encrypted channel between the sensor subsystem
and the authentication module using X25519MLKEM768 post-quantum hybrid
key agreement (RFC 9794 / FIPS 203).

Blocks attack class AC-4: SDK interposition via LD_PRELOAD / dyld shims.
Any SDK-boundary substitution of biometric frames breaks the AEAD
integrity check on the authenticated channel.

Security property: channel integrity / injection resistance (SG-3)

References:
  [13] RFC 9794 — Terminology for PQ Traditional Hybrid Schemes, IETF, Jun 2025.
  [14] NIST FIPS 203 — ML-KEM Standard, Aug 2024.
"""

from .channel import SETChannel, ChannelRole
from .handshake import SETHandshake

__all__ = ["SETChannel", "ChannelRole", "SETHandshake"]
