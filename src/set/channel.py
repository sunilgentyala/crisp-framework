"""
SET — Secure Telemetry Channel (X25519MLKEM768 + AES-256-GCM)
=============================================================
Implements the SET component described in Section IV.B of the paper.

Key agreement: X25519MLKEM768 hybrid (RFC 9794 §4)
  - Classical component:    X25519 Diffie-Hellman (CDH hardness)
  - Post-quantum component: ML-KEM-768 (LWE hardness, FIPS 203)
  - Hybrid shared secret:   KDF(X25519_ss || MLKEM_ss)
  - Channel cipher:         AES-256-GCM (authenticated encryption)

Hybrid security guarantee (per RFC 9794 §4):
  If EITHER the X25519 component is secure under CDH OR the ML-KEM-768
  component is secure under LWE, then the combined channel is secure.
  Security does not require both to hold simultaneously.

IND-CCA2 security: ML-KEM-768 classical hardness 2^178 ops,
                   quantum hardness 2^164 ops (NIST parameter set).

Implementation requires:
  pip install liboqs-python   (Python bindings for liboqs)
  or: openssl 3.x + oqs-provider (see BENCHMARK_GUIDE.md)
"""

from __future__ import annotations

import enum
import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Optional, Tuple


class ChannelRole(enum.Enum):
    SENSOR       = "sensor"        # Initiator (sensor subsystem)
    AUTH_MODULE  = "auth_module"   # Responder (authentication module)


@dataclass
class SETChannel:
    """
    Established SET channel state. Holds the symmetric key material
    and session context for encrypting biometric frame telemetry.

    Created via SETHandshake.complete() — do not instantiate directly.

    Usage:
        # Encrypt a frame (sensor side)
        ciphertext, tag = channel.encrypt(frame_bytes)

        # Decrypt and authenticate (auth module side)
        frame_bytes = channel.decrypt(ciphertext, tag)
    """

    role:         ChannelRole
    session_id:   str               # 32-byte hex session identifier
    _aes_key:     bytes = field(repr=False)   # 32-byte AES-256 key
    _frame_counter: int = field(default=0, repr=False)

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM.

        Returns (ciphertext, tag) where tag is the 16-byte AEAD
        authentication tag. The nonce is derived deterministically
        from the frame counter to avoid nonce reuse.

        The counter is incremented after each call. Wrap-around at
        2^32 frames triggers a channel re-key (not yet implemented;
        authentication sessions are expected to be << 2^32 frames).
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = self._derive_nonce(self._frame_counter)
        aad   = self._aad(self._frame_counter)

        aesgcm     = AESGCM(self._aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        # AES-GCM appends 16-byte tag to ciphertext
        ct, tag = ciphertext[:-16], ciphertext[-16:]
        self._frame_counter += 1
        return ct, tag

    def decrypt(self, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Decrypt and authenticate AES-256-GCM ciphertext.

        Raises cryptography.exceptions.InvalidTag if authentication fails,
        which indicates channel tampering (AC-4 SDK interposition attempt).
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag

        nonce = self._derive_nonce(self._frame_counter)
        aad   = self._aad(self._frame_counter)

        aesgcm = AESGCM(self._aes_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad)
        except InvalidTag:
            raise InjectionAttemptError(
                "SET channel: AEAD authentication tag verification failed. "
                "This indicates AC-4 SDK interposition or channel tampering."
            )
        self._frame_counter += 1
        return plaintext

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _derive_nonce(self, counter: int) -> bytes:
        """
        Derive a 12-byte AES-GCM nonce from the session ID and frame counter.
        Using a KDF-derived nonce (rather than a random one) avoids nonce
        reuse without requiring nonce synchronization between sensor and
        auth module — both sides derive the same nonce from the same counter.
        """
        material = f"crisp-set-nonce:{self.session_id}:{counter}".encode()
        return hashlib.sha256(material).digest()[:12]

    def _aad(self, counter: int) -> bytes:
        """
        Additional authenticated data: session ID + frame counter.
        Binds each ciphertext to its position in the session stream,
        preventing frame reordering attacks.
        """
        return f"crisp-set:{self.session_id}:{counter}".encode()


class InjectionAttemptError(Exception):
    """Raised when AEAD verification fails, indicating a possible AC-4 attack."""
    pass
