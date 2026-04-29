"""
SET — Handshake: X25519MLKEM768 Hybrid Key Agreement
=====================================================
Implements the channel establishment protocol for the SET component.

Protocol (2-round):
  1. Sensor sends:        X25519_pub_sensor || MLKEM768_ek_sensor
  2. AuthModule sends:    X25519_pub_auth   || MLKEM768_ct
  3. Both sides derive:   shared_secret = KDF(X25519_ss || MLKEM768_ss)
  4. Both sides derive:   AES-256 key    = HKDF(shared_secret, session_id)

This follows the "initiator sends first" pattern in RFC 9794 §4.
Per-session ephemeral keys ensure forward secrecy.

Implementation note:
  This module uses liboqs-python for ML-KEM-768 operations.
  Install: pip install liboqs-python
  The liboqs library must be compiled with ML-KEM support (FIPS 203).
  See benchmarks/BENCHMARK_GUIDE.md for build instructions.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from typing import Tuple, Optional

from .channel import SETChannel, ChannelRole


class SETHandshake:
    """
    Performs the X25519MLKEM768 hybrid key agreement.

    Sensor side (initiator):
        hs = SETHandshake(role=ChannelRole.SENSOR)
        msg1 = hs.initiate()          # send to auth module
        channel = hs.complete(msg2)   # receive from auth module

    Auth module side (responder):
        hs = SETHandshake(role=ChannelRole.AUTH_MODULE)
        msg2 = hs.respond(msg1)       # receive from sensor, send back
        channel = hs.get_channel()    # channel is established after respond()
    """

    MLKEM768_PK_LEN  = 1184    # bytes (FIPS 203 ML-KEM-768 public key)
    MLKEM768_CT_LEN  = 1088    # bytes (ML-KEM-768 ciphertext)
    X25519_PK_LEN    = 32      # bytes

    def __init__(self, role: ChannelRole, session_id: Optional[str] = None):
        self.role       = role
        self.session_id = session_id or secrets.token_hex(32)
        self._channel:  Optional[SETChannel] = None

        # X25519 ephemeral key
        self._x25519_priv: Optional[bytes] = None
        self._x25519_pub:  Optional[bytes] = None

        # ML-KEM-768 state
        self._mlkem_priv: Optional[bytes] = None   # sensor side only
        self._mlkem_pub:  Optional[bytes] = None   # sensor side (encapsulation key)

        self._x25519_ss:  Optional[bytes] = None   # X25519 shared secret
        self._mlkem_ss:   Optional[bytes] = None   # ML-KEM shared secret

        self._generate_ephemeral_keys()

    # ── Public API ───────────────────────────────────────────────────────────

    def initiate(self) -> bytes:
        """
        Sensor side: generate and return the first handshake message.

        Returns bytes: X25519_pub (32B) || MLKEM768_ek (1184B) = 1216 bytes
        """
        if self.role != ChannelRole.SENSOR:
            raise ValueError("Only the sensor (initiator) calls initiate()")
        return self._x25519_pub + self._mlkem_pub

    def respond(self, msg1: bytes) -> bytes:
        """
        Auth module side: process the sensor's message and return msg2.

        Parameters: msg1 = X25519_pub_sensor (32B) || MLKEM_ek_sensor (1184B)
        Returns:    msg2 = X25519_pub_auth (32B) || MLKEM_ct (1088B) = 1120 bytes

        Side effect: establishes the SETChannel (accessible via get_channel()).
        """
        if self.role != ChannelRole.AUTH_MODULE:
            raise ValueError("Only the auth module (responder) calls respond()")
        if len(msg1) != self.X25519_PK_LEN + self.MLKEM768_PK_LEN:
            raise ValueError(f"Unexpected msg1 length: {len(msg1)}")

        x25519_pub_sensor = msg1[:self.X25519_PK_LEN]
        mlkem_ek_sensor   = msg1[self.X25519_PK_LEN:]

        # X25519 key exchange
        self._x25519_ss = self._x25519_dh(self._x25519_priv, x25519_pub_sensor)

        # ML-KEM-768 encapsulation (auth module encapsulates to sensor's ek)
        mlkem_ct, self._mlkem_ss = self._mlkem_encapsulate(mlkem_ek_sensor)

        # Derive channel key
        self._channel = self._derive_channel()

        return self._x25519_pub + mlkem_ct

    def complete(self, msg2: bytes) -> SETChannel:
        """
        Sensor side: process auth module's response, return established channel.

        Parameters: msg2 = X25519_pub_auth (32B) || MLKEM_ct (1088B)
        """
        if self.role != ChannelRole.SENSOR:
            raise ValueError("Only the sensor (initiator) calls complete()")
        if len(msg2) != self.X25519_PK_LEN + self.MLKEM768_CT_LEN:
            raise ValueError(f"Unexpected msg2 length: {len(msg2)}")

        x25519_pub_auth = msg2[:self.X25519_PK_LEN]
        mlkem_ct        = msg2[self.X25519_PK_LEN:]

        # X25519 key exchange
        self._x25519_ss = self._x25519_dh(self._x25519_priv, x25519_pub_auth)

        # ML-KEM-768 decapsulation
        self._mlkem_ss = self._mlkem_decapsulate(self._mlkem_priv, mlkem_ct)

        self._channel = self._derive_channel()
        return self._channel

    def get_channel(self) -> SETChannel:
        if self._channel is None:
            raise RuntimeError("Handshake not yet complete.")
        return self._channel

    # ── Private helpers ──────────────────────────────────────────────────────

    def _generate_ephemeral_keys(self) -> None:
        """Generate per-session ephemeral X25519 and ML-KEM-768 keys."""
        # X25519 ephemeral key
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        self._x25519_priv = priv
        self._x25519_pub  = priv.public_key().public_bytes_raw()

        # ML-KEM-768 key pair (sensor side only; auth module just encapsulates)
        if self.role == ChannelRole.SENSOR:
            try:
                import oqs
                kem = oqs.KeyEncapsulation("ML-KEM-768")
                self._mlkem_pub  = kem.generate_keypair()
                self._mlkem_priv = kem   # Keep the OQS object for decapsulation
            except ImportError:
                raise ImportError(
                    "liboqs-python is required for ML-KEM-768.\n"
                    "Install: pip install liboqs-python\n"
                    "And ensure liboqs is compiled. See benchmarks/BENCHMARK_GUIDE.md"
                )

    def _x25519_dh(self, priv, peer_pub_bytes: bytes) -> bytes:
        """Perform X25519 DH and return the 32-byte shared secret."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        return priv.exchange(peer_pub)

    @staticmethod
    def _mlkem_encapsulate(ek: bytes) -> Tuple[bytes, bytes]:
        """ML-KEM-768 encapsulation. Returns (ciphertext, shared_secret)."""
        try:
            import oqs
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            ct, ss = kem.encap_secret(ek)
            return ct, ss
        except ImportError:
            raise ImportError("liboqs-python required for ML-KEM-768 encapsulation.")

    @staticmethod
    def _mlkem_decapsulate(kem_obj, ct: bytes) -> bytes:
        """ML-KEM-768 decapsulation. Returns shared_secret."""
        try:
            return kem_obj.decap_secret(ct)
        except Exception as e:
            raise RuntimeError(f"ML-KEM-768 decapsulation failed: {e}")

    def _derive_channel(self) -> SETChannel:
        """
        Derive the AES-256-GCM key from the hybrid shared secret.

        Hybrid combiner (RFC 9794 §4):
          combined = X25519_ss || ML-KEM_ss || session_id
          aes_key  = HKDF-SHA256(combined, salt=b"crisp-set-v1", length=32)

        Security: if either component ss is pseudorandom, the combined
        key is pseudorandom (hybrid security, RFC 9794 Theorem 1).
        """
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        combined = self._x25519_ss + self._mlkem_ss + self.session_id.encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"crisp-set-v1",
            info=b"aes256gcm-key",
        )
        aes_key = hkdf.derive(combined)
        return SETChannel(
            role=self.role,
            session_id=self.session_id,
            _aes_key=aes_key,
        )
