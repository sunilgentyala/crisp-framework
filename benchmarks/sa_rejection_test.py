"""
CRISP Framework — Real SA/SET Protocol-Level Rejection Test
=============================================================
Paper: "The Weaponization of Deepfakes: A Novel Cryptographic Framework
        Mitigating Biometric Injection and Identity Gaps"

Purpose:
    The paper claims (Section VI.D) that SA blocks AC-2/AC-3 injection
    "by construction" and SET blocks AC-4 SDK interposition via its AEAD
    integrity check. This script replaces that "by construction" assertion
    with a measured empirical result by driving the actual src/sa and
    src/set modules against genuine and adversarial inputs.

Adversary model (Section III.B — no physical sensor/TPM access):
    AC-2 / AC-3 sim A (no attestation at all):
        Adversary submits a frame with no TPM quote whatsoever.
    AC-2 / AC-3 sim B (forged quote):
        Adversary fabricates random quote_blob/signature bytes and
        stamps the correct frame_hash/session_nonce fields to pass the
        hash/nonce checks, attempting to bypass the *signature* check.
    AC-2 / AC-3 sim C (unauthorized key):
        Adversary provisions their OWN AIK (as any virtual-camera/injection
        tool could — provisioning is unauthenticated) and produces a
        genuinely valid TPM quote, but signed by a key the auth module's
        trust anchor never certified. This is the realistic AC-3 case:
        virtual camera software cannot obtain the CERTIFIED sensor's AIK.
    AC-4 (SET channel tampering):
        Adversary intercepts/modifies ciphertext or tag in transit
        (LD_PRELOAD-style SDK interposition). Tests SETChannel.decrypt().

    Bona fide case (BPCER check):
        A genuine frame, genuinely attested by the provisioned sensor AIK,
        must be ACCEPTED. This is measured alongside the attack rejection
        rate so we're not just measuring "rejects everything."

Usage:
    python3 benchmarks/sa_rejection_test.py
"""

from __future__ import annotations

import base64
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sa.attestation import SensorAttestation, AttestationQuote, DEFAULT_PCR_LIST
from sa.provisioning import SensorProvisioner
from set.channel import SETChannel, ChannelRole, InjectionAttemptError as SETInjectionError

TCTI = "swtpm:path=/tmp/vtpm/sock"
WORKDIR = Path("/tmp/crisp-sa-rejection-test")


def run(cmd, env=None, check=True):
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{result.stderr}")
    return result


def main():
    print("CRISP: Real SA/SET Protocol-Level Rejection Test")
    print("=" * 60)
    WORKDIR.mkdir(exist_ok=True)

    print("\n[setup] Connecting to swtpm (expected already running at /tmp/vtpm/sock)...")
    env = {**os.environ, "TPM2TOOLS_TCTI": TCTI}
    run(["tpm2_startup", "-c"], env=env, check=False)

    if True:
        env = {**os.environ, "TPM2TOOLS_TCTI": TCTI}

        # ── Provision the LEGITIMATE sensor AIK (handle 0x81000001) ──────────
        print("[setup] Provisioning legitimate sensor AIK...")
        legit_provisioner = SensorProvisioner(
            tpm_handle="0x81000001", tcti=TCTI, work_dir=str(WORKDIR / "legit")
        )
        legit = legit_provisioner.provision(sensor_id="sensor-legit-001")
        aik_pub_legit = legit["aik_pub"]

        # ── Provision an UNAUTHORIZED AIK at a different handle ───────────────
        # Simulates AC-3: virtual camera / injection tool can provision ITS OWN
        # key (provisioning itself isn't gated) but the auth module only
        # trusts aik_pub_legit as the certified sensor identity.
        print("[setup] Provisioning unauthorized (adversary) AIK...")
        adv_provisioner = SensorProvisioner(
            tpm_handle="0x81000002", tcti=TCTI, work_dir=str(WORKDIR / "adversary")
        )
        adversary = adv_provisioner.provision(sensor_id="adversary-vcam-001")

        sa_legit = SensorAttestation(tpm_handle="0x81000001", tcti=TCTI)
        sa_adversary = SensorAttestation(tpm_handle="0x81000002", tcti=TCTI)

        results = {}

        # ── Bona fide case: genuine frame, genuine quote (BPCER check) ────────
        print("\n[test] Bona fide: genuine frame + genuine attested quote")
        n_trials = 20
        n_accepted = 0
        for i in range(n_trials):
            frame = secrets.token_bytes(4096)
            nonce = SensorAttestation.generate_session_nonce()
            quote = sa_legit.quote_frame(frame, nonce)
            accepted = SensorAttestation.verify_quote(
                quote, frame, nonce, aik_pub_legit, tcti=TCTI
            )
            if accepted:
                n_accepted += 1
        results["bona_fide_accept_rate"] = (n_trials, n_accepted)
        print(f"  Accepted {n_accepted}/{n_trials} genuine sessions "
              f"(BPCER = {(n_trials - n_accepted) / n_trials * 100:.1f}%)")
        # Keep the last (frame, nonce) pair around for sim A / sim B below.

        # ── AC-2/AC-3 sim A: no attestation at all ────────────────────────────
        print("\n[test] AC-2/AC-3 sim A: frame with no TPM quote")
        # No quote object can even be constructed without a TPM signature;
        # the closest real-world equivalent is the auth module receiving a
        # frame with zero/empty quote fields.
        forged_empty = AttestationQuote(
            frame_hash=SensorAttestation._sha256_hex(frame),
            session_nonce=nonce,
            pcr_values={},
            quote_blob="",
            signature="",
        )
        try:
            accepted = SensorAttestation.verify_quote(
                forged_empty, frame, nonce, aik_pub_legit, tcti=TCTI
            )
        except Exception:
            accepted = False
        results["ac2_3_sim_a"] = accepted
        print(f"  ACCEPTED: {accepted}  (expected False)")

        # ── AC-2/AC-3 sim B: forged quote/signature bytes, correct hash+nonce ─
        print("\n[test] AC-2/AC-3 sim B: random forged quote_blob+signature")
        n_trials = 20
        n_rejected = 0
        for i in range(n_trials):
            forged = AttestationQuote(
                frame_hash=SensorAttestation._sha256_hex(frame),
                session_nonce=nonce,
                pcr_values={},
                quote_blob=base64.b64encode(secrets.token_bytes(64)).decode(),
                signature=base64.b64encode(secrets.token_bytes(64)).decode(),
            )
            try:
                accepted = SensorAttestation.verify_quote(
                    forged, frame, nonce, aik_pub_legit, tcti=TCTI
                )
            except Exception:
                accepted = False
            if not accepted:
                n_rejected += 1
        results["ac2_3_sim_b"] = (n_trials, n_rejected)
        print(f"  Rejected {n_rejected}/{n_trials} forged-signature attempts "
              f"(APCER = {(n_trials - n_rejected) / n_trials * 100:.1f}%)")

        # ── AC-2/AC-3 sim C: genuinely valid quote, but from the UNAUTHORIZED
        #    (uncertified) AIK — the realistic virtual-camera/injection case ──
        print("\n[test] AC-2/AC-3 sim C: valid quote from uncertified adversary AIK")
        n_trials = 20
        n_rejected = 0
        for i in range(n_trials):
            adv_frame = secrets.token_bytes(4096)
            adv_nonce = SensorAttestation.generate_session_nonce()
            adv_quote = sa_adversary.quote_frame(adv_frame, adv_nonce)
            # Auth module verifies against the CERTIFIED sensor's public key,
            # not the adversary's — this is the trust-anchor check.
            try:
                accepted = SensorAttestation.verify_quote(
                    adv_quote, adv_frame, adv_nonce, aik_pub_legit, tcti=TCTI
                )
            except Exception:
                accepted = False
            if not accepted:
                n_rejected += 1
        results["ac2_3_sim_c"] = (n_trials, n_rejected)
        print(f"  Rejected {n_rejected}/{n_trials} uncertified-AIK attempts "
              f"(APCER = {(n_trials - n_rejected) / n_trials * 100:.1f}%)")

        # ── AC-4: SET channel AEAD tampering ──────────────────────────────────
        # Exercises SETChannel's AEAD encrypt/decrypt directly (the exact
        # logic that runs after a real X25519MLKEM768 handshake — key
        # agreement itself is benchmarked separately via openssl+oqs-provider
        # in set_bench.py / set_results.txt, not re-derived here).
        print("\n[test] AC-4: SET channel AEAD tag/ciphertext tampering")

        def make_channel_pair():
            session_id = secrets.token_hex(32)
            aes_key = secrets.token_bytes(32)
            sensor_ch = SETChannel(role=ChannelRole.SENSOR, session_id=session_id, _aes_key=aes_key)
            auth_ch = SETChannel(role=ChannelRole.AUTH_MODULE, session_id=session_id, _aes_key=aes_key)
            return sensor_ch, auth_ch

        sensor_channel, auth_channel = make_channel_pair()
        plaintext = b"legit biometric frame telemetry"
        ct, tag = sensor_channel.encrypt(plaintext)

        # Legit path: auth module decrypts untampered ciphertext
        recovered = auth_channel.decrypt(ct, tag)
        legit_ok = recovered == plaintext
        print(f"  Untampered decrypt succeeds: {legit_ok} (expected True)")

        # Adversary tampers with ciphertext (simulating LD_PRELOAD substitution)
        n_trials = 20
        n_rejected = 0
        for i in range(n_trials):
            s_ch, a_ch = make_channel_pair()
            ct2, tag2 = s_ch.encrypt(b"frame telemetry " + secrets.token_bytes(8))
            tampered_ct = bytearray(ct2)
            tampered_ct[0] ^= 0xFF  # flip a bit — simulates substituted frame data
            try:
                a_ch.decrypt(bytes(tampered_ct), tag2)
                rejected = False
            except SETInjectionError:
                rejected = True
            except Exception:
                rejected = True
            if rejected:
                n_rejected += 1
        results["ac4"] = (n_trials, n_rejected)
        print(f"  Rejected {n_rejected}/{n_trials} tampered-ciphertext attempts "
              f"(APCER = {(n_trials - n_rejected) / n_trials * 100:.1f}%)")

        # ── Summary ────────────────────────────────────────────────────────
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Bona fide acceptance      : {results['bona_fide_accept_rate'][1]}/{results['bona_fide_accept_rate'][0]}")
        print(f"AC-2/3 sim A (no quote)   : rejected={not results['ac2_3_sim_a']}")
        print(f"AC-2/3 sim B (forged sig) : {results['ac2_3_sim_b'][1]}/{results['ac2_3_sim_b'][0]} rejected")
        print(f"AC-2/3 sim C (wrong AIK)  : {results['ac2_3_sim_c'][1]}/{results['ac2_3_sim_c'][0]} rejected")
        print(f"AC-4 (AEAD tamper)        : {results['ac4'][1]}/{results['ac4'][0]} rejected")


if __name__ == "__main__":
    main()
