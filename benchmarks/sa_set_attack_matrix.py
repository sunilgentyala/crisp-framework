"""
CRISP Framework: SA/SET Attack Matrix and Ablation
===================================================

Purpose:
    Extend the protocol-level rejection test (sa_rejection_test.py) into a
    wider attack matrix with more trials per condition, exact confidence
    intervals, and an ablation that shows which verifier check blocks which
    attack.

What it measures:
    Protocol-level behavior of the real src/sa and src/set modules against
    genuine and adversarial inputs. It does NOT measure biometric accuracy,
    liveness, hardware capture security, or resistance to an adaptive
    adversary with access to the sensor or the TPM.

Verifier configurations compared (ablation):
    full         : frame hash + nonce + AIK signature (SensorAttestation.verify_quote)
    hash+nonce   : frame hash + nonce only (signature check removed)
    none         : accepts everything (a pipeline with no capture attestation)

Outcome classes per trial:
    accepted     : verifier returned True (an attack that succeeds)
    rejected     : verifier returned False or raised its documented rejection error
    error        : any other exception (reported separately, never counted as a rejection)

Usage (WSL or Linux with swtpm and tpm2-tools running, see BENCHMARK_GUIDE.md):
    python3 benchmarks/sa_set_attack_matrix.py [N_TRIALS]
"""

from __future__ import annotations

import base64
import os
import secrets
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sa.attestation import SensorAttestation, AttestationQuote
from sa.provisioning import SensorProvisioner
from set.channel import SETChannel, ChannelRole, InjectionAttemptError as SETInjectionError

TCTI = "swtpm:path=/tmp/vtpm/sock"
WORKDIR = Path("/tmp/crisp-attack-matrix")


# ── statistics ───────────────────────────────────────────────────────────────

def _binom_cdf(k: int, n: int, p: float) -> float:
    from math import comb
    return sum(comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(0, k + 1))


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact two-sided (1-alpha) binomial confidence interval for k successes in n trials."""
    if n == 0:
        return (0.0, 1.0)

    def solve(target_fn, increasing: bool) -> float:
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            above = target_fn(mid) > alpha / 2
            if above == increasing:
                hi = mid
            else:
                lo = mid
        return (lo + hi) / 2

    # lower: P(X >= k | p) rises with p; find p where it first exceeds alpha/2
    lower = 0.0 if k == 0 else solve(lambda p: 1 - _binom_cdf(k - 1, n, p), increasing=True)
    # upper: P(X <= k | p) falls with p; find p where it drops to alpha/2
    upper = 1.0 if k == n else solve(lambda p: _binom_cdf(k, n, p), increasing=False)
    return (lower, upper)


# ── verifier variants ────────────────────────────────────────────────────────

def verify_full(quote, frame, nonce, aik_pub):
    return SensorAttestation.verify_quote(quote, frame, nonce, aik_pub, tcti=TCTI)


def verify_hash_nonce(quote, frame, nonce, aik_pub):
    if quote.frame_hash != SensorAttestation._sha256_hex(frame):
        return False
    return quote.session_nonce == nonce


def verify_none(quote, frame, nonce, aik_pub):
    return True


VERIFIERS = {"full": verify_full, "hash+nonce": verify_hash_nonce, "none": verify_none}


def classify(fn, *args) -> str:
    try:
        return "accepted" if fn(*args) else "rejected"
    except SETInjectionError:
        return "rejected"
    except Exception:
        return "error"


def flip_bit_b64(b64: str, byte_index: int = 0) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[byte_index % len(raw)] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    print(f"CRISP SA/SET attack matrix, n={n} trials per condition")
    print("=" * 66)
    WORKDIR.mkdir(exist_ok=True)

    env = {**os.environ, "TPM2TOOLS_TCTI": TCTI}
    subprocess.run(["tpm2_startup", "-c"], env=env, capture_output=True)

    legit = SensorProvisioner(tpm_handle="0x81000001", tcti=TCTI, work_dir=str(WORKDIR / "legit")).provision(sensor_id="sensor-legit-001")
    adversary = SensorProvisioner(tpm_handle="0x81000002", tcti=TCTI, work_dir=str(WORKDIR / "adversary")).provision(sensor_id="adversary-vcam-001")
    aik_pub = legit["aik_pub"]
    sa_legit = SensorAttestation(tpm_handle="0x81000001", tcti=TCTI)
    sa_adv = SensorAttestation(tpm_handle="0x81000002", tcti=TCTI)

    # Each SA condition builds (quote, frame_expected, nonce_expected) per trial.
    def bona_fide():
        frame = secrets.token_bytes(4096)
        nonce = SensorAttestation.generate_session_nonce()
        return sa_legit.quote_frame(frame, nonce), frame, nonce

    def no_quote():
        frame = secrets.token_bytes(4096)
        nonce = SensorAttestation.generate_session_nonce()
        q = AttestationQuote(frame_hash=SensorAttestation._sha256_hex(frame), session_nonce=nonce,
                             pcr_values={}, quote_blob="", signature="")
        return q, frame, nonce

    def forged_signature():
        frame = secrets.token_bytes(4096)
        nonce = SensorAttestation.generate_session_nonce()
        q = AttestationQuote(frame_hash=SensorAttestation._sha256_hex(frame), session_nonce=nonce, pcr_values={},
                             quote_blob=base64.b64encode(secrets.token_bytes(64)).decode(),
                             signature=base64.b64encode(secrets.token_bytes(64)).decode())
        return q, frame, nonce

    def uncertified_aik():
        frame = secrets.token_bytes(4096)
        nonce = SensorAttestation.generate_session_nonce()
        return sa_adv.quote_frame(frame, nonce), frame, nonce

    def cross_session_replay():
        # Genuine quote from an earlier session, replayed into a new session.
        old_frame = secrets.token_bytes(4096)
        old_nonce = SensorAttestation.generate_session_nonce()
        old_quote = sa_legit.quote_frame(old_frame, old_nonce)
        new_nonce = SensorAttestation.generate_session_nonce()
        return old_quote, old_frame, new_nonce

    def frame_substitution():
        # Genuine quote for frame A; attacker presents injected frame B.
        frame_a = secrets.token_bytes(4096)
        nonce = SensorAttestation.generate_session_nonce()
        quote = sa_legit.quote_frame(frame_a, nonce)
        return quote, secrets.token_bytes(4096), nonce

    def relabeled_quote():
        # Attacker takes a genuine quote and rewrites its frame_hash and nonce
        # fields to match an injected frame and a fresh nonce.
        frame_a = secrets.token_bytes(4096)
        nonce_a = SensorAttestation.generate_session_nonce()
        quote = sa_legit.quote_frame(frame_a, nonce_a)
        frame_b = secrets.token_bytes(4096)
        nonce_b = SensorAttestation.generate_session_nonce()
        relabeled = replace(quote, frame_hash=SensorAttestation._sha256_hex(frame_b), session_nonce=nonce_b)
        return relabeled, frame_b, nonce_b

    def quote_blob_bitflip():
        q, frame, nonce = bona_fide()
        return replace(q, quote_blob=flip_bit_b64(q.quote_blob)), frame, nonce

    def signature_bitflip():
        q, frame, nonce = bona_fide()
        return replace(q, signature=flip_bit_b64(q.signature)), frame, nonce

    SA_CONDITIONS = [
        ("bona fide (should accept)", bona_fide, True),
        ("A1 no quote", no_quote, False),
        ("A2 forged signature bytes", forged_signature, False),
        ("A3 valid quote, uncertified AIK", uncertified_aik, False),
        ("A4 cross-session replay", cross_session_replay, False),
        ("A5 frame substitution", frame_substitution, False),
        ("A6 relabeled quote fields", relabeled_quote, False),
        ("A7 quote blob 1-bit flip", quote_blob_bitflip, False),
        ("A8 signature 1-bit flip", signature_bitflip, False),
    ]

    rows = []
    print("\nSA conditions: outcomes per verifier configuration")
    for name, builder, genuine in SA_CONDITIONS:
        trials = [builder() for _ in range(n)]
        row = {"name": name, "genuine": genuine}
        for vname, vfn in VERIFIERS.items():
            counts = {"accepted": 0, "rejected": 0, "error": 0}
            for q, frame, nonce in trials:
                counts[classify(vfn, q, frame, nonce, aik_pub)] += 1
            row[vname] = counts
        rows.append(row)
        f = row["full"]
        print(f"  {name:36s} full: acc={f['accepted']:3d} rej={f['rejected']:3d} err={f['error']:2d} | "
              f"hash+nonce acc={row['hash+nonce']['accepted']:3d} | none acc={row['none']['accepted']:3d}")

    # ── SET conditions ──────────────────────────────────────────────────────
    def channel_pair():
        sid = secrets.token_hex(32)
        key = secrets.token_bytes(32)
        return (SETChannel(role=ChannelRole.SENSOR, session_id=sid, _aes_key=key),
                SETChannel(role=ChannelRole.AUTH_MODULE, session_id=sid, _aes_key=key))

    def set_trial(kind: str) -> str:
        s, a = channel_pair()
        msg = b"frame telemetry " + secrets.token_bytes(16)
        ct, tag = s.encrypt(msg)
        if kind == "bona fide":
            return "accepted" if classify(lambda: a.decrypt(ct, tag) == msg) == "accepted" else "rejected"
        if kind == "ciphertext 1-bit flip":
            b = bytearray(ct); b[0] ^= 1
            return classify(lambda: a.decrypt(bytes(b), tag) is not None)
        if kind == "tag 1-bit flip":
            b = bytearray(tag); b[0] ^= 1
            return classify(lambda: a.decrypt(ct, bytes(b)) is not None)
        if kind == "replay of accepted frame":
            a.decrypt(ct, tag)
            return classify(lambda: a.decrypt(ct, tag) is not None)
        if kind == "frame reorder":
            ct2, tag2 = s.encrypt(b"second " + secrets.token_bytes(16))
            return classify(lambda: a.decrypt(ct2, tag2) is not None)
        if kind == "truncated ciphertext":
            return classify(lambda: a.decrypt(ct[:-1], tag) is not None)
        if kind == "wrong session key":
            _, other = channel_pair()
            return classify(lambda: other.decrypt(ct, tag) is not None)
        raise ValueError(kind)

    SET_CONDITIONS = [("bona fide (should accept)", "bona fide", True),
                      ("S1 ciphertext 1-bit flip", "ciphertext 1-bit flip", False),
                      ("S2 tag 1-bit flip", "tag 1-bit flip", False),
                      ("S3 replay of accepted frame", "replay of accepted frame", False),
                      ("S4 frame reorder", "frame reorder", False),
                      ("S5 truncated ciphertext", "truncated ciphertext", False),
                      ("S6 wrong session key", "wrong session key", False)]
    set_rows = []
    print("\nSET conditions (AES-256-GCM channel, counter-bound AAD)")
    for name, kind, genuine in SET_CONDITIONS:
        counts = {"accepted": 0, "rejected": 0, "error": 0}
        for _ in range(n):
            counts[set_trial(kind)] += 1
        set_rows.append({"name": name, "genuine": genuine, "counts": counts})
        print(f"  {name:36s} acc={counts['accepted']:3d} rej={counts['rejected']:3d} err={counts['error']:2d}")

    # ── summary with exact CIs ───────────────────────────────────────────────
    def fmt(k, total):
        lo, hi = clopper_pearson(k, total)
        return f"{k}/{total} ({100*k/total:.1f}%, 95% CI {100*lo:.2f}-{100*hi:.2f}%)"

    print("\n" + "=" * 66)
    print("SUMMARY (attack acceptance, exact Clopper-Pearson 95% CI)")
    print("=" * 66)
    for r in rows:
        if r["genuine"]:
            print(f"  {r['name']:36s} accepted {fmt(r['full']['accepted'], n)}")
    print("\nFull verifier, attacks accepted:")
    for r in rows:
        if not r["genuine"]:
            print(f"  {r['name']:36s} {fmt(r['full']['accepted'], n)}   errors={r['full']['error']}")
    print("\nAblation, attacks accepted by 'hash+nonce' verifier (no signature check):")
    for r in rows:
        if not r["genuine"]:
            print(f"  {r['name']:36s} {fmt(r['hash+nonce']['accepted'], n)}")
    print("\nSET, attacks accepted:")
    for r in set_rows:
        if r["genuine"]:
            print(f"  {r['name']:36s} accepted {fmt(r['counts']['accepted'], n)}")
        else:
            print(f"  {r['name']:36s} {fmt(r['counts']['accepted'], n)}   errors={r['counts']['error']}")


if __name__ == "__main__":
    main()
