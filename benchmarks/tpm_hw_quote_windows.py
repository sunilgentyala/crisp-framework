"""
Hardware TPM 2.0 quote latency on Windows via TBS (tbs.dll), no external tools.

Creates a volatile restricted ECDSA P-256 signing key in the NULL hierarchy
(no owner/endorsement auth needed), then times TPM2_Quote over PCRs 0,1,7
(SHA-256 bank) with a fresh 32-byte qualifying nonce per trial.
"""
import ctypes, struct, time, secrets, statistics, sys, json
from ctypes import wintypes

tbs = ctypes.WinDLL("tbs.dll")

class TBS_CONTEXT_PARAMS2(ctypes.Structure):
    _fields_ = [("version", wintypes.UINT), ("flags", wintypes.UINT)]

TBS_CONTEXT_VERSION_TWO = 2
INCLUDE_TPM20 = 0x4  # includeTpm20 bit

ctx = ctypes.c_void_p()
params = TBS_CONTEXT_PARAMS2(TBS_CONTEXT_VERSION_TWO, INCLUDE_TPM20)
rc = tbs.Tbsi_Context_Create(ctypes.byref(params), ctypes.byref(ctx))
if rc != 0:
    print("Tbsi_Context_Create failed: 0x%08X" % (rc & 0xFFFFFFFF)); sys.exit(1)


def submit(cmd: bytes) -> bytes:
    out = ctypes.create_string_buffer(8192)
    out_len = wintypes.UINT(8192)
    rc = tbs.Tbsip_Submit_Command(ctx, 0, 200, cmd, len(cmd), out, ctypes.byref(out_len))
    if rc != 0:
        raise RuntimeError("Tbsip_Submit_Command failed: 0x%08X" % (rc & 0xFFFFFFFF))
    return out.raw[:out_len.value]


def rc_of(resp: bytes) -> int:
    return struct.unpack(">I", resp[6:10])[0]

TPM_ST_SESSIONS = 0x8002
TPM_CC_CreatePrimary = 0x00000131
TPM_CC_Quote = 0x00000158
TPM_CC_FlushContext = 0x00000165
TPM_RH_NULL = 0x40000007
TPM_RS_PW = 0x40000009

pw_auth = struct.pack(">IHBH", TPM_RS_PW, 0, 0, 0)       # handle, nonce size 0, attrs 0, hmac size 0
auth_area = struct.pack(">I", len(pw_auth)) + pw_auth

# TPMT_PUBLIC: ECC restricted signing key, ECDSA-SHA256, P-256
attrs = 0x00000002 | 0x00000010 | 0x00000020 | 0x00000040 | 0x00010000 | 0x00040000
tpmt_public = (struct.pack(">HHI", 0x0023, 0x000B, attrs) +
               struct.pack(">H", 0) +                    # authPolicy size 0
               struct.pack(">H", 0x0010) +               # symmetric: NULL
               struct.pack(">HH", 0x0018, 0x000B) +      # scheme: ECDSA, SHA256
               struct.pack(">HH", 0x0003, 0x0010) +      # curve P256, kdf NULL
               struct.pack(">HH", 0, 0))                 # unique x,y sizes 0
in_public = struct.pack(">H", len(tpmt_public)) + tpmt_public
in_sensitive = struct.pack(">H", 4) + struct.pack(">HH", 0, 0)
body = (struct.pack(">I", TPM_RH_NULL) + auth_area + in_sensitive + in_public +
        struct.pack(">H", 0) + struct.pack(">I", 0))
cmd = struct.pack(">HII", TPM_ST_SESSIONS, 10 + len(body), TPM_CC_CreatePrimary) + body
resp = submit(cmd)
if rc_of(resp) != 0:
    print("CreatePrimary rc=0x%08X" % rc_of(resp)); sys.exit(2)
key_handle = struct.unpack(">I", resp[10:14])[0]
print("key handle: 0x%08X" % key_handle)

pcr_sel = struct.pack(">IHB", 1, 0x000B, 3) + bytes([0x83, 0x00, 0x00])  # PCR 0,1,7
def quote_cmd(nonce: bytes) -> bytes:
    params = struct.pack(">H", len(nonce)) + nonce + struct.pack(">H", 0x0010) + pcr_sel
    body = struct.pack(">I", key_handle) + auth_area + params
    return struct.pack(">HII", TPM_ST_SESSIONS, 10 + len(body), TPM_CC_Quote) + body

N = int(sys.argv[1]) if len(sys.argv) > 1 else 100
# warm-up
for _ in range(5):
    r = submit(quote_cmd(secrets.token_bytes(32)))
    if rc_of(r) != 0:
        print("Quote rc=0x%08X" % rc_of(r)); sys.exit(3)
lat = []
for _ in range(N):
    q = quote_cmd(secrets.token_bytes(32))
    t0 = time.perf_counter()
    r = submit(q)
    lat.append((time.perf_counter() - t0) * 1000)
    assert rc_of(r) == 0
flush = struct.pack(">HIII", 0x8001, 14, TPM_CC_FlushContext, key_handle)
submit(flush)
lat.sort()
def pct(p): return lat[min(len(lat) - 1, int(round(p / 100 * (len(lat) - 1))))]
res = {"n": N, "min_ms": lat[0], "p50_ms": pct(50), "p95_ms": pct(95), "p99_ms": pct(99), "max_ms": lat[-1], "mean_ms": statistics.mean(lat)}
print(json.dumps({k: round(v, 2) if isinstance(v, float) else v for k, v in res.items()}))
tbs.Tbsip_Context_Close(ctx)
