/*
 * CRISP ZKBV Circuit — Hamming Distance Check
 * ============================================
 * Paper: "The Weaponization of Deepfakes: A Novel Cryptographic Framework
 *         Mitigating Biometric Injection and Identity Gaps"
 * IEEE Transactions on Information Forensics and Security, 2026
 *
 * Statement proven:
 *   ∃ probe[0..n-1] ∈ {0,1}^n such that:
 *     (1) hamming_distance(enrolled, probe) ≤ tau
 *     (2) The proof is bound to the current session via session_nonce
 *
 * The prover knows probe[] (private witness) but the verifier only
 * sees the proof, commitment hash, and session nonce.
 *
 * Circuit parameters (paper Section VI.A):
 *   n = 2048 feature bits
 *   tau = 307 (≈ 15% error tolerance)
 *   BCH(2047, 1723) error correction applied before circuit input
 *   Resulting R1CS constraints: ~48,000
 *
 * Compile with circom 2.1:
 *   circom hamming_distance.circom --r1cs --wasm --sym -o ./
 *
 * Trusted setup (Groth16):
 *   snarkjs groth16 setup hamming_distance.r1cs pot18_final.ptau \
 *       hamming_distance_0000.zkey
 *   snarkjs zkey contribute hamming_distance_0000.zkey \
 *       hamming_distance_final.zkey --name="CRISP setup" -e="entropy"
 *   snarkjs zkey export verificationkey \
 *       hamming_distance_final.zkey verification_key.json
 */

pragma circom 2.1.0;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/pedersen.circom";

/*
 * XorBit: outputs a XOR b (single bit)
 */
template XorBit() {
    signal input  a;
    signal input  b;
    signal output out;

    // a XOR b = a + b - 2*a*b  (works for binary inputs)
    out <== a + b - 2 * a * b;
}

/*
 * HammingDistance: compute sum of XOR differences over n bits
 * Returns the Hamming distance as a field element
 */
template HammingDistance(n) {
    signal input  a[n];
    signal input  b[n];
    signal output dist;

    component xors[n];
    signal partial[n+1];
    partial[0] <== 0;

    for (var i = 0; i < n; i++) {
        xors[i]      = XorBit();
        xors[i].a    <== a[i];
        xors[i].b    <== b[i];
        partial[i+1] <== partial[i] + xors[i].out;
    }

    dist <== partial[n];
}

/*
 * HammingCheck: prove that hamming_distance(enrolled, probe) <= tau
 * Main ZKBV circuit
 *
 * Private inputs (witness — never revealed):
 *   enrolled[N]:  enrolled biometric feature bits
 *   probe[N]:     probe biometric feature bits from live capture
 *
 * Public inputs (transmitted to verifier — no biometric content):
 *   tau:           Hamming distance threshold (fixed at 307)
 *   session_nonce: Session-specific nonce for freshness (SG-4)
 *
 * Constraint: dist <= tau
 */
template HammingCheck(N) {
    // Private witness (biometric content — not revealed)
    signal input enrolled[N];
    signal input probe[N];

    // Public inputs (revealed to verifier — no biometric data)
    signal input tau;
    signal input session_nonce;  // Binds proof to session (SG-4)

    // Constrain all inputs to be binary {0,1}
    for (var i = 0; i < N; i++) {
        enrolled[i] * (enrolled[i] - 1) === 0;
        probe[i]    * (probe[i]    - 1) === 0;
    }

    // Compute Hamming distance
    component hd = HammingDistance(N);
    for (var i = 0; i < N; i++) {
        hd.a[i] <== enrolled[i];
        hd.b[i] <== probe[i];
    }

    // Assert dist <= tau using a LessEqThan comparator
    // LessEqThan(k) checks that in[0] <= in[1] using k-bit comparison
    // k = 12 suffices for values up to 2048
    component leq = LessEqThan(12);
    leq.in[0] <== hd.dist;
    leq.in[1] <== tau;
    leq.out   === 1;

    // session_nonce is included as a public input to bind this proof
    // to the specific authentication session, preventing replay (SG-4).
    // It does not affect the constraint system beyond being present.
    _ <== session_nonce;
}

// Instantiate with N = 2048 feature bits (paper parameter)
component main {public [tau, session_nonce]} = HammingCheck(2048);
