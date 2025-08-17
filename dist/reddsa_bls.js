import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToHex, numberToBytesBE, bytesToNumberBE } from '@noble/curves/abstract/utils';
import { webcrypto as crypto } from 'node:crypto';
import assert from 'node:assert';
import { sha512 } from "@noble/hashes/sha2";
import { poseidon4 } from "poseidon-bls12381";
// ---- Curve constants ----
const G = bls12_381.G1.ProjectivePoint.BASE;
const n = bls12_381.G1.Point.CURVE().n;
const DST_NONCE = new TextEncoder().encode("TokamakAuth-EDDSA-POSEIDON-NONCE-v1");
const DST_CHALLENGE = new TextEncoder().encode("TokamakAuth-EDDSA-POSEIDON-CHALLENGE-v1");
// ---------- tiny bigint + poseidon utils ----------
const mod = (x) => ((x % n) + n) % n;
const add = (a, b) => mod(a + b);
const mul = (a, b) => mod(a * b);
// Poseidon(t=4) for nonce/challenge: H(PREFIX, X, Y, Z) -> Fr
function Hash4(...chunks) {
    const inputs = chunks.map((b) => bytesToNumberBE(b) % n);
    const state = poseidon4(inputs); // bigint[]
    return state % n;
}
function concat(...arrays) {
    const len = arrays.reduce((sum, a) => sum + a.length, 0);
    const out = new Uint8Array(len);
    let offset = 0;
    for (const arr of arrays) {
        out.set(arr, offset);
        offset += arr.length;
    }
    return out;
}
// ---- Keys ----
export function generateSecretSeed() {
    const sk = new Uint8Array(32);
    crypto.getRandomValues(sk);
    // avoid s==0
    if (bytesToNumberBE(sk) % n === 0n)
        sk[0] ^= 1;
    return sk;
}
export function getPublicKey(s) {
    if (s === 0n)
        s = 1n;
    const A = G.multiply(s);
    return A.toBytes(); // compressed
}
function ctEq(a, b) {
    if (a.length !== b.length)
        return false;
    let v = 0;
    for (let i = 0; i < a.length; i++)
        v |= a[i] ^ b[i];
    return v === 0;
}
function deriveKeysFromSeed(skBytes) {
    // 64-byte digest — replace with your preferred KDF
    const h = sha512(skBytes); // implement or import
    const s = mod(bytesToNumberBE(h.slice(0, 32)));
    if (s === 0n)
        throw new Error("invalid secret key");
    const nonceKey = h.slice(32, 64); // kept secret; not the same as pk
    return { s, nonceKey };
}
// ---- RedDSA-flavored sign/verify over Jubjub + Poseidon(t=4) ----
export function signPoseidon(msg, skSeed) {
    const { s, nonceKey } = deriveKeysFromSeed(skSeed);
    const A = G.multiply(s);
    const Abytes = A.toBytes();
    // Nonce r = H4(prefix, nonceKey, pk, msg)
    let r = Hash4(DST_NONCE, nonceKey, Abytes, msg);
    if (r === 0n) {
        // tweak deterministically
        r = Hash4(DST_NONCE, concat(nonceKey, new Uint8Array([1])), Abytes, msg);
        if (r === 0n)
            throw new Error("nonce derivation failed");
    }
    const R = G.multiply(r);
    const Rbytes = R.toBytes();
    // Challenge e = H4(prefix, R, A, msg)   (keep same arity/params as circuit)
    const e = Hash4(DST_CHALLENGE, Rbytes, Abytes, msg);
    const S = add(r, mul(e, s));
    const Sbytes = numberToBytesBE(S, 32);
    return { R: Rbytes, S: Sbytes };
}
export function verifyPoseidon(msg, pk, sig) {
    try {
        const R = bls12_381.G1.Point.fromHex(bytesToHex(sig.R));
        if (R.is0())
            return false;
        const A = bls12_381.G1.Point.fromHex(bytesToHex(pk));
        if (A.is0() || A.isSmallOrder() || !A.isTorsionFree?.())
            return false; // or [n]A==0
        // parse S
        let S = bytesToNumberBE(sig.S);
        // Challenge e = H4(prefix, R, A, msg)
        const e = Hash4(DST_CHALLENGE, sig.R, pk, msg);
        const left = G.multiply(S);
        const right = R.add(A.multiply(e));
        return ctEq(left.toBytes(), right.toBytes());
    }
    catch {
        return false;
    }
}
console.log("x", G.x.toString(16));
console.log("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n");
console.log("0x%sn", n.toString(16));
console.log(n.toString(10));
// ---- Smoke test ----
for (let i = 0; i < 1001; i++) {
    const skSeed = generateSecretSeed();
    let { s, nonceKey } = deriveKeysFromSeed(skSeed);
    const pk = getPublicKey(s);
    const msg = new TextEncoder().encode('Hello from TokamakAuth!');
    const sig = signPoseidon(msg, skSeed);
    const ok = verifyPoseidon(msg, pk, sig);
    assert.equal(ok, true);
    if (i == 1000) {
        console.log('pk=', bytesToHex(pk));
        console.log('R=', bytesToHex(sig.R));
        console.log('S=', bytesToHex(sig.S));
    }
}
