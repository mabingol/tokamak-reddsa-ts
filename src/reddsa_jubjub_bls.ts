import {jubjub} from '@noble/curves/misc';
import {bytesToHex, numberToBytesBE, bytesToNumberBE} from '@noble/curves/abstract/utils';
import {webcrypto as crypto} from 'node:crypto';
import assert from 'node:assert/strict';
import {keccak_256} from '@noble/hashes/sha3';

import {sha512} from "@noble/hashes/sha2";

import {
    poseidon1, poseidon2, poseidon3, poseidon4, poseidon5,
    poseidon6, poseidon7, poseidon8, poseidon9, poseidon10,
    poseidon11, poseidon12, poseidon13, poseidon14, poseidon15, poseidon16
} from "poseidon-bls12381";

const POSEIDON_BY_ARITY: Record<number, (xs: bigint[]) => bigint> = {
    1: poseidon1,
    2: poseidon2,
    3: poseidon3,
    4: poseidon4,
    5: poseidon5,
    6: poseidon6,
    7: poseidon7,
    8: poseidon8,
    9: poseidon9,
    10: poseidon10,
    11: poseidon11,
    12: poseidon12,
    13: poseidon13,
    14: poseidon14,
    15: poseidon15,
    16: poseidon16,
};
// ---- Curve constants ----
const G = jubjub.Point.BASE;
//curve modulo F_p
const p: bigint = jubjub.Point.CURVE().p;
//curve subgroup order
const n: bigint = jubjub.Point.CURVE().n;
//prefix
const DST_NONCE = new TextEncoder().encode("TokamakAuth-EDDSA-NONCE-v1");


// ---------- tiny bigint + poseidon utils ----------
export const mod_p = (x: bigint) => ((x % p) + p) % p;
export const mod_r = (x: bigint) => ((x % n) + n) % n;
export const add = (a: bigint, b: bigint) => mod_r(a + b);
export const mul = (a: bigint, b: bigint) => mod_r(a * b);

// keccak for nonce/challenge: H(PREFIX, X, Y, Z) -> Fr
export function keccak(...chunks: Uint8Array[]): bigint {
    const hash = keccak_256.create();// 32 bytes
    for (const c of chunks) {
        hash.update(c);
    }
    return bytesToNumberBE(hash.digest());
}

// Split a byte array into 32-byte chunks (no padding; last limb may be <32B)
export  function splitTo32(b: Uint8Array): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (let i = 0; i < b.length; i += 32) out.push(b.subarray(i, i + 32));
    // If you prefer zero-padding the last limb to 32B, do it here instead.
    return out;
}
// Group an array into chunks of at most 'size'
export function groupsOf<T>(arr: T[], size: number): T[][] {
    const out: T[][] = [];
    for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
    return out;
}

// Pad to exactly 4 field elements with constants 1,2,3 (mod_r n)
export function pad4(xs: bigint[]): [bigint, bigint, bigint, bigint] {
    if (xs.length === 4) return [xs[0], xs[1], xs[2], xs[3]];
    const PADS = [1n, 2n, 3n];
    const out = xs.slice();
    while (out.length < 4) out.push(PADS[out.length - xs.length]);
    return [out[0], out[1], out[2], out[3]];
}

export function Poseidon4Only(...chunks: Uint8Array[]): bigint {
    if (chunks.length < 1) throw new Error(`need at least 1 chunk`);

    // Expand last chunk into 32-byte limbs
    const last = chunks[chunks.length - 1];
    const head = chunks.slice(0, -1);
    const expandedLast = splitTo32(last);

    // Build field inputs
    const limbs: bigint[] = [
        ...head.map((b) => mod_p(bytesToNumberBE(b))),
        ...expandedLast.map((b) => mod_p(bytesToNumberBE(b))),
    ];
    if (limbs.length === 0) throw new Error("no inputs after expansion");

    // Optional guard if you truly never expect >16
    /*if (limbs.length > 16) {
        throw new Error(`too many limbs (${limbs.length}); expected <= 16`);
    }*/

    // Reduce by poseidon4 on groups of 4, padding with [1,2,3]
    let level: bigint[] = limbs;
    while (level.length > 1) {
        const groups = groupsOf(level, 4);
        const next: bigint[] = [];
        for (const g of groups) {
            const g4 = pad4(g);
            const out = poseidon4(g4); // returns bigint
            next.push(out);
        }
        level = next;
    }
    return level[0];
}

// PoseidonX where (X=1..16) -> Fr
export function PoseidonX(...chunks: Uint8Array[]): bigint {
    if (chunks.length < 1) throw new Error("need at least 1 chunk");

    // Expand last chunk
    const last = chunks[chunks.length - 1];
    const head = chunks.slice(0, -1);
    const expandedLast = splitTo32(last);

    // Build input limbs (as Fr)
    const limbs: bigint[] = [
        ...head.map((b) => mod_p(bytesToNumberBE(b))),
        ...expandedLast.map((b) => mod_p(bytesToNumberBE(b))),
    ];

    const total = limbs.length;
    if (total < 1) throw new Error("no inputs after expansion");
    if (total > 16) {
        throw new Error("there are more than 16 limbs after expansion");
    }
    console.log("Poseidon%d is called", total);
    const f = POSEIDON_BY_ARITY[total];
    if (!f) throw new Error(`Poseidon arity ${total} not available`);
    return f(limbs);
}

// ---- Keys ----
export function generateSecretSeed(): Uint8Array {
    const sk = new Uint8Array(32);
    crypto.getRandomValues(sk);
    // avoid s==0
    if ( mod_r(bytesToNumberBE(sk)) === 0n) sk[0] ^= 1;
    return sk;
}

export function getPublicKey(s: bigint): Uint8Array {
    if (s === 0n) s = 1n;
    const A = G.multiply(s);
    return A.toBytes(); // compressed
}

function ctEq(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let v = 0;
    for (let i = 0; i < a.length; i++) v |= a[i] ^ b[i];
    return v === 0;
}

export function deriveKeysFromSeed(skBytes: Uint8Array) {
    // 64-byte digest — replace with your preferred KDF
    const h = sha512(skBytes); // implement or import
    const s = mod_r(bytesToNumberBE(h.slice(0, 32)));
    if (s === 0n) throw new Error("invalid secret key");
    const nonceKey = h.slice(32, 64); // kept secret; not the same as pk
    return {s, nonceKey};
}

// ---- RedDSA-flavored sign/verify over Jubjub + Poseidon(t=5) ----
export function signPoseidon(msg: Uint8Array, skSeed: Uint8Array) {
    const {s, nonceKey} = deriveKeysFromSeed(skSeed);

    const A = G.multiply(s);
    const Axbytes = numberToBytesBE(A.x, 32);
    const Aybytes = numberToBytesBE(A.y, 32);

    // Nonce r = keccak(prefix, nonceKey, pk, msg)
    let r = mod_r(keccak(DST_NONCE, nonceKey, Axbytes, Aybytes, msg));
    const R = G.multiply(r);

    const Rxbytes = numberToBytesBE(R.x, 32);
    const Rybytes = numberToBytesBE(R.y, 32);

    // Challenge e = H5(Rx,Ry,Ax,Ay, msg)   (keep same arity/params as circuit)
    const e = mod_r(Poseidon4Only(Rxbytes, Rybytes, Axbytes, Aybytes, msg));

    const S = add(r, mul(e, s));
    const Sbytes = numberToBytesBE(S, 32);

    return {R: R.toBytes(), S: Sbytes};
}

export function verifyPoseidon(
    msg: Uint8Array,
    pk: Uint8Array,
    sig: { R: Uint8Array; S: Uint8Array }
): boolean {
    try {
        const R = jubjub.Point.fromHex(bytesToHex(sig.R));
        if (R.is0()) return false;

        const A = jubjub.Point.fromHex(bytesToHex(pk));
        if (A.is0() || A.isSmallOrder() || !A.isTorsionFree?.()) return false; // or [n]A==0

        // parse S
        let S = bytesToNumberBE(sig.S)

        let Rxbytes = numberToBytesBE(R.x, 32);
        let Rybytes = numberToBytesBE(R.y, 32);

        let Axbytes = numberToBytesBE(A.x, 32);
        let Aybytes = numberToBytesBE(A.y, 32);

        // Challenge e = H5(Rx,Ry,Ax,Ay, msg)   (keep same arity/params as circuit)
        const e = mod_r(Poseidon4Only(Rxbytes, Rybytes, Axbytes, Aybytes, msg));

        const left = G.multiply(S);
        const right = R.add(A.multiply(e));
        return ctEq(left.toBytes(), right.toBytes())
    } catch {
        return false;
    }
}

console.log("F_p=0x%s",p.toString(16));
console.log("F_r=0x%s",n.toString(16));

// ---- Smoke test ----
const skSeed = generateSecretSeed();
let {s, nonceKey} = deriveKeysFromSeed(skSeed);
const pk = getPublicKey(s);
const msg = new TextEncoder().encode('Hello from TokamakAuth! Hello from TokamakAuth! Hello from TokamakAuth! Hello from TokamakAuth!');

const sig = signPoseidon(msg, skSeed);
const ok = verifyPoseidon(msg, pk, sig);
assert.equal(ok, true);
console.log('pk=', bytesToHex(pk));
console.log('R=', bytesToHex(sig.R));
console.log('S=', bytesToHex(sig.S));





