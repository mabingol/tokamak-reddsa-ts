import {jubjub} from '@noble/curves/misc';
import {bls12_381} from '@noble/curves/bls12-381';
import {
    poseidon as poseidonFactory,
    validateOpts,
} from '@noble/curves/abstract/poseidon';
import {bytesToHex, numberToBytesBE, bytesToNumberBE} from '@noble/curves/abstract/utils';
import {webcrypto as crypto} from 'node:crypto';
import assert from 'node:assert/strict'; // not 'node:assert'

import {sha512} from "@noble/hashes/sha2";

import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname, join} from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const t4json: any = JSON.parse(
    readFileSync(join(__dirname, '../poseidon_consts_t4.json'), 'utf8')
);

// ---- Curve constants ----
const G = jubjub.Point.BASE;
const n: bigint = jubjub.Point.CURVE().n;
const DST_NONCE = new TextEncoder().encode("TokamakAuth-EDDSA-POSEIDON-NONCE-v1");
const DST_CHALLENGE = new TextEncoder().encode("TokamakAuth-EDDSA-POSEIDON-CHALLENGE-v1");

// Noble versions differ on where Fr lives; support both:
const Fr = (bls12_381 as any).Fr ?? (bls12_381 as any).fields?.Fr;
if (!Fr) throw new Error('Could not find bls12_381.Fr');

// ---- Poseidon(t=4) constants (BLS12-381 Fr) ----
// helpers to convert JSON hex -> bigint
// Make SURE these match your circuit parameters.
/*const baseOpts = {
    Fp: Fr,
    t: 4,
    roundsFull: 8,
    roundsPartial: 60,
    sboxPower: 5,
};
const { mds, roundConstants } = grainGenConstants(baseOpts);
const poseidonF4 = poseidonFactory(
    validateOpts({ ...baseOpts, mds, roundConstants })
);*/
const toBig = (h: string) => BigInt(h);
const map2DBig = (M: readonly (readonly string[])[]) => M.map((row) => row.map(toBig));

const poseidonF4 = poseidonFactory(
    validateOpts({
        Fp: Fr,
        t: t4json.t,                         // 4
        roundsFull: t4json.roundsFull,       // 8 (per your dump)
        roundsPartial: t4json.roundsPartial, // 60 (per your dump)
        sboxPower: t4json.sboxPower,    // 5
        mds: map2DBig(t4json.mds),
        roundConstants: map2DBig(t4json.roundConstants),
    })
);

// ---------- tiny bigint + poseidon utils ----------
const mod = (x: bigint) => ((x % n) + n) % n;
const add = (a: bigint, b: bigint) => mod(a + b);
const mul = (a: bigint, b: bigint) => mod(a * b);

// Poseidon(t=4) for nonce/challenge: H(PREFIX, X, Y, Z) -> Fr
function Hash4(...chunks: Uint8Array[]): bigint {
    const inputs = chunks.map((b) => bytesToNumberBE(b) % n);
    const state = poseidonF4(inputs); // bigint[]
    return state[0] % n;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
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
export function generateSecretSeed(): Uint8Array {
    const sk = new Uint8Array(32);
    crypto.getRandomValues(sk);
    // avoid s==0
    if (bytesToNumberBE(sk) % n === 0n) sk[0] ^= 1;
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

function deriveKeysFromSeed(skBytes: Uint8Array) {
    // 64-byte digest — replace with your preferred KDF
    const h = sha512(skBytes); // implement or import
    const s = mod(bytesToNumberBE(h.slice(0, 32)));
    if (s === 0n) throw new Error("invalid secret key");
    const nonceKey = h.slice(32, 64); // kept secret; not the same as pk
    return {s, nonceKey};
}

// ---- RedDSA-flavored sign/verify over Jubjub + Poseidon(t=4) ----
export function signPoseidon(msg: Uint8Array, skSeed: Uint8Array) {
    const {s, nonceKey} = deriveKeysFromSeed(skSeed);

    const A = G.multiply(s);
    const Abytes = A.toBytes();

    // Nonce r = H4(prefix, nonceKey, pk, msg)
    let r = Hash4(DST_NONCE, nonceKey, Abytes, msg);
    if (r === 0n) {
        // tweak deterministically
        r = Hash4(DST_NONCE, concat(nonceKey, new Uint8Array([1])), Abytes, msg);
        if (r === 0n) throw new Error("nonce derivation failed");
    }
    const R = G.multiply(r);
    const Rbytes = R.toBytes();

    // Challenge e = H4(prefix, R, A, msg)   (keep same arity/params as circuit)
    const e = Hash4(DST_CHALLENGE, Rbytes, Abytes, msg);

    const S = add(r, mul(e, s));
    const Sbytes = numberToBytesBE(S, 32);

    return {R: Rbytes, S: Sbytes};
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

        // Challenge e = H4(prefix, R, A, msg)
        const e = Hash4(DST_CHALLENGE, sig.R, pk, msg);

        const left = G.multiply(S);
        const right = R.add(A.multiply(e));
        return ctEq(left.toBytes(), right.toBytes())
    } catch {
        return false;
    }
}

// ---- Smoke test ----
for (let i = 0; i < 101; i++) {
    const skSeed = generateSecretSeed();
    let {s, nonceKey} = deriveKeysFromSeed(skSeed);
    const pk = getPublicKey(s);
    const msg = new TextEncoder().encode('Hello from TokamakAuth!');

    const sig = signPoseidon(msg, skSeed);
    const ok = verifyPoseidon(msg, pk, sig);
    assert.equal(ok, true);
    if (i == 100) {
        console.log('pk=', bytesToHex(pk));
        console.log('R=', bytesToHex(sig.R));
        console.log('S=', bytesToHex(sig.S));
    }
}



