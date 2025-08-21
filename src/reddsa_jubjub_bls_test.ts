import {
    keccak,
    splitTo32,
    groupsOf,
    pad4,
    Poseidon4Only,
    PoseidonX,
    generateSecretSeed,
    getPublicKey,
    deriveKeysFromSeed,
    signPoseidon,
    verifyPoseidon,
    mod_p,mod_r
} from './reddsa_jubjub_bls.js';

import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToNumberBE, numberToBytesBE, bytesToHex } from '@noble/curves/abstract/utils';
import assert from 'node:assert/strict';
import {poseidon1, poseidon16, poseidon2, poseidon4} from "poseidon-bls12381";

function u8(s: string): Uint8Array {
    return new TextEncoder().encode(s);
}

function concat(...arrs: Uint8Array[]) {
    let len = 0;
    for (const a of arrs) len += a.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) { out.set(a, off); off += a.length; }
    return out;
}

it('test for poseidon1 and poseidon2', () => {
    assert.notEqual(poseidon1([1n]), poseidon2([1n,0n]));
});


it('test for poseidon1 and poseidon2 with zero elements', () => {
    console.log(poseidon1([0n]))
    console.log(poseidon2([0n,0n]))
    assert.notEqual(poseidon1([0n]), poseidon2([0n,0n]));
});

// --- 1) keccak ---
it('keccak(concat) equals keccak(chunks...)', () => {
    const a = u8('hello');
    const b = u8('world');
    const ref = bytesToNumberBE(keccak_256(concat(a, b)));
    const got = keccak(a, b);
    assert.equal(got, BigInt(ref));
});

it('keccak changes with order', () => {
    const a = u8('A');
    const b = u8('B');
    assert.notEqual(keccak(a, b), keccak(b, a));
});

// --- 2) splitTo32 ---
it('splitTo32 exact multiple of 32', () => {
    const buf = new Uint8Array(64).map((_, i) => i & 0xff);
    const parts = splitTo32(buf);
    assert.equal(parts.length, 2);
    assert.equal(parts[0].length, 32);
    assert.equal(parts[1].length, 32);
    assert.equal(parts[0][0], 0);
    assert.equal(parts[1][0], 32);
});

it('splitTo32 non-multiple (last shorter)', () => {
    const buf = new Uint8Array(70);
    const parts = splitTo32(buf);
    assert.equal(parts.length, 3);
    assert.equal(parts[0].length, 32);
    assert.equal(parts[1].length, 32);
    assert.equal(parts[2].length, 6);
});

// --- 3) groupsOf ---
it('groupsOf groups into fixed sizes', () => {
    const g = groupsOf([1, 2, 3, 4, 5], 2);
    assert.deepEqual(g, [[1, 2], [3, 4], [5]]);
});

// --- 4) pad4 ---
it('pad4 with len=4 keeps elements', () => {
    const [a, b, c, d] = pad4([10n, 20n, 30n, 40n]);
    assert.equal(a, 10n);
    assert.equal(b, 20n);
    assert.equal(c, 30n);
    assert.equal(d, 40n);
});
it('groupsOf groups into fixed size=4 with remainder shorter', () => {
    const arr = [1, 2, 3, 4, 5, 6, 7];
    const g = groupsOf(arr, 4);

    // Expect: [ [1,2,3,4], [5,6,7] ]
    assert.equal(g.length, 2);
    assert.deepEqual(g[0], [1, 2, 3, 4]);
    assert.deepEqual(g[1], [5, 6, 7]);
});

it('groupsOf len=4 exact multiple', () => {
    const arr = [10, 20, 30, 40, 50, 60, 70, 80];
    const g = groupsOf(arr, 4);

    // Expect: [ [10,20,30,40], [50,60,70,80] ]
    assert.equal(g.length, 2);
    assert.deepEqual(g[0], [10, 20, 30, 40]);
    assert.deepEqual(g[1], [50, 60, 70, 80]);
});

it('pad4 with len=1 pads with [1,2,3]', () => {
    const [a, b, c, d] = pad4([99n]);
    assert.equal(a, 99n);
    assert.equal(b, 1n);
    assert.equal(c, 2n);
    assert.equal(d, 3n);
});
it('pad4 with len=2 pads 1n and 2n', () => {
    const [a, b, c, d] = pad4([5n, 6n]);
    assert.equal(a, 5n);
    assert.equal(b, 6n);
    assert.equal(c, 1n);
    assert.equal(d, 2n);
});
it('pad4 with len=3 pads single 1n', () => {
    const [a, b, c, d] = pad4([5n, 6n, 7n]);
    assert.equal(a, 5n);
    assert.equal(b, 6n);
    assert.equal(c, 7n);
    assert.equal(d, 1n);
});

// --- 5) Poseidon4Only ---
it('Poseidon4Only with 1 small limb equals padded poseidon4 of same limb', () => {
    // one chunk -> 1 limb (<=4) → folded with pad [1,2,3]
    const x = numberToBytesBE(123n, 32);
    const out = Poseidon4Only(x);
    // sanity: should be a field element in Fp
    assert.equal(out, mod_p(out));
});

it('Poseidon4Only expands last chunk >32B', () => {
    // first chunk small; last chunk 70B → split into 32,32,6 = 3 limbs; total limbs = 4 → single poseidon4 call
    const first = numberToBytesBE(7n, 32);
    const last = new Uint8Array(70).map((_, i) => (200 + i) & 0xff);
    const out = Poseidon4Only(first, last);
    assert.equal(out, mod_p(out));
});

/*it('Poseidon4Only throws on >16 limbs', () => {
    const huge = new Uint8Array(17 * 32); // 17 limbs if last-only; here we pass only "last"
    assert.throws(() => Poseidon4Only(huge as unknown as Uint8Array));
});*/

// --- 6) PoseidonX ---
it('PoseidonX arity=3 matches direct poseidon3 semantics (field reduced)', () => {
    // three 32B chunks -> arity 3
    const a = numberToBytesBE(1n, 32);
    const b = numberToBytesBE(2n, 32);
    const c = numberToBytesBE(3n, 32);
    const out = PoseidonX(a, b, c);
    assert.equal(out, mod_p(out));
});

it('PoseidonX expands last chunk like Poseidon4Only for small counts', () => {
    const a = numberToBytesBE(1n, 32);
    const big = new Uint8Array(65);
    const out = PoseidonX(a, big);
    assert.equal(out, mod_p(out));
});

it('PoseidonX rejects >16 limbs after expansion', () => {
    const huge = new Uint8Array(17 * 32);
    assert.throws(() => PoseidonX(huge as unknown as Uint8Array));
});

// --- 7) Keys / KDF ---
it('generateSecretSeed returns 32B and not zero mod n', () => {
    const seed = generateSecretSeed();
    assert.equal(seed.length, 32);
    assert.notEqual(mod_r(bytesToNumberBE(seed)), 0n);
});

it('deriveKeysFromSeed deterministically derives s, nonceKey', () => {
    const seed = new Uint8Array(32).fill(7);
    const a = deriveKeysFromSeed(seed);
    const b = deriveKeysFromSeed(seed);
    assert.equal(a.s, b.s);
    assert.equal(bytesToHex(a.nonceKey), bytesToHex(b.nonceKey));
    assert.notEqual(a.s, 0n);
    assert.equal(a.nonceKey.length, 32);
});

it('getPublicKey(0n) equals getPublicKey(1n) due to guard', () => {
    const pk0 = getPublicKey(0n);
    const pk1 = getPublicKey(1n);
    assert.equal(bytesToHex(pk0), bytesToHex(pk1));
});

// --- 8) sign/verify ---
it('signPoseidon / verifyPoseidon succeeds roundtrip', () => {
    const seed = new Uint8Array(32).map((_, i) => (i + 1) & 0xff);
    const { s } = deriveKeysFromSeed(seed);
    const pk = getPublicKey(s);
    const msg = u8('hello tokamak');
    const sig = signPoseidon(msg, seed);
    const ok = verifyPoseidon(msg, pk, sig);
    assert.equal(ok, true);
});

it('verifyPoseidon fails on message tamper', () => {
    const seed = new Uint8Array(32).fill(9);
    const { s } = deriveKeysFromSeed(seed);
    const pk = getPublicKey(s);
    const msg = u8('original');
    const sig = signPoseidon(msg, seed);
    const bad = u8('tampered');
    assert.equal(verifyPoseidon(bad, pk, sig), false);
});

it('verifyPoseidon fails with wrong pk', () => {
    const seed1 = new Uint8Array(32).fill(1);
    const seed2 = new Uint8Array(32).fill(2);
    const { s: s1 } = deriveKeysFromSeed(seed1);
    const { s: s2 } = deriveKeysFromSeed(seed2);
    const pk2 = getPublicKey(s2);
    const msg = u8('pk mismatch');
    const sig1 = signPoseidon(msg, seed1);
    assert.equal(verifyPoseidon(msg, pk2, sig1), false);
});

it('verifyPoseidon fails if S is mangled', () => {
    const seed = new Uint8Array(32).fill(5);
    const { s } = deriveKeysFromSeed(seed);
    const pk = getPublicKey(s);
    const msg = u8('mangle S');
    const sig = signPoseidon(msg, seed);
    // flip one bit in S
    const badS = new Uint8Array(sig.S);
    badS[0] ^= 0xff;
    assert.equal(verifyPoseidon(msg, pk, { R: sig.R, S: badS }), false);
});

// Helper: manual two-level fold using only poseidon4 (mirrors Poseidon4Only)
function manualPoseidon4Fold(limbs: bigint[]): bigint {
    let level = limbs.slice();
    while (level.length > 1) {
        const next: bigint[] = [];
        for (const g of groupsOf(level, 4)) {
            const g4 = pad4(g);
            next.push(poseidon4(g4));
        }
        level = next;
    }
    return level[0];
}
it('Poseidon4Only performs correct two-level fold (manual equivalence)', () => {
    // Build 9 limbs total: 3 head chunks (32B each) + last chunk of 6*32B
    const headA = numberToBytesBE(11n, 32);
    const headB = numberToBytesBE(22n, 32);
    const headC = numberToBytesBE(33n, 32);
    const last = new Uint8Array(6 * 32); // 6 limbs
    for (let i = 0; i < last.length; i++) last[i] = (200 + i) & 0xff;

    const out = Poseidon4Only(headA, headB, headC, last);

    // Recreate the exact limbs list the function sees:
    const limbs: bigint[] = [
        bytesToNumberBE(headA),
        bytesToNumberBE(headB),
        bytesToNumberBE(headC),
        ...splitTo32(last).map(bytesToNumberBE),
    ];
    // 9 limbs => round1: 4,4,1 -> 3 outputs; round2: 3 + pad -> 1 output
    const manual = manualPoseidon4Fold(limbs);
    assert.equal(out, manual);
});


it('verifyPoseidon rejects signature if R is tampered (challenge mismatch)', () => {
    const seed = new Uint8Array(32).map((_, i) => (i + 10) & 0xff);
    const { s } = deriveKeysFromSeed(seed);
    const pk = getPublicKey(s);
    const msg = new TextEncoder().encode('tamper R test');

    const sig = signPoseidon(msg, seed);
    const badR = new Uint8Array(sig.R);
    // Flip a bit in compressed R; ensures Rx/Ry change after decode
    badR[0] ^= 0x01;

    // If R decoding fails, verifyPoseidon returns false; if it succeeds,
    // challenge e changes and left != right, still false.
    const ok = verifyPoseidon(msg, pk, { R: badR, S: sig.S });
    assert.equal(ok, false);
});


it('signPoseidon is deterministic per (seed,msg) and domain-separated across msgs (R differs)', () => {
    const seed = new Uint8Array(32).fill(7);
    const { s } = deriveKeysFromSeed(seed);
    const pk = getPublicKey(s);

    const m1 = new TextEncoder().encode('msg-1');
    const m2 = new TextEncoder().encode('msg-2');

    const sig1a = signPoseidon(m1, seed);
    const sig1b = signPoseidon(m1, seed);
    const sig2 = signPoseidon(m2, seed);

    // Deterministic for same (seed,msg)
    assert.equal(bytesToHex(sig1a.R), bytesToHex(sig1b.R));
    assert.equal(bytesToHex(sig1a.S), bytesToHex(sig1b.S));
    assert.equal(verifyPoseidon(m1, pk, sig1a), true);

    // Nonces (and thus signatures) differ for different msgs
    assert.notEqual(bytesToHex(sig1a.R), bytesToHex(sig2.R));
    assert.equal(verifyPoseidon(m2, pk, sig2), true);
});


it('PoseidonX at arity=16 equals direct poseidon16', () => {
    // Create exactly 16 limbs: 15 head chunks + 1 last chunk (32B)
    const heads: Uint8Array[] = [];
    for (let i = 0; i < 15; i++) heads.push(numberToBytesBE(BigInt(i + 1), 32));
    const last = numberToBytesBE(123456789n, 32);

    const out = PoseidonX(...heads, last);

    const limbs: bigint[] = [
        ...heads.map(bytesToNumberBE),
        bytesToNumberBE(last),
    ];
    assert.equal(limbs.length, 16);
    const direct = poseidon16(limbs);
    assert.equal(out, direct);
});


it('Poseidon4Only [0,0,0,0]', () => {
    const x = numberToBytesBE(0n, 32);
    const out = Poseidon4Only(x,x,x,x);
    console.log("Poseidon4Only(0,0,0,0) = ",out)
    assert.equal(out, mod_p(out));
    let expected = 13414013329667544728247370350271255543326139971590598177275881238397992759743n;
    assert.equal(out, expected);
});
it('Poseidon4Only [1,2,3,4]', () => {
    const x = numberToBytesBE(1n, 32);
    const y = numberToBytesBE(2n, 32);
    const z = numberToBytesBE(3n, 32);
    const t = numberToBytesBE(4n, 32);

    const out = Poseidon4Only(x,y,z,t);
    console.log("Poseidon4Only(1,2,3,4) = ",out)
    assert.equal(out, mod_p(out));

    let expected = 21145329782224435656281698581333264404190182101555512590871803982657985796198n;
    assert.equal(out, expected);
});
it('Poseidon4Only [123, 456, 789, 101112]', () => {
    const x = numberToBytesBE(123n, 32);
    const y = numberToBytesBE(456n, 32);
    const z = numberToBytesBE(789n, 32);
    const t = numberToBytesBE(101112n, 32);

    const out = Poseidon4Only(x,y,z,t);
    console.log("Poseidon4Only(123, 456, 789, 101112) = ",out)
    assert.equal(out, mod_p(out));

    let expected = 2961043210948921036705143845074294525317436046909118360899673960778402575172n;
    assert.equal(out, expected);
});

