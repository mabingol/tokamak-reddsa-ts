// src/dump_poseidon_consts.ts
import { bls12_381 } from '@noble/curves/bls12-381';
import { grainGenConstants, validateOpts } from '@noble/curves/abstract/poseidon';
import fs from 'node:fs';

const Fr = (bls12_381 as any).Fr ?? (bls12_381 as any).fields?.Fr;
if (!Fr) throw new Error('Could not find bls12_381.Fr');

const hex32 = (x: bigint) => '0x' + x.toString(16).padStart(64, '0');
const map2DHex = (M: readonly (readonly bigint[])[]) => M.map(r => r.map(hex32));

function dumpPoseidonConstants(params: { t: number; roundsFull: number; roundsPartial: number; sboxPower?: number }) {
    const { t, roundsFull, roundsPartial, sboxPower = 5 } = params;

    const gen = grainGenConstants({ Fp: Fr, t, roundsFull, roundsPartial, sboxPower });
    const constants = validateOpts({ Fp: Fr, t, roundsFull, roundsPartial, sboxPower, mds: gen.mds, roundConstants: gen.roundConstants });

    const rcRows = constants.roundConstants.length;
    const rcWidth = constants.roundConstants[0]?.length ?? 0;

    if (constants.mds.length !== t || constants.mds.some(r => r.length !== t)) {
        throw new Error(`MDS must be ${t}x${t}`);
    }
    if (rcWidth !== t) {
        throw new Error(`roundConstants rows must each be length ${t}, got ${rcWidth}`);
    }

    console.log(`Derived: t=${constants.t}, full=${constants.roundsFull}, partial=${constants.roundsPartial}, RC rows=${rcRows}`);

    return {
        field: 'bls12-381.field.Fr',
        t: constants.t,
        roundsFull: constants.roundsFull,
        roundsPartial: constants.roundsPartial,
        sboxPower,
        mds: map2DHex(constants.mds),
        roundConstants: map2DHex(constants.roundConstants),
    };
}

const T4 = dumpPoseidonConstants({ t: 4, roundsFull: 8, roundsPartial: 60, sboxPower: 5 });
fs.writeFileSync('poseidon_consts_t4.json', JSON.stringify(T4, null, 2));
console.log('Wrote poseidon_consts_t4.json');
