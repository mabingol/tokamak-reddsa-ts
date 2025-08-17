import { poseidon2, poseidon4 } from 'poseidon-bls12381';
import { expect } from 'chai';

describe('Poseidon2 Implementation Comparison', () => {
    it('should produce the same hash for the same input', async function() {

        const input = [1n, 2n];

        const tsHash = poseidon2(input);
        console.log('TS Hash:', tsHash.toString());

    });
});
describe('Poseidon2 Implementation Comparison', () => {
    it('should produce the same hash for the same input', async function() {

        const input = [1n, 2n, 3n, 4n];

        const tsHash1 = poseidon2([input[0],input[1]]);
        const tsHash2 = poseidon2([input[2],input[3]]);
        const tsHash = poseidon2([tsHash1,tsHash2]);

        console.log('TS Hash:', tsHash.toString());

    });
});
describe('Poseidon2 Implementation Comparison', () => {
    it('should produce the same hash for the same input', async function() {

        const input = [1n, 2n, 3n, 4n];

        const tsHash = poseidon4(input);
        console.log('TS Hash:', tsHash.toString());

    });
});
