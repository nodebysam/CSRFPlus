/**
 * CSRF Plus
 * Next-level protection against forged requests
 * 
 * @author Sam Wilcox aka NodeBySam
 * @github https://github.com/nodebysam/CSRFPlus
 * 
 * CSRF Plus is released under the MIT license.
 * See the LICENSE file in the root of this
 * library's path.
 */

import { describe, it, expect } from 'vitest';
const { makeMaskedToken, unmaskToken } = require('../src/token/mask');
const { randomBytes, safeEqual } = require('../src/utils/cryptoHelpers');

describe('token/mask', () => {
    it ('makeMaskedToken + unmaskToken roundtrip returns original secret', () => {
        const secret = randomBytes(32);
        const token = makeMaskedToken(secret);
        const recovered = unmaskToken(token);
        expect(Buffer.isBuffer(recovered)).toBe(true);
        expect(recovered.length).toBe(secret.length);
        expect(safeEqual(recovered, secret)).toBe(true);
    });

    it('tampered masked token will not match original secret', () => {
        const secret = randomBytes(32);
        const token = makeMaskedToken(secret);
        const tampered = token.slice(0, token.length - 1) + (token[token.length - 1] === 'A' ? 'B' : 'A');

        try {
            const recovered = unmaskToken(tampered);
            expect(safeEqual(recovered, secret)).toBe(false);
        } catch (e) {
            expect(e).toBeTruthy();
        }
    });

    it('unmaskToken throws on invalid input length', () => {
        expect(() => unmaskToken('AA')).toThrow();
    });
});