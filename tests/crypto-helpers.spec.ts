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

import { describe, it, expect } from "vitest";
const { randomBytes, safeEqual } = require('../src/utils/cryptoHelpers');

describe('crypto-helpers', () => {
    it('randomBytes returns a Buffer of requested length', () => {
        const b: Buffer = randomBytes(16);
        expect(Buffer.isBuffer(b)).toBe(true);
        expect(b.length).toBe(16);
    });

    it ('safeEqual returns true for equal buffers and false for different', () => {
        const a = Buffer.from('abcd');
        const b = Buffer.from('abcd');
        const c = Buffer.from('abce');
        expect(safeEqual(a, b)).toBe(true);
        expect(safeEqual(a, c)).toBe(false);
    });

    it ('safeEqual accepts strings and buffers', () => {
        expect(safeEqual('hello', Buffer.from('hello'))).toBe(true);
        expect(safeEqual('hello', 'world')).toBe(false);
    });
});