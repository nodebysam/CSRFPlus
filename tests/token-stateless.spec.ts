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
const { signPayload, verifySignedToken, createStatelessToken } = require('../src/token/stateless');

describe('token/stateless', () => {
    const key = 'test-signing-key-12345';

    it('signPayload and verifySignedToken succeed for valid payload', () => {
        const payload = JSON.stringify({ foo: 'bar', iat: Date.now() });
        const token = signPayload(payload, key);
        const { ok, payload: decoded } = verifySignedToken(token, key);
        expect(ok).toBe(true);
        expect(decoded).toBeTruthy();
        expect(decoded.foo).toBe('bar');
    });

    it('verifySignedToken fails for tampered token', () => {
        const payload = JSON.stringify({ foo: 'bar', iat: Date.now() });
        const token = signPayload(payload, key);
        const tampered = token.slice(0, token.length - 1) + (token[token.length - 1] === 'A' ? 'B' : 'A');
        const { ok } = verifySignedToken(tampered, key);
        expect(ok).toBe(false);
    });

    it('createStatelessToken produces a token that decodes to an object with exp', () => {
        const token = createStatelessToken(1000, key);
        const { ok, payload } = verifySignedToken(token, key);
        expect(ok).toBe(true);
        expect(payload).toBeTruthy();
        expect(typeof payload.iat).toBe('number');
        expect(typeof payload.exp).toBe('number');
    });
});