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

const { encode, decode } = require('../utils/b64url');
const { safeEqual } = require('../utils/cryptoHelpers');
const crypto = require('crypto');

/**
 * Creates a signed stateless token by computing an HMAC over a JSON payload string.
 * 
 * @param {string} payloadStr - A UTF-8 JSON string representing the payload (e.g., `{"iat":..., "exp":... }`).
 * @param {Buffer|string} key - THe symmetric HMAC signing key. Must remain secret. 
 * @returns {string} A Base64-URL-encoded signed token.
 */
const signPayload = (payloadStr, key) => {
    const mac = crypto.createHmac('sha256', key).update(payloadStr).digest();
    return encode(Buffer.concat([Buffer.from(payloadStr, 'utf8'), Buffer.from('.'), mac]));
};

/**
 * Validates a signed stateless token created by `signPayload()` and returns its decoded payload if valid.
 * Performs `timing-safe` HMAC comparison to prevent side-channel leaks.
 * 
 * @param {string} tokenStr - Base64-URL-encoded signed token.
 * @param {Buffer|string} key - The secret key used to verify the HMAC. Must match the signing key. 
 * @returns {object} An object containing the result; `ok=true` if token is valid; otherwise `false`.
 *                   `payload` is the parsed JSON object or `null` on failure.
 */
const verifySignedToken = (tokenStr, key) => {
    try {
        const raw = decode(tokenStr);
        const dotIdx = raw.lastIndexOf(0x2E);
        if (dotIdx <= 0) return { ok: false, payload: null };
        const payloadBuf = raw.slice(0, dotIdx);
        const macBuf = raw.slice(dotIdx + 1);
        const payloadStr = payloadBuf.toString('utf8');
        const expected = crypto.createHmac('sha256', key).update(payloadStr).digest();
        if (macBuf.length !== expected.length) return { ok: false, payload: null };
        if (!safeEqual(macBuf, expected)) return { ok: false, payload: null };
        let payload;
        try { payload = JSON.parse(payloadStr); } catch (e) { payload = null; }
        return { ok: true, payload };
    } catch (e) {
        return { ok: false, payload: null };
    }
};

/**
 * Helper that constructs a signed stateless token containing:
 *  `iat` = issued-at timestamp.
 *  `exp` = expiration timestamp `(iat + ttlsMs)`.
 * 
 * @param {number} ttlMs - Time-to-live in milliseconds.
 * @param {Buffer|string} key - The secret signing key used for HMAC.
 * @returns {string} A Base64-URL-encoded HMAC-signed token.
 */
const createStatelessToken = (ttlMs, key) => {
    const iat = Date.now();
    const payload = JSON.stringify({ iat, exp: iat + ttlMs });
    return signPayload(payload, key);
};

module.exports = { signPayload, verifySignedToken, createStatelessToken };