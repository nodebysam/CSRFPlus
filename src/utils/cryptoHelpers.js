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

const crypto = require('crypto');

/**
 * Generates a cryptographically secure sequence of random bytes.
 * 
 * @param {number} n - Number of random bytes to generate. Must be a positive integer. 
 * @returns {Buffer} A `Buffer` containing `n` cryptographically secure random bytes.
 */
const randomBytes = (n) => { return crypto.randomBytes(n); }

/**
 * Compares two values in constant time to avoid timing attacks.
 * This prevents attackers from using subtle timing difference to guess valid CSRF tokens,
 * HMAC's, or other secrets.
 * 
 * @param {Buffer|string} a - First value to compare. 
 * @param {Buffer|string} b - Second value to comapre. 
 * @returns {boolean} `true` if both inputs are identical in length and content; otherwise `false`. 
 */
const safeEqual = (a, b) => {
    if (!Buffer.isBuffer(a)) a = Buffer.from(a);
    if (!Buffer.isBuffer(b)) b = Buffer.from(b);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
};

module.exports = { randomBytes, safeEqual };