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

/**
 * Encode a string to base64.
 * 
 * @param {Buffer} buf - The buffer. 
 * @returns {string} The encoded string.
 */
const encode = (buf) => {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/**
 * Decode a string.
 * 
 * @param {string} str - The string to decode.
 * @returns {string} The decoded string.
 */
const decode = (str) => {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Buffer.from(str, 'base64');
};

module.exports = { encode, decode };