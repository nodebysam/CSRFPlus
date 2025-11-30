/**
 * CSRF Plus
 * Next-level protection against forged requests
 * 
 * @author Sam Wilcox aka NodeBySam
 * @github https://github.com/nodebysam/CSRFPlus
 * 
 * CSRF Plus is released under the MIT license.
 * See the LICENSE file in the root of this
 * libary's path.
 */

const createMiddleware = require('./middleware');

/**
 * Create a new CSRF Plus.
 * 
 * @param {object} opts - User options for creating CSRF Plus. 
 * @returns {Function} The middleware.
 */
const createCsrfPlus = (opts) => {
    return createMiddleware(opts);
};

module.exports = { createCsrfPlus };