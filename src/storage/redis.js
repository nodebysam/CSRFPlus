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
 * Create a storage adapter backed by Redis.
 * The provided `redisClient` must support the standard `get`, `set`, and `del` commands (e.g., `node-redis` or `ioredis`).
 * This adapter is used by `CSRF Plus` to persist tokens across processes or servers in a distributed environment.
 * 
 * @param {Object} redisClient - A Redis client instance with `get(key)`, `set(key, value, ...args)`,
 *                               and `del(key)` methods.
 * @returns {object} An object implementing the CSRF Plus storage interface.
 */
const redisAdapter = (redisClient) => {
    return {
        async get(k) {
            const v = await redisClient.get(k);
            return v === null ? null : v;
        },
        async set(k, v, ttlSec) {
            if (ttlSec) await redisClient.set(k, v, 'EX', ttlSec);
            else await redisClient.set(k, v);
        },
        async del(k) { await redisClient.del(k); }
    };
};

module.exports = redisAdapter;