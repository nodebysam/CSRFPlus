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
 * Creates a lighweight, asynchronous, in-memory storage system for secrets, session-bound CSRF
 * values, or temporary tokens.
 * 
 * Values can optionally expire based on a TTL (in seconds).
 * 
 * @returns {object} A storage API with async `get()`, `set()`, and `del()` functions.
 */
const createMemoryStore = () => {
    const map = new Map();

    return {
        async get(k) {
            const e = map.get(k);
            if (!e) return null;
            if (e.exp && Date.now() > e.exp) { map.delete(k); return null; }
            return e.val;
        },
        async set(k, v, ttlSec) {
            const exp = ttlSec ? Date.now() + ttlSec * 1000 : null;
            map.set(k, { val: v, exp });
            if (ttlSec) setTimeout(() => map.delete(k), ttlSec * 1000 + 100);
        },
        async del(k) { map.delete(k); }
    };
};

module.exports = createMemoryStore;