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

const { encode, decode } = require('./utils/b64url');
const { randomBytes, safeEqual } = require('./utils/cryptoHelpers');
const createMemoryStore = require('./storage/memory');
const redisAdapter = require('./storage/redis');
const { makeMaskedToken, unmaskToken } = require('./token/mask');
const { createStatelessToken, verifySignedToken } = require('./token/stateless');

const DEFAULTS = {
    cookieName: 'CSRF_PLUS_TOKEN',
    cookieSidName: 'CSRF_PLUS_SID',
    headerName: 'x-csrf-plus',
    fieldName: '_csrf',
    store: createMemoryStore(),
    ttl: 60 * 60,
    secretLen: 32,
    mask: true,
    cookieOptions: { httpOnly: false, secure: true, sameSite: 'Lax', maxAge: 3600 * 1000, path: '/' },
    originCheck: true,
    allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
    stateless: false,
    statelessKey: null,
    statelessTTL: 60 * 60 * 1000,
};

/**
 * Factory that creates a CSRF Plus middleware bundle configured with the given options.
 * This method returns an object with:
 * `{ middleware, verify, adapters: { memory, redis } }`
 * 
 * @param {object} [userOpts={}] - Optional overrides for defaults.
 * @param {string} [userOpts.cookieName='CSRF_PLUS_TOKEN'] - Name of the token cookie (default is `CSRF_PLUS_TOKEN`).
 * @param {string} [userOpts.cookieSidName='CSRF_PLUS_SID'] - Name of the SID cookie used to tie browser -> stored secret (default is `CSRF_PLUS_SID`).
 * @param {string} [userOpts.headerName='x-csrf-plus'] - Header to check for XHR tokens (default is `x-csrf-plus`).
 * @param {string} [userOpts.fieldName='_csrf'] - Form body/query field name for form-submitted tokens (default is `_csrf`).
 * @param {Function} [userOpts.store=in-memory] - Storage adapter implementing `get`, `set, and `del` methods (default is `in-memory`).
 * @param {number} [userOpts.ttl=3600] - Seconds to keep server-stored secrets (default is `3600`).
 * @param {number} [userOpts.secretLen=32] - Secret length in bytes (default is `32`).
 * @param {boolean} [userOpts.mask=true] - Whether to use masked synchronizer tokens (recommended, default is `true`).
 * @param {object} [userOpts.cookieOptions] - Object passed to `req.cookie()` (secure, sameSite, etc).
 * @param {boolean} [userOpts.originCheck=true] - Whether to perform Origin/Referer defense-in-depth (default is `true`).
 * @param {string[]} [userOpts.allowedMethods=['GET', 'HEAD', 'OPTIONS']] - HTTP methods that skip verification (default is `['GET', 'HEAD', 'OPTIONS']`).
 * @param {boolean} [userOpts.stateless=false] - Set to `true` to use stateless HMAC tokens (no-server store).
 * @param {string|null} [userOpts.statelessKey=null] - Secret used to sign/verify stateless tokens (required if `userOpts.stateless=true`) (default is `null`).
 * @param {number} [userOpts.statelessTTL=60*60*1000] - TTL (ms) used when creating stateless tokens.
 * @returns {Promise<{ key: string, secret: Buffer } | null>} A promise that resolves to return `null` immediately if `stateless` mode is enabled.
 *                                                            Otherwise returns the key and secret buffer.
 * @throws {Error} If a store is not provided in stored mode or if stateless mode is chosen but no signing key is provided.
 */
const createMiddleware = (userOpts = {}) => {
    const opts = Object.assign({}, DEFAULTS, userOpts);
    if (!opts.stateless && (!opts.store || !opts.store.get)) throw new Error('store required when stateless=false.');
    if (opts.stateless && !opts.statelessKey) throw new Error('statelessKey required when stateless=true');

    /**
     * Internal helper used by `middleware` to obtain (or create) the server-side secret for the current client.
     * Returns `{ key, secret }` where `key` is the storage key and `secret` is a `Buffer`.
     * 
     * @param {http.IncomingMessage} req - `Express` request object. 
     * @param {http.ServerResponse} res - `Express` response object. 
     * @returns {Promise<{ key: string, secret: Buffer } | null>} A promise that resolves to return `null` immediately if `stateless` mode is enabled. 
     *                                                            Otherwise returns the key and secret buffer.
     */
    const getOrCreateSecret = async (req, res) => {
        if (opts.stateless) return null;
        let key = (req.session && req.session.id) || req.get('x-session-id') || null;

        if (!key) {
            key = req.cookies && req.cookies[opts.cookieSidName];

            if (!key) {
                key = encode(randomBytes(16));
                res.cookie(opts.cookieSidName, key, Object.assign({}, opts.cookieOptions, { httpOnly: false }));
            }
        }

        const stored = await opts.store.get(key);

        if (!stored) {
            const secret = randomBytes(opts.secretLen);
            await opts.store.set(key, encode(secret), opts.ttl);
            return { key, secret };
        }

        return {key, secret: decode(stored) };
    };

    /**
     * Express middlware that:
     *  - Attaches `req.csrfPlus` with helper `token()` and metadata.
     *  - Ensures a token cookie (`cookieName`) is set on responses for client-side XHR convenience.
     * 
     * This middleware should be mounted globally (e.g., `app.use(csrf.middleware)`) so requests have access
     * to the token and the cookie is present on pages.
     * 
     * @param {http.IncomingMessage} req - `Express` request object.     
     * @param {http.ServerResponse} res - `Express` response object. 
     * @param {Function} next - The next middleware to execute. 
     */
    const middleware = async (req, res, next) => {
        req.csrfPlus = {
            async token() {
                if (opts.stateless) return createStatelessToken(opts.statelessTTL, opts.statelessKey);
                const { secret } = await getOrCreateSecret(req, res);
                return opts.mask ? makeMaskedToken(secret) : encode(secret);
            },
            cookieName: opts.cookieName,
            fieldName: opts.fieldName,
            headerName: opts.headerName
        };

        try {
            const token = await req.csrfPlus.token();
            res.cookie(opts.cookieName, token, opts.cookieOptions);
        } catch (e) {
            if (process.env.NODE_ENV !== 'production') console.warn('CSRFPlus: token cookie is not set:', e && e.message);
        } finally { next(); }
    };

    /**
     * Express middleware to validate CSRF tokens on state-changing requests. Attach as route middleware for
     * protected endpoints.
     * 
     * @param {http.IncomingMessage} req - `Express` request object.     
     * @param {http.ServerResponse} res - `Express` response object. 
     * @param {Function} next - The next middleware to execute. 
     */
    const verify = async (req, res, next) => {
        try {
            if (opts.allowedMethods.includes(req.method)) return next();

            if (opts.originCheck) {
                const origin = req.get('origin');
                const referer = req.get('referer');
                const host = req.get('host');
                let ok = false;
                if (origin) { try { ok = new URL(origin).host === host } catch (e) { ok = false; } }
                else if (referer) { try { ok = new URL(referer).host === host; } catch (e) { ok = false; }  }
                if (!ok) return res.status(403).send('CSRF: origin/referrer mismatch.');
            }

            const token = (req.get(opts.headerName) || (req.body && req.body[opts.fieldName]) || (req.query && req.query[opts.fieldName]) || null);
            if (!token) return res.status(403).send('CSRF token missing.');

            if (opts.stateless) {
                const { ok, payload } = verifySignedToken(token, opts.statelessKey);
                if (!ok) return res.status(403).send('CSRF token invalid.');
                if (payload && payload.exp && Date.now() > payload.exp) return res.status(403).send('CSRF token expired.');
                return next();
            }

            const key = (req.session && req.session.id) || req.get('x-session-id') || (req.cookies && req.cookies[opts.cookieSidName]);
            if (!key) return res.status(403).send('CSRF session missing.');

            const storedB64 = await opts.store.get(key);
            if (!storedB64) return res.status(403).send('CSRF secret missing.');

            const secret = decode(storedB64);
            let provided;
            try { provided = opts.mask ? unmaskToken(token) : decode(token); } catch (e) { return res.status(403).send('CSRF token malformed.'); }
            if (provided.length !== secret.length) return res.status(403).send('CSRF token length mismatch.');
            if (!safeEqual(provided, secret)) return res.status(403).send('CSRF token mismatch.');
            return next();
        } catch (error) {
            console.error('CSRFPlus verify error:', error);
            return res.status(500).send('CSRF verification error.');
        }
    };

    return { middleware, verify, adapters: { memory: createMemoryStore, redis: redisAdapter } };
};

module.exports = createMiddleware;