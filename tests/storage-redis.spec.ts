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

import { describe, it, expect, vi } from 'vitest';
const redisAdapter = require('../src/storage/redis');

describe('storage/redis adapter (mocked client)', () => {
    it ('set/get/del works via adapter (mock client)', async () => {
        const mockMap = new Map<string, any>();

        const client = {
            get: vi.fn(async (k: string) => {
                const e = mockMap.get(k);
                if (!e) return null;
                if (e.exp && Date.now() > e.exp) { mockMap.delete(k); return null; }
                return e.val;
            }),
            set: vi.fn(async (k: string, v: any, ...args: any[]) => {
                if (args.length === 2 && args[0] === 'EX') {
                    const ttl = args[1];
                    mockMap.set(k, { val: v, exp: Date.now() + ttl * 1000 });
                } else {
                    if (args.length === 0) mockMap.set(k, { val: v, exp: null });
                    else if (args.length === 2 && args[0] === 'EX') {
                        const ttl = args[1];
                        mockMap.set(k, { val: v, exp: Date.now() + ttl * 1000 });
                    } else mockMap.set(k, { val: v, exp: null });
                }
            }),
            del: vi.fn(async (k: string) => { mockMap.delete(k); })
        };

        const adapter = redisAdapter(client);
        await adapter.set('r1', 'abc', 0);
        expect(await adapter.get('r1')).toBe('abc');
        await adapter.del('r1');
        expect(await adapter.get('r1')).toBeNull();

        // Check TTL
        await adapter.set('rttl', 'x', 1);
        expect (await adapter.get('rttl')).toBe('x');
        await new Promise((r) => setTimeout(r, 1100));
        expect(await adapter.get('rttl')).toBeNull();
    });
});