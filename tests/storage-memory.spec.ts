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
const createMemoryStore = require('../src/storage/memory');

describe('storage/memory', () => {
    it('set/get/del basic behavior', async () => {
        const store = createMemoryStore();
        await store.set('k1', 'v1', 0);
        expect(await store.get('k1')).toBe('v1');
        await store.del('k1');
        expect(await store.get('k1')).toBeNull();
    });

    it('ttl expiration removes keys', async () => {
        const store = createMemoryStore();
        await store.set('ttlkey', 'val', 1);
        expect(await store.get('ttlkey')).toBe('val');
        await new Promise((r) => setTimeout(r, 1100));
        expect(await store.get('ttlkey')).toBeNull();
    });
});