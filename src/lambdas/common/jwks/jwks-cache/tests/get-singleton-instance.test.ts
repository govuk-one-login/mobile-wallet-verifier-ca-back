import { InMemoryJwksCache } from '../jwks-cache.ts';
import { describe, it, expect } from 'vitest';

describe('InMemoryJwksCache - getSingletonInstance', () => {
  it('Returns same instance on repeated calls', () => {
    const first = InMemoryJwksCache.getSingletonInstance();
    const second = InMemoryJwksCache.getSingletonInstance();
    expect(first).toBe(second);
  });
});
