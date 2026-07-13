import { describe, expect, it } from 'vitest';
import { CACHE_RESET_TOPIC } from '../../../src/database/redis';
import { TOPIC_PREFIX } from '../../../src/config/conf';

describe('Redis cache reset topic', () => {
  it('CACHE_RESET_TOPIC should be derived from TOPIC_PREFIX', () => {
    expect(CACHE_RESET_TOPIC).toBe(`${TOPIC_PREFIX}CACHE_RESET_TOPIC`);
  });

  it('CACHE_RESET_TOPIC should end with CACHE_RESET_TOPIC', () => {
    expect(CACHE_RESET_TOPIC.endsWith('CACHE_RESET_TOPIC')).toBe(true);
  });
});
