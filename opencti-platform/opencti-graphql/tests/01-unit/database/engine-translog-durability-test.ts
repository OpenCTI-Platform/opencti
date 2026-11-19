import { beforeEach, describe, expect, it, vi } from 'vitest';

// The enabled flags are read once, when the configuration module loads: the check itself is replaced
const { enabledFeatures } = vi.hoisted(() => ({ enabledFeatures: { flags: [] as string[] } }));
vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn((feature: string) => enabledFeatures.flags.includes(feature)),
}));

import { isFeatureEnabled } from '../../../src/config/conf';
import { getTranslogDurability, isTranslogAsyncEnabled } from '../../../src/database/engine-config';

describe('engine: translog durability of the platform indices', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    enabledFeatures.flags = [];
  });

  it('should keep the Elasticsearch default without the feature flag', () => {
    expect(isTranslogAsyncEnabled()).toBe(false);
    expect(getTranslogDurability()).toBe('request');
  });

  it('should ask for async with the feature flag', () => {
    enabledFeatures.flags = ['ES_TRANSLOG_ASYNC'];

    expect(isTranslogAsyncEnabled()).toBe(true);
    expect(getTranslogDurability()).toBe('async');
  });

  it('should read the ES_TRANSLOG_ASYNC flag only', () => {
    enabledFeatures.flags = ['ANOTHER_FEATURE'];

    expect(getTranslogDurability()).toBe('request');
    expect(isFeatureEnabled).toHaveBeenCalledWith('ES_TRANSLOG_ASYNC');
  });
});
