import { beforeEach, describe, expect, it, vi } from 'vitest';

// The enabled flags are read once, when the configuration module loads: the check itself is replaced
const { enabledFeatures } = vi.hoisted(() => ({ enabledFeatures: { flags: [] as string[] } }));
vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn((feature: string) => enabledFeatures.flags.includes(feature)),
}));

import { isFeatureEnabled } from '../../../src/config/conf';
import { getTranslogDurability, isTranslogRequestForced } from '../../../src/database/engine-config';

describe('engine: translog durability of the platform indices', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    enabledFeatures.flags = [];
  });

  it('should be asynchronous by default', () => {
    expect(isTranslogRequestForced()).toBe(false);
    expect(getTranslogDurability()).toBe('async');
  });

  it('should restore the Elasticsearch default with the opt-out flag', () => {
    enabledFeatures.flags = ['ES_TRANSLOG_REQUEST'];

    expect(isTranslogRequestForced()).toBe(true);
    expect(getTranslogDurability()).toBe('request');
  });

  it('should read the ES_TRANSLOG_REQUEST flag only', () => {
    enabledFeatures.flags = ['ANOTHER_FEATURE'];

    expect(getTranslogDurability()).toBe('async');
    expect(isFeatureEnabled).toHaveBeenCalledWith('ES_TRANSLOG_REQUEST');
  });
});
