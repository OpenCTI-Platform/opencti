import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return { ...actual, isFeatureEnabled: vi.fn(() => true) };
});

import { isFeatureEnabled } from '../../../src/config/conf';
import { resolvePasswordHistoryCount } from '../../../src/domain/setting-auth';

describe('resolvePasswordHistoryCount', () => {
  beforeEach(() => {
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
  });

  it('saves nothing when the field is not sent', () => {
    expect(resolvePasswordHistoryCount({})).toBeUndefined();
    expect(resolvePasswordHistoryCount({ password_policy_history_count: null })).toBeUndefined();
  });

  it('accepts integers from 0 to 24', () => {
    expect(resolvePasswordHistoryCount({ password_policy_history_count: 0 })).toBe(0);
    expect(resolvePasswordHistoryCount({ password_policy_history_count: 24 })).toBe(24);
  });

  it('refuses a value out of range or not an integer', () => {
    [-1, 25, 2.5].forEach((value) => {
      expect(() => resolvePasswordHistoryCount({ password_policy_history_count: value })).toThrow('between 0 and 24');
    });
  });

  it('ignores the 0 the hidden field sends when the feature flag is off', () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    expect(resolvePasswordHistoryCount({ password_policy_history_count: 0 })).toBeUndefined();
  });

  it('refuses any other value when the feature flag is off', () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    expect(() => resolvePasswordHistoryCount({ password_policy_history_count: 5 })).toThrow('not available');
  });
});
