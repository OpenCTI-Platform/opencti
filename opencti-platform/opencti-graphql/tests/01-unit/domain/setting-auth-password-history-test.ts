import { describe, expect, it } from 'vitest';
import { resolvePasswordHistoryCount } from '../../../src/domain/setting-auth';

describe('resolvePasswordHistoryCount', () => {
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
});
