import { describe, expect, it } from 'vitest';
import settingsResolvers from '../../../../src/resolvers/settings';
import userResolvers from '../../../../src/modules/user/user-resolver';

const resolveStatus = (settings: unknown) => (settingsResolvers.Settings.platform_bootstrap_status as (s: unknown) => unknown)(settings);

describe('Platform bootstrap status', () => {
  it('should be null when the attribute is absent (existing platform)', () => {
    expect(resolveStatus({})).toBeNull();
  });

  it('should expose pending and completed only', () => {
    expect(resolveStatus({ platform_bootstrap_status: 'pending' })).toEqual('pending');
    expect(resolveStatus({ platform_bootstrap_status: 'completed' })).toEqual('completed');
    expect(resolveStatus({ platform_bootstrap_status: 'skipped' })).toBeNull();
  });

  it('should have no default on MeUser.bootstrap_wizard_skipped', () => {
    expect((userResolvers.MeUser as Record<string, unknown>).bootstrap_wizard_skipped).toBeUndefined();
  });
});
