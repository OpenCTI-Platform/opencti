import { describe, expect, it } from 'vitest';
import { assertUserMergeAllowed, assertValidUserMergeIds, resolveUserMergeOptions } from '../../../../src/modules/userMerge/userMerge-domain';
import { UserMergeRightsStrategy } from '../../../../src/modules/userMerge/userMerge-types';
import { BYPASS, SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthUser } from '../../../../src/types/user';

const userWith = (capabilities: string[], id = 'user-under-test'): AuthUser => ({
  id,
  capabilities: capabilities.map((name) => ({ name })),
} as AuthUser);

describe('resolveUserMergeOptions', () => {
  it('should default to a dry-run so that a call without options never rewrites data', () => {
    expect(resolveUserMergeOptions().dryRun).toBe(true);
    expect(resolveUserMergeOptions(null).dryRun).toBe(true);
    expect(resolveUserMergeOptions({}).dryRun).toBe(true);
  });

  it('should default to the non-widening rights strategy', () => {
    expect(resolveUserMergeOptions().rightsStrategy).toBe(UserMergeRightsStrategy.Strict);
    expect(resolveUserMergeOptions({ rightsStrategy: null }).rightsStrategy).toBe(UserMergeRightsStrategy.Strict);
  });

  it('should keep the values provided by the caller', () => {
    const options = resolveUserMergeOptions({ dryRun: false, rightsStrategy: UserMergeRightsStrategy.Union });
    expect(options.dryRun).toBe(false);
    expect(options.rightsStrategy).toBe(UserMergeRightsStrategy.Union);
  });
});

describe('assertValidUserMergeIds', () => {
  it('should accept two distinct regular users', () => {
    expect(() => assertValidUserMergeIds('source-id', 'target-id')).not.toThrow();
  });

  it('should reject a merge of a user into itself', () => {
    expect(() => assertValidUserMergeIds('same-id', 'same-id')).toThrow('Cannot merge a user into itself');
  });

  it('should reject missing identifiers', () => {
    expect(() => assertValidUserMergeIds('', 'target-id')).toThrow('Source and target users are required to merge');
    expect(() => assertValidUserMergeIds('source-id', '')).toThrow('Source and target users are required to merge');
  });

  it('should reject internal platform users, as source or as target', () => {
    expect(() => assertValidUserMergeIds(SYSTEM_USER.id, 'target-id')).toThrow('Cannot merge an internal platform user');
    expect(() => assertValidUserMergeIds('source-id', SYSTEM_USER.id)).toThrow('Cannot merge an internal platform user');
  });
});

describe('assertUserMergeAllowed', () => {
  // The test configuration enables every dev feature, so the flag is on here and the
  // capability is what this suite exercises. The flag-off path is covered by the directive.
  it('should allow a user holding BYPASS', () => {
    expect(() => assertUserMergeAllowed(userWith([BYPASS]))).not.toThrow();
  });

  it('should reject a user without BYPASS loudly, never by returning early', () => {
    expect(() => assertUserMergeAllowed(userWith(['KNOWLEDGE']))).toThrow('Merging users requires the BYPASS capability');
  });

  it('should reject a user with no capability at all', () => {
    expect(() => assertUserMergeAllowed(userWith([]))).toThrow('Merging users requires the BYPASS capability');
  });
});
