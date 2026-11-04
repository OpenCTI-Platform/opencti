import { describe, expect, it } from 'vitest';
import { buildDataRestrictions } from '../../../src/database/engine';
import { BYPASS } from '../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const testContext = {} as AuthContext;

const bypassUser = (opts: { serviceAccount: boolean }) => ({
  id: 'b6f4ee64-1d9c-4b7c-9a5e-3c2b1a0f9e8d',
  internal_id: 'b6f4ee64-1d9c-4b7c-9a5e-3c2b1a0f9e8d',
  capabilities: [{ name: BYPASS }],
  groups: [],
  organizations: [],
  roles: [],
  user_service_account: opts.serviceAccount,
}) as unknown as AuthUser;

describe('buildDataRestrictions authorized members filter', () => {
  it('should not send the authorized members filter for a service account', async () => {
    const restrictions = await buildDataRestrictions(testContext, bypassUser({ serviceAccount: true }));
    expect(restrictions).toEqual({ must: [], must_not: [] });
  });
  it('should keep the authorized members filter for a user that is not a service account', async () => {
    const restrictions = await buildDataRestrictions(testContext, bypassUser({ serviceAccount: false }));
    expect(restrictions.must).toHaveLength(1);
    expect(JSON.stringify(restrictions.must[0])).toContain('restricted_members');
    expect(restrictions.must_not).toEqual([]);
  });
});
