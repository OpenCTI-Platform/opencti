import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { initializeAdminUser } from '../../../src/config/providers-initialization';
import conf from '../../../src/config/conf';
import { SYSTEM_USER } from '../../../src/utils/access';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import { findById } from '../../../src/domain/user';
import type { AuthUser } from '../../../src/types/user';

describe('initializeAdminUser configurations verifications', () => {
  let initialEmail: string;
  let initialPassword: string;
  let initialToken: string;

  beforeAll(() => {
    initialEmail = conf.get('app:admin:email');
    initialPassword = conf.get('app:admin:password');
    initialToken = conf.get('app:admin:token');
  });

  afterAll(async () => {
    // reset to value that were set before running this test.
    conf.set('app:admin:email', initialEmail);
    conf.set('app:admin:password', initialPassword);
    conf.set('app:admin:token', initialToken);
    await initializeAdminUser({});
  });

  it('should well configured admin be initialized', async () => {
    // GIVEN configuration
    conf.set('app:admin:email', 'cecilia.payne@filigran.io');
    conf.set('app:admin:password', 'IDiscoveredUniverseMatter');
    conf.set('app:admin:token', 'aaaaaaaa-1111-2222-3333-999999999999');

    await initializeAdminUser({});

    const existingAdmin = await findById({}, SYSTEM_USER, OPENCTI_ADMIN_UUID) as AuthUser;
    expect(existingAdmin.user_email).toBe('cecilia.payne@filigran.io');
  });

  it('should password env with digit only works', async () => {
    // GIVEN configuration
    conf.set('app:admin:email', initialEmail);
    conf.set('app:admin:password', 1111); // ENV var with digit only is interpreted as number by node.
    conf.set('app:admin:token', initialToken);

    await initializeAdminUser({});
    // expect no exception, exception are failing tests so nothing to check more.
  });
});
