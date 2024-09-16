import { describe, it, expect } from 'vitest';
import type { GraphQLError } from 'graphql/index';
import { checkFileAccess, SUPPORT_STORAGE_PATH } from '../../../src/modules/internal/document/document-domain';
import { ADMIN_USER, testContext, USER_PARTICIPATE, USER_PLATFORM_ADMIN } from '../../utils/testQuery';
import { findById } from '../../../src/domain/user';
import type { AuthUser } from '../../../src/types/user';

describe('checkFileAccess coverage', () => {
  it('should be allowed for any authenticated user to get an imported file', async () => {
    const myUser: AuthUser = await findById(testContext, ADMIN_USER, USER_PARTICIPATE.id);
    const opts: { entity_id?: string, filename: string, id: string } = { entity_id: 'fake-entityid', filename: 'file.json', id: 'export/report/file.json' };
    expect(await checkFileAccess(testContext, myUser, 'read', opts)).toBeTruthy();
  });

  it('should be forbidden for any authenticated user without SUPPORT capa to get an support file', async () => {
    const myUser: AuthUser = await findById(testContext, ADMIN_USER, USER_PARTICIPATE.id);
    const opts: { entity_id?: string, filename: string, id: string } = { entity_id: 'fake-entityid', filename: 'anyfile.zip', id: `${SUPPORT_STORAGE_PATH}/anyfile.zip` };

    let errorRaised = false;
    try {
      await checkFileAccess(testContext, myUser, 'read', opts);
    } catch (e) {
      const error = e as GraphQLError;
      expect(error.message, 'ForbiddenAccess should be raised').toBe('Access to this file is restricted');
      errorRaised = true;
    }
    expect(errorRaised, 'ForbiddenAccess should be raised').toBeTruthy();
  });

  it('should be allowed for user with SUPPORT capa to get an support file', async () => {
    const myUser: AuthUser = await findById(testContext, ADMIN_USER, USER_PLATFORM_ADMIN.id);
    const opts: { entity_id?: string, filename: string, id: string } = { entity_id: 'fake-entityid', filename: 'anyfile.zip', id: `${SUPPORT_STORAGE_PATH}/anyfile.zip` };

    expect(await checkFileAccess(testContext, myUser, 'read', opts)).toBeTruthy();
  });
});
