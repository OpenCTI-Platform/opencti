import { describe, it, expect } from 'vitest';
import { findUsersThatCanShareWithOrganizations } from '../../../src/modules/requestAccess/requestAccess-domain';
import { ADMIN_USER, TEST_ORGANIZATION, testContext, USER_EDITOR } from '../../utils/testQuery';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';

describe('Request access domain level test coverage', async () => {
  it('should find users that can share knowledge with an org', async () => {
    const testOrgEntity = await getOrganizationEntity(TEST_ORGANIZATION);
    const result = await findUsersThatCanShareWithOrganizations(testContext, ADMIN_USER, [testOrgEntity.id]);
    expect(result[0].user_email).toBe(USER_EDITOR.email);
  });
});
