import { describe, expect, it } from 'vitest';
import { addOrganization } from '../../../src/modules/organization/organization-domain';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { addSector } from '../../../src/domain/sector';
import type { UserAddInput } from '../../../src/generated/graphql';
import type { AuthUser } from '../../../src/types/user';
import { addUser, findById as findUserById, userAddRelation, userDelete } from '../../../src/domain/user';
import { RELATION_PARTICIPATE_TO } from '../../../src/schema/internalRelationship';
import type { BasicStoreEntity } from '../../../src/types/store';
import { deleteElementById } from '../../../src/database/middleware';
import { ENTITY_TYPE_IDENTITY_SECTOR } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';

describe('Testing buildCompleteUser', () => {
  it('should user organization list be composed of organizations entity only', async () => {
    const testOrgCustom = await addOrganization(testContext, ADMIN_USER, { name: 'CompleteUserOrg' });
    const testSector = await addSector(testContext, ADMIN_USER, { name: 'CompleteUserSector' });

    const userInput: UserAddInput = {
      name: `User for buildCompleteUser ${Date.now()}`,
      password: 'buildCompleteUser',
      user_email: 'user.buildCompleteUser@opencti.invalid',
      objectOrganization: [testOrgCustom.id],
    };
    const userInOrgCustom: AuthUser = await addUser(testContext, ADMIN_USER, userInput);
    const wrongRelationInput = { relationship_type: RELATION_PARTICIPATE_TO, toId: testSector.id };
    await userAddRelation(testContext, ADMIN_USER, userInOrgCustom.id, wrongRelationInput);
    const userAuth = await findUserById(testContext, ADMIN_USER, userInOrgCustom.id);
    expect(userAuth.organizations.filter((org: BasicStoreEntity) => org.id === testOrgCustom.id).length).toBe(1); // Actual Organization
    expect(userAuth.organizations.filter((org: BasicStoreEntity) => org.id === testSector.id).length).toBe(0); // Sector should not be there
    expect(userAuth.organizations.length).toBe(1);

    // Cleanup
    await userDelete(testContext, ADMIN_USER, userInOrgCustom.id);
    await deleteElementById(testContext, ADMIN_USER, testOrgCustom.id, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    await deleteElementById(testContext, ADMIN_USER, testSector.id, ENTITY_TYPE_IDENTITY_SECTOR);
  });
});
