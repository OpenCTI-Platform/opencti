import { v4 as uuid } from 'uuid';
import { ADMIN_USER, type GroupTestData, type OrganizationTestData, testContext } from './testQuery';
import type { StoreEntityConnection } from '../../src/types/store';
import type { BasicStoreEntityOrganization } from '../../src/modules/organization/organization-types';
import { findAll as findAllOrganization } from '../../src/modules/organization/organization-domain';
import { generateStandardId } from '../../src/schema/identifier';
import { ENTITY_TYPE_GROUP } from '../../src/schema/internalObject';
import { storeLoadById } from '../../src/database/middleware-loader';
import type { Group } from '../../src/types/group';
import type { AuthUser } from '../../src/types/user';
import { ACCOUNT_STATUS_ACTIVE } from '../../src/config/conf';

/**
 * Utilities and helper for test that are done at domain level (so direct to database, no graphQL query)
 */

/**
 * Resolve test organization data to entity organization.
 * @param testOrg
 */
export const getOrganizationEntity = async (testOrg: OrganizationTestData) => {
  const allOrgs: StoreEntityConnection<BasicStoreEntityOrganization> = await findAllOrganization(testContext, ADMIN_USER, { search: `"${testOrg.name}"` });
  return allOrgs.edges.find((currentOrg) => currentOrg.node.name === testOrg.name)?.node as BasicStoreEntityOrganization;
};

/**
 * Resolve test group data to entity group.
 * @param testGroup
 */
export const getGroupEntity = async (testGroup: GroupTestData) => {
  const groupId = generateStandardId(ENTITY_TYPE_GROUP, { name: testGroup.name });
  const data = await storeLoadById(testContext, ADMIN_USER, groupId, ENTITY_TYPE_GROUP) as Group;
  return data;
};

export const getFakeAuthUser = (userName: string) => {
  const userId = uuid();
  const user: AuthUser = {
    api_token: uuid(),
    individual_id: undefined,
    administrated_organizations: [],
    entity_type: 'User',
    id: userId,
    internal_id: userId,
    organizations: [],
    name: `${userName}`,
    user_email: `${userName}@opencti.io`,
    roles: [],
    groups: [],
    capabilities: [],
    all_marking: [],
    allowed_marking: [],
    default_marking: [],
    origin: { referer: 'test', user_id: userId },
    account_status: ACCOUNT_STATUS_ACTIVE,
    account_lock_after_date: undefined,
    effective_confidence_level: {
      max_confidence: 100,
      overrides: [],
    },
    user_confidence_level: {
      max_confidence: 100,
      overrides: [],
    },
    max_shareable_marking: [],
    restrict_delete: false,
    no_creators: false
  };
  return user;
};

/**
 * Helper for counter debug
 * @param data
 */
export const mapEdgesCountPerEntityType = (data: any) => {
  const map = new Map();
  for (let i = 0; i < data.edges.length; i += 1) {
    const entityType = data.edges[i].node.entity_type;
    if (map.has(entityType)) {
      const count = map.get(entityType);
      map.set(entityType, count + 1);
    } else {
      map.set(entityType, 1);
    }
  }
  return map;
};

export const mapCountPerEntityType = (data: any) => {
  const map = new Map();
  for (let i = 0; i < data.length; i += 1) {
    const entityType = data[i].entity_type;
    if (map.has(entityType)) {
      const count = map.get(entityType);
      map.set(entityType, count + 1);
    } else {
      map.set(entityType, 1);
    }
  }
  return map;
};
