import { describe, it, expect } from 'vitest';
import { v4 as uuid } from 'uuid';
import {
  ADMINISTRATOR_ROLE,
  BYPASS,
  checkUserCanAccessStixElement,
  checkUserFilterStoreElements,
  DEFAULT_ROLE,
  getUserAccessRight,
  isMarkingAllowed,
  isOrganizationAllowed,
  KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS,
  MEMBER_ACCESS_RIGHT_ADMIN,
  MEMBER_ACCESS_RIGHT_EDIT,
  MEMBER_ACCESS_RIGHT_VIEW
} from '../../../src/utils/access';
import type { BasicStoreCommon } from '../../../src/types/store';
import { MARKING_TLP_AMBER, MARKING_TLP_CLEAR, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import type { AuthUser } from '../../../src/types/user';
import type { BasicStoreSettings } from '../../../src/types/settings';
import { PLATFORM_ORGANIZATION, TEST_ORGANIZATION, testContext } from '../../utils/testQuery';
import { RELATION_GRANTED_TO } from '../../../src/schema/stixRefRelationship';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import type { StixObject, StixOpenctiExtension } from '../../../src/types/stix-2-1-common';
import type { Group } from '../../../src/types/group';

const inPlatformContext = { ...testContext, user_inside_platform_organization: true };

describe('Check markings test coverage', () => {
  it('should element with no marking be allowed', async () => {
    const element: Partial<BasicStoreCommon> = {
      'object-marking': [],
    };
    const userAllowedMarking: string[] = [];
    expect(isMarkingAllowed(element as BasicStoreCommon, userAllowedMarking)).toBeTruthy();
  });

  it('should element with marking refused for user without markings', async () => {
    const element: Partial<BasicStoreCommon> = {
      'object-marking': [MARKING_TLP_GREEN],
    };
    const userAllowedMarking: string[] = [];
    expect(isMarkingAllowed(element as BasicStoreCommon, userAllowedMarking)).toBeFalsy();
  });

  it('should element with marking refused for user with lower marking', async () => {
    const element: Partial<BasicStoreCommon> = {
      'object-marking': [MARKING_TLP_GREEN],
    };
    const userAllowedMarking: string[] = [MARKING_TLP_CLEAR];
    expect(isMarkingAllowed(element as BasicStoreCommon, userAllowedMarking)).toBeFalsy();
  });

  it('should element with marking allowed for user with higher marking', async () => {
    const element: Partial<BasicStoreCommon> = {
      'object-marking': [MARKING_TLP_CLEAR],
    };
    const userAllowedMarking: string[] = [MARKING_TLP_GREEN, MARKING_TLP_CLEAR];
    expect(isMarkingAllowed(element as BasicStoreCommon, userAllowedMarking)).toBeTruthy();
  });

  it('should element with one marking higher than user ones be refused', async () => {
    const element: Partial<BasicStoreCommon> = {
      'object-marking': [MARKING_TLP_CLEAR, MARKING_TLP_RED],
    };
    const userAllowedMarking: string[] = [MARKING_TLP_GREEN, MARKING_TLP_AMBER];
    expect(isMarkingAllowed(element as BasicStoreCommon, userAllowedMarking)).toBeFalsy();
  });
});

describe('Check organization access for element.', () => {
  it('should element when no platform organization setup be allowed', async () => {
    const element: Partial<BasicStoreCommon> = {
      internal_id: uuid()
    };

    const user: Partial<AuthUser> = {
      organizations: [],
      internal_id: uuid()
    };

    const settings: Partial<BasicStoreSettings> = {
      platform_organization: undefined,
    };
    const hasPlatformOrg = !!settings.platform_organization;
    expect(isOrganizationAllowed(inPlatformContext, element as BasicStoreCommon, user as AuthUser, hasPlatformOrg)).toBeTruthy();
  });

  it('should element not shared be allowed to user in platform organization', async () => {
    const element: Partial<BasicStoreCommon> = {
      internal_id: uuid()
    };

    const org : Partial<BasicStoreEntityOrganization> = {
      internal_id: PLATFORM_ORGANIZATION.id,
    };
    const allOrgs: BasicStoreEntityOrganization[] = [];
    allOrgs.push(org as BasicStoreEntityOrganization);

    const user: Partial<AuthUser> = {
      organizations: allOrgs,
      internal_id: uuid()
    };

    const settings: Partial<BasicStoreSettings> = {
      platform_organization: PLATFORM_ORGANIZATION.name,
    };
    const hasPlatformOrg = !!settings.platform_organization;
    expect(isOrganizationAllowed(inPlatformContext, element as BasicStoreCommon, user as AuthUser, hasPlatformOrg)).toBeTruthy();
  });

  it('should element not shared not be allowed to user in another organization', async () => {
    const element: Partial<BasicStoreCommon> = {
      internal_id: uuid()
    };

    const org : Partial<BasicStoreEntityOrganization> = {
      internal_id: TEST_ORGANIZATION.id,
    };
    const allOrgs: BasicStoreEntityOrganization[] = [];
    allOrgs.push(org as BasicStoreEntityOrganization);

    const user: Partial<AuthUser> = {
      organizations: allOrgs,
      internal_id: uuid()
    };

    const settings: Partial<BasicStoreSettings> = {
      platform_organization: PLATFORM_ORGANIZATION.name,
    };
    const hasPlatformOrg = !!settings.platform_organization;
    expect(isOrganizationAllowed(testContext, element as BasicStoreCommon, user as AuthUser, hasPlatformOrg)).toBeFalsy();
  });

  it('should element shared to user organization be allowed', async () => {
    const element: Partial<BasicStoreCommon> = {
      internal_id: uuid()
    };
    element[RELATION_GRANTED_TO] = [TEST_ORGANIZATION.id];

    const org : Partial<BasicStoreEntityOrganization> = {
      internal_id: TEST_ORGANIZATION.id,
      id: TEST_ORGANIZATION.id,
    };
    const allOrgs: BasicStoreEntityOrganization[] = [];
    allOrgs.push(org as BasicStoreEntityOrganization);

    const user: Partial<AuthUser> = {
      organizations: allOrgs,
      internal_id: uuid()
    };

    const settings: Partial<BasicStoreSettings> = {
      platform_organization: PLATFORM_ORGANIZATION.name,
    };
    const hasPlatformOrg = !!settings.platform_organization;
    expect(isOrganizationAllowed(inPlatformContext, element as BasicStoreCommon, user as AuthUser, hasPlatformOrg)).toBeTruthy();
  });
});

describe('User access entity testing', async () => {
  const user_is_allowed: Partial<AuthUser> = {
    id: '55ec0c6a-13ce-5e39-b486-354fe4a7084f',
    internal_id: '55ec0c6a-13ce-5e39-b486-354fe4a7084f',
    capabilities: [{ name: KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS }],
    organizations: [],
    allowed_marking: [],
    roles: [ADMINISTRATOR_ROLE],
    groups: [],
  };

  const user_is_not_allowed: Partial<AuthUser> = {
    id: '48ec0c6a-13ce-5e39-b486-354fe4a7084f',
    internal_id: '48ec0c6a-13ce-5e39-b486-354fe4a7084f',
    allowed_marking: [],
    roles: [ADMINISTRATOR_ROLE],
    groups: [],
    capabilities: [{ name: KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS, }],
    organizations: [],
  };

  const report: Partial<StixObject> = {
    id: 'report--f3e554eb-60f5-587c-9191-4f25e9ba9f32',
    spec_version: '2.1',
    type: 'report',
    extensions: {
      'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
        extension_type: 'property-extension',
        id: 'f13cd64f-9268-4d77-9850-eb6fbe322463',
        type: 'Report',
        authorized_members: [
          {
            id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
            access_right: 'admin'
          },
          {
            id: '55ec0c6a-13ce-5e39-b486-354fe4a7084f',
            access_right: 'view'
          },
        ],
      } as StixOpenctiExtension,
    },
  };

  const element: Partial<BasicStoreCommon> = {
    id: 'report--f3e554eb-60f5-587c-9191-4f25e9ba9f32',
    spec_version: '2.1',
    entity_type: 'Report',
    internal_id: 'f13cd64f-9268-4d77-9850-eb6fbe322463',
    restricted_members: [
      {
        id: '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
        access_right: 'admin'
      },
      {
        id: '55ec0c6a-13ce-5e39-b486-354fe4a7084f',
        access_right: 'view'
      },
    ],
  } as BasicStoreCommon;

  it('user in auth members should access element', () => {
    const hasAccess = checkUserCanAccessStixElement(testContext, user_is_allowed as AuthUser, report as StixObject, true);
    expect(hasAccess).toEqual(true);
  });
  it('User not in authorized members should not access STIX element', () => {
    const hasAccess = checkUserCanAccessStixElement(testContext, user_is_not_allowed as AuthUser, report as StixObject, true);
    expect(hasAccess).toEqual(false);
  });
  it('User in authorized members should access stored element', () => {
    const hasAccess = checkUserFilterStoreElements(testContext, user_is_allowed as AuthUser, element as BasicStoreCommon, [], true);
    expect(hasAccess).toEqual(true);
  });
  it('User not in authorized members should not access stored element', () => {
    const hasAccess = checkUserFilterStoreElements(testContext, user_is_not_allowed as AuthUser, element as BasicStoreCommon, [], true);
    expect(hasAccess).toEqual(false);
  });
});

describe('getUserAccessRight testing', () => {
  const groupId = '8a522ce7-j325-6hc8-a2ab-t8a934a1c647';
  const group: Partial<Group> = {
    id: groupId,
    internal_id: groupId,
  };

  const group2Id = '4d522ce7-j325-6hc8-a2ab-t8a934a1c657';
  const group2: Partial<Group> = {
    id: group2Id,
    internal_id: group2Id,
  };

  const orgaId = '7b522ce7-j325-6hc8-a2ab-t8a934a1c612';
  const orga: Partial<BasicStoreEntityOrganization> = {
    id: orgaId,
    internal_id: orgaId,
  };

  const userId = '55ec0c6a-13ce-5e39-b486-354fe4a7084f';
  const user: Partial<AuthUser> = {
    id: userId,
    internal_id: userId,
    capabilities: [{ name: KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS }],
    organizations: [orga as BasicStoreEntityOrganization],
    allowed_marking: [],
    roles: [DEFAULT_ROLE],
    groups: [group as Group, group2 as Group],
  };

  const bypassUserId = '2a522ce7-j325-4hc8-a2ab-t8a934a1c645';
  const bypassUser: Partial<AuthUser> = {
    id: bypassUserId,
    capabilities: [{ name: BYPASS }],
    organizations: [],
    allowed_marking: [],
    roles: [ADMINISTRATOR_ROLE],
    groups: [],
  };

  it('should return "admin" if no restricted members', () => {
    const element = { restricted_members: [], authorized_authorities: [] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(MEMBER_ACCESS_RIGHT_ADMIN);
  });
  it('should return "admin" for BYPASS User', () => {
    const restricted_members = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'edit',
      groups_restriction_ids: []
    }];
    const element = { restricted_members, authorized_authorities: [] };
    const expected = getUserAccessRight(bypassUser as AuthUser, element);
    expect(expected).toEqual(MEMBER_ACCESS_RIGHT_ADMIN);
  });
  it('should return "admin" with authorized authorities', () => {
    const restricted_members = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'edit',
      groups_restriction_ids: []
    }];
    const element = { restricted_members, authorized_authorities: [userId] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(MEMBER_ACCESS_RIGHT_ADMIN);
  });
  it('should return "admin" if member has access right "admin"', () => {
    const restricted_members = [{
      id: userId,
      access_right: 'admin',
      groups_restriction_ids: []
    }];
    const element = { restricted_members, authorized_authorities: [] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(MEMBER_ACCESS_RIGHT_ADMIN);
  });
  it('should return "edit" if member has access right "edit"', () => {
    const restricted_members = [{
      id: userId,
      access_right: 'edit',
      groups_restriction_ids: []
    }];
    const element = { restricted_members, authorized_authorities: [] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(MEMBER_ACCESS_RIGHT_EDIT);
  });
  it('should return "view" if member has access right "view"', () => {
    const restricted_members = [{
      id: userId,
      access_right: 'view',
      groups_restriction_ids: []
    }];
    const element = { restricted_members, authorized_authorities: [] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(MEMBER_ACCESS_RIGHT_VIEW);
  });
  it('should return access right if user belongs to orga and to groups_restriction_ids', () => {
    const restricted_members = [{
      id: orgaId,
      access_right: 'view',
      groups_restriction_ids: [groupId]
    }];
    const element = { restricted_members, authorized_authorities: [] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(MEMBER_ACCESS_RIGHT_VIEW);
  });
  it('should return access right if user belongs to orga and to all groups_restriction_ids', () => {
    const restricted_members = [{
      id: orgaId,
      access_right: 'view',
      groups_restriction_ids: [groupId, group2Id]
    }];
    const element = { restricted_members, authorized_authorities: [] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(MEMBER_ACCESS_RIGHT_VIEW);
  });
  it('should return null if user belongs to orga but not to groups_restriction_ids', () => {
    const restricted_members = [{
      id: orgaId,
      access_right: 'view',
      groups_restriction_ids: ['1e522ce6-f324-4cc9-a2ab-a1a934a1c209']
    }];
    const element = { restricted_members, authorized_authorities: [] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(null);
  });
  it('should return nul if user belongs to orga and not to all groups_restriction_ids', () => {
    const restricted_members = [{
      id: orgaId,
      access_right: 'view',
      groups_restriction_ids: [groupId, '1e522ce6-f324-4cc9-a2ab-a1a934a1c209']
    }];
    const element = { restricted_members, authorized_authorities: [] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(null);
  });
  it('should return null if user not in restricted members', () => {
    const restricted_members = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: []
    }];
    const element = { restricted_members, authorized_authorities: [] };
    const expected = getUserAccessRight(user as AuthUser, element);
    expect(expected).toEqual(null);
  });
});
