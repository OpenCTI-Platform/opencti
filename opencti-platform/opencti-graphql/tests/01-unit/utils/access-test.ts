import { describe, it, expect } from 'vitest';
import { v4 as uuid } from 'uuid';
import { ADMINISTRATOR_ROLE, checkUserCanAccessStixElement, isMarkingAllowed, isOrganizationAllowed, KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../src/utils/access';
import type { BasicStoreCommon } from '../../../src/types/store';
import { MARKING_TLP_AMBER, MARKING_TLP_CLEAR, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import type { AuthUser } from '../../../src/types/user';
import type { BasicStoreSettings } from '../../../src/types/settings';
import { PLATFORM_ORGANIZATION, TEST_ORGANIZATION } from '../../utils/testQuery';
import { RELATION_GRANTED_TO } from '../../../src/schema/stixRefRelationship';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import type { StixObject, StixOpenctiExtension } from '../../../src/types/stix-common';

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

    expect(isOrganizationAllowed(element as BasicStoreCommon, user as AuthUser, settings.platform_organization as string)).toBeTruthy();
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
      inside_platform_organization: true,
      organizations: allOrgs,
      internal_id: uuid()
    };

    const settings: Partial<BasicStoreSettings> = {
      platform_organization: PLATFORM_ORGANIZATION.name,
    };

    expect(isOrganizationAllowed(element as BasicStoreCommon, user as AuthUser, settings.platform_organization as string)).toBeTruthy();
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
      inside_platform_organization: false,
      organizations: allOrgs,
      internal_id: uuid()
    };

    const settings: Partial<BasicStoreSettings> = {
      platform_organization: PLATFORM_ORGANIZATION.name,
    };

    expect(isOrganizationAllowed(element as BasicStoreCommon, user as AuthUser, settings.platform_organization as string)).toBeFalsy();
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
      inside_platform_organization: false,
      organizations: allOrgs,
      internal_id: uuid()
    };

    const settings: Partial<BasicStoreSettings> = {
      platform_organization: PLATFORM_ORGANIZATION.name,
    };

    expect(isOrganizationAllowed(element as BasicStoreCommon, user as AuthUser, settings.platform_organization as string)).toBeTruthy();
  });
});

describe('checkUserCanAccessStixElement testing', async () => {
  const user_is_allowed: Partial<AuthUser> = {
    id: '55ec0c6a-13ce-5e39-b486-354fe4a7084f',
    internal_id: '55ec0c6a-13ce-5e39-b486-354fe4a7084f',
    capabilities: [{ name: KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS }],
    organizations: [],
    inside_platform_organization: true,
    allowed_marking: [],
    roles: [ADMINISTRATOR_ROLE],
    groups: [],
  };

  const user_is_not_allowed: Partial<AuthUser> = {
    id: '48ec0c6a-13ce-5e39-b486-354fe4a7084f',
    internal_id: '48ec0c6a-13ce-5e39-b486-354fe4a7084f',
    inside_platform_organization: false,
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

  it('user in auth members should access element', async () => {
    const hasAccess = await checkUserCanAccessStixElement(user_is_allowed as AuthUser, report as StixObject, true);
    expect(hasAccess).toEqual(true);
  });
  it('user not in auth members should not access element', async () => {
    const hasAccess = await checkUserCanAccessStixElement(user_is_not_allowed as AuthUser, report as StixObject, true);
    expect(hasAccess).toEqual(false);
  });
});
