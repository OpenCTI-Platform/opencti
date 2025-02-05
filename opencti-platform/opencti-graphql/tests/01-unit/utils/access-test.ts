import { describe, it, expect } from 'vitest';
import { v4 as uuid } from 'uuid';
import { isMarkingAllowed, isOrganizationAllowed } from '../../../src/utils/access';
import type { BasicStoreCommon } from '../../../src/types/store';
import { MARKING_TLP_AMBER, MARKING_TLP_CLEAR, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import type { AuthUser } from '../../../src/types/user';
import type { BasicStoreSettings } from '../../../src/types/settings';
import { PLATFORM_ORGANIZATION, TEST_ORGANIZATION } from '../../utils/testQuery';
import { RELATION_GRANTED_TO } from '../../../src/schema/stixRefRelationship';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';

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

    expect(isOrganizationAllowed(element as BasicStoreCommon, user as AuthUser, settings as BasicStoreSettings)).toBeTruthy();
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

    expect(isOrganizationAllowed(element as BasicStoreCommon, user as AuthUser, settings as BasicStoreSettings)).toBeTruthy();
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

    expect(isOrganizationAllowed(element as BasicStoreCommon, user as AuthUser, settings as BasicStoreSettings)).toBeFalsy();
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

    expect(isOrganizationAllowed(element as BasicStoreCommon, user as AuthUser, settings as BasicStoreSettings)).toBeTruthy();
  });
});
