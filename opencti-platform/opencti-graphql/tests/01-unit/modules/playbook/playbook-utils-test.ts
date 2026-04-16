import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as stixFiltering from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import { FilterMode } from '../../../../src/generated/graphql';
import { filterBundleElements, isBundleElementMatchFilters } from '../../../../src/modules/playbook/playbook-utils';
import { testContext } from '../../../utils/testQuery';
import type { StixObject } from '../../../../src/types/stix-2-1-common';
import * as cache from '../../../../src/database/cache';
import type { AuthUser } from '../../../../src/types/user';
import { convertMembersToUsers, extractBundleBaseElement } from '../../../../src/modules/playbook/playbook-utils';
import type { StixBundle, StixDomainObject } from '../../../../src/types/stix-2-1-common';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

describe('Playbook utils unit tests', () => {
  const matchingFilter = JSON.stringify({
    filterGroups: [],
    filters: [],
    mode: FilterMode.And,
  });
  const nonMatchingFilter = JSON.stringify({
    filterGroups: [],
    filters: [],
    mode: FilterMode.Or,
  });
  const stixElement1 = { id: 'malware--345243' } as unknown as StixObject;
  const stixElement2 = { id: 'campaign--2348746' } as unknown as StixObject;
  const stixElements = [stixElement1, stixElement2];
  const platformUsersWithGroupsAndOrganizations = [
    {
      _id: 'id-1',
      id: 'id-1',
      name: 'user-with-correct-member-id@opencti.io',
      groups: [],
      organizations: [],
    },
    {
      _id: 'id-2',
      id: 'id-2',
      name: 'user-with-correct-group@opencti.io',
      groups: [
        {
          _index: 'test_internal_objects-000001',
          _id: 'id-3',
          id: 'id-3',
          sort: [1761291916492],
          standard_id: 'group--id-4',
          internal_id: 'id-3',
          parent_types: ['Basic-Object', 'Internal-Object'],
          no_creators: false,
          confidence: 100,
          description: 'GROUP 1',
          created_at: '2025-10-24T07:45:16.492Z',
          auto_new_marking: false,
          restrict_delete: false,
          entity_type: 'Group',
          base_type: 'ENTITY',
          group_confidence_level: { max_confidence: 100, overrides: [] },
          updated_at: '2025-10-24T07:45:16.492Z',
          refreshed_at: '2025-10-24T07:45:31.781Z',
          name: 'GROUP 1',

          default_assignation: true,
        },
        {
          _index: 'test_internal_objects-000001',
          _id: 'id-5',
          id: 'id-5',
          sort: [1761291930468],
          standard_id: 'group--913fd3d5-fc8a-5835-8a30-392631282820',
          internal_id: 'id-5',
          parent_types: ['Basic-Object', 'Internal-Object'],
          no_creators: false,
          confidence: 100,
          created_at: '2025-10-24T07:45:30.468Z',
          auto_new_marking: false,
          restrict_delete: false,
          entity_type: 'Group',
          base_type: 'ENTITY',
          group_confidence_level: { max_confidence: 100, overrides: [] },
          updated_at: '2025-10-24T07:45:30.468Z',
          refreshed_at: '2025-10-24T07:45:30.715Z',
          name: 'GROUP 2',

          default_assignation: false,
        },
      ],
      organizations: [],
    },
    {
      _id: 'id-2',
      id: 'id-2',
      name: 'user-with-correct-organization@opencti.io',
      groups: [],
      organizations: [
        {
          _index: 'test_stix_domain_objects-000001',
          _id: 'id-6',
          id: 'id-6',
          sort: [1761291927301],
          standard_id: 'identity--id-7',
          identity_class: 'organization',
          internal_id: 'id-6',
          parent_types: [
            'Basic-Object',
            'Stix-Object',
            'Stix-Core-Object',
            'Stix-Domain-Object',
            'Identity',
          ],
          created: '2025-10-24T07:45:27.301Z',
          confidence: 100,
          created_at: '2025-10-24T07:45:27.301Z',
          revoked: false,
          entity_type: 'Organization',
          base_type: 'ENTITY',
          updated_at: '2025-10-24T07:45:27.301Z',
          refreshed_at: '2025-10-24T07:45:30.870Z',
          name: 'PlatformOrganization',

          modified: '2025-10-24T07:45:27.301Z',
          i_aliases_ids: [],
          x_opencti_stix_ids: [],
          lang: 'en',
          'rel_participate-to.internal_id.keyword': [
            'id-8',
            'id-2',
          ],
          'participate-to': [
            'id-8',
            'id-2',
          ],
        },
      ],
    },
    {
      _id: 'id-9',
      id: 'id-9',
      name: 'user-author@opencti.io',
      groups: [],
      organizations: [],
    },
    {
      _id: 'id-10',
      id: 'id-10',
      name: 'user-creator@opencti.io',
      groups: [],
      organizations: [],
    },
    {
      _id: 'id-11',
      id: 'id-11',
      name: 'user-assignee@opencti.io',
      groups: [],
      organizations: [],
    },
    {
      _id: 'id-12',
      id: 'id-12',
      name: 'user-participant@opencti.io',
      groups: [],
      organizations: [],
    },
    {
      _id: 'id-bundle-organizations',
      id: 'id-bundle-organizations',
      name: 'user-bundle-organization@opencti.io',
      groups: [],
      organizations: [],
    },
  ] as unknown as AuthUser[];

  beforeEach(() => {
    vi.spyOn(stixFiltering, 'isStixMatchFilterGroup')
      .mockImplementation(async (_, __, ___, filterGroup) => {
        return filterGroup?.mode === FilterMode.And;
      });
    vi.spyOn(cache, 'getEntitiesListFromCache').mockImplementation(async () => {
      return platformUsersWithGroupsAndOrganizations;
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Function: isBundleElementMatchFilters()', () => {
    it('should return true if matching filter', async () => {
      const result = await isBundleElementMatchFilters(
        testContext,
        stixElement1,
        matchingFilter,
      );
      expect(result).toBe(true);
    });

    it('should return false if non matching filter', async () => {
      const result = await isBundleElementMatchFilters(
        testContext,
        stixElement1,
        nonMatchingFilter,
      );
      expect(result).toBe(false);
    });

    it('should return true if no filters given', async () => {
      const result = await isBundleElementMatchFilters(
        testContext,
        stixElement1,
        '',
      );
      expect(result).toBe(true);
    });
  });

  describe('Function: filterBundleElements()', () => {
    it('should return full bundle if no filters', async () => {
      const result = await filterBundleElements(
        testContext,
        stixElements,
        '',
      );
      expect(result.length).toBe(2);
    });

    it('should return full bundle if matching filters', async () => {
      const result = await filterBundleElements(
        testContext,
        stixElements,
        matchingFilter,
      );
      expect(result.length).toBe(2);
    });

    it('should return empty bundle if non matching filters', async () => {
      const result = await filterBundleElements(
        testContext,
        stixElements,
        nonMatchingFilter,
      );
      expect(result.length).toBe(0);
    });
  });

  describe('Function: extractBundleBaseElement()', () => {
    const testBundle: StixBundle = {
      id: 'id-13',
      spec_version: '2.1',
      type: 'bundle',
      objects: [
        {
          id: 'malware--id-14',
          spec_version: '2.1',
          type: 'malware',
        } as unknown as StixDomainObject,
      ],
    };

    it('should throw an error if the data is not found in bundle', () => {
      const call = () => extractBundleBaseElement('not-present-id', testBundle);
      expect(call).toThrowError('Playbook base element no longer accessible');
    });

    it('should return data for the given ID', () => {
      const data = extractBundleBaseElement(
        'malware--id-14',
        testBundle,
      );
      expect(data).toEqual({
        id: 'malware--id-14',
        spec_version: '2.1',
        type: 'malware',
      });
    });
  });

  describe('Function: convertMembersToUsers()', () => {
    const testBundle: StixBundle = {
      id: 'id-13',
      spec_version: '2.1',
      type: 'bundle',
      objects: [
        {
          id: 'malware--id-14',
          spec_version: '2.1',
          type: 'malware',
          extensions: {
            [STIX_EXT_OCTI]: {
              created_by_ref_id: 'id-9',
              creator_ids: [
                'id-10',
                'id-15',
              ],
              assignee_ids: [
                'id-11',
              ],
              participant_ids: [
                'id-12',
                'id-10',
              ],
              type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
              id: 'id-bundle-organizations',
            },
          },
        } as unknown as StixDomainObject,
      ],
    };
    const baseData = testBundle.objects[0];

    it('should return an empty array if members is empty', async () => {
      expect(await convertMembersToUsers([], baseData, testBundle)).toEqual([]);
    });

    it('should return users directly set in members array', async () => {
      const members = [
        { value: 'invalid_id' },
        // ID of user with correct member id.
        { value: 'id-1' },
      ];
      const users = await convertMembersToUsers(members, baseData, testBundle);
      const usersNames = users.map((u) => u.name);
      expect(usersNames).toEqual(['user-with-correct-member-id@opencti.io']);
    });

    it('should return users from a group set in members array', async () => {
      const members = [
        { value: 'invalid_id' },
        // ID of group GROUP 1.
        { value: 'id-3' },
      ];
      const users = await convertMembersToUsers(members, baseData, testBundle);
      const usersNames = users.map((u) => u.name);
      expect(usersNames).toEqual(['user-with-correct-group@opencti.io']);
    });

    it('should return users from an organization set in members array', async () => {
      const members = [
        { value: 'invalid_id' },
        // ID of organization PlatformOrganization.
        { value: 'id-6' },
      ];
      const users = await convertMembersToUsers(members, baseData, testBundle);
      const usersNames = users.map((u) => u.name);
      expect(usersNames).toEqual(['user-with-correct-organization@opencti.io']);
    });

    it('should replace dynamic key AUTHOR by the correct user', async () => {
      const members = [
        { value: 'invalid_id' },
        { value: 'AUTHOR' },
      ];
      const users = await convertMembersToUsers(members, baseData, testBundle);
      const usersNames = users.map((u) => u.name);
      expect(usersNames).toEqual(['user-author@opencti.io']);
    });

    it('should replace dynamic key CREATORS by the correct users', async () => {
      const members = [
        { value: 'invalid_id' },
        { value: 'CREATORS' },
      ];
      const users = await convertMembersToUsers(members, baseData, testBundle);
      const usersNames = users.map((u) => u.name);
      expect(usersNames).toEqual(['user-creator@opencti.io']);
    });

    it('should replace dynamic key ASSIGNEES by the correct users', async () => {
      const members = [
        { value: 'invalid_id' },
        { value: 'ASSIGNEES' },
      ];
      const users = await convertMembersToUsers(members, baseData, testBundle);
      const usersNames = users.map((u) => u.name);
      expect(usersNames).toEqual(['user-assignee@opencti.io']);
    });

    it('should replace dynamic key PARTICIPANTS by the correct users', async () => {
      const members = [
        { value: 'invalid_id' },
        { value: 'PARTICIPANTS' },
      ];
      const users = await convertMembersToUsers(members, baseData, testBundle);
      const usersNames = users.map((u) => u.name);
      expect(usersNames).toEqual(['user-creator@opencti.io', 'user-participant@opencti.io']);
    });

    it('should replace dynamic key BUNDLE_ORGANIZATIONS by the correct users', async () => {
      const members = [
        { value: 'invalid_id' },
        { value: 'BUNDLE_ORGANIZATIONS' },
      ];
      const users = await convertMembersToUsers(members, baseData, testBundle);
      const usersNames = users.map((u) => u.name);
      expect(usersNames).toEqual(['user-bundle-organization@opencti.io']);
    });
  });
});
