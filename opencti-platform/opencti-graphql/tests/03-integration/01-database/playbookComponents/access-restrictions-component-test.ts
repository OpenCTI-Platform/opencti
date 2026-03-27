import { describe, expect, it, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import * as authorizedMembers from '../../../../src/utils/authorizedMembers';
import { PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT } from '../../../../src/modules/playbook/components/access-restrictions-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../../src/modules/grouping/grouping-types';
import { USER_EDITOR } from '../../../utils/testQuery';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';

describe('PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT', () => {
  const REPORT_ID = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
  const GROUPING_ID = 'grouping--5f78a68b-2c4d-5e6f-beaa-7b987b0e7133';
  const USER_ID = USER_EDITOR.id;
  const ORGA_ID = 'org-uuid-1';
  const GROUP_ID = 'group-uuid-1';

  const createAccessRestriction = (
    value: string,
    accessRight: string,
    options?: {
      label?: string;
      type?: string;
      groupsRestriction?: { label: string; value: string; type: string }[];
    },
  ) => ({
    label: options?.label ?? 'Test',
    value,
    type: options?.type ?? 'User',
    accessRight,
    groupsRestriction: options?.groupsRestriction ?? [],
  });

  type BuildRestrictedMembersSpy = MockInstance<typeof authorizedMembers.buildRestrictedMembers>;
  let buildRestrictedMembersSpy: BuildRestrictedMembersSpy;

  beforeEach(() => {
    buildRestrictedMembersSpy = vi.spyOn(authorizedMembers, 'buildRestrictedMembers');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('when applying static access restrictions', () => {
    it('should add authorized_members to dataInstanceId object', async () => {
      const mockAuthorizedMembers = [
        { id: USER_ID, access_right: 'admin', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
        })],
        configuration: {
          access_restrictions: [createAccessRestriction(USER_ID, 'admin')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).toHaveBeenCalled();
      expect(result.output_port).toBe('out');
      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toBeDefined();
      expect(ext.authorized_members).toEqual(mockAuthorizedMembers);
    });

    it('should add authorized_members with groups restriction', async () => {
      const mockAuthorizedMembers = [
        { id: USER_ID, access_right: 'edit', groups_restriction_ids: [GROUP_ID] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
        })],
        configuration: {
          access_restrictions: [createAccessRestriction(USER_ID, 'edit', {
            groupsRestriction: [{ label: 'Test Group', value: GROUP_ID, type: 'Group' }],
          })],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(result.output_port).toBe('out');
      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toEqual(mockAuthorizedMembers);
    });

    it('should add multiple authorized_members', async () => {
      const mockAuthorizedMembers = [
        { id: USER_ID, access_right: 'admin', groups_restriction_ids: [] },
        { id: ORGA_ID, access_right: 'view', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
        })],
        configuration: {
          access_restrictions: [
            createAccessRestriction(USER_ID, 'admin'),
            createAccessRestriction(ORGA_ID, 'view', { type: 'Organization' }),
          ],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(result.output_port).toBe('out');
      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toEqual(mockAuthorizedMembers);
    });

    it('should call buildRestrictedMembers with correct input', async () => {
      const mockAuthorizedMembers = [
        { id: USER_ID, access_right: 'admin', groups_restriction_ids: [GROUP_ID] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
        })],
        configuration: {
          access_restrictions: [createAccessRestriction(USER_ID, 'admin', {
            groupsRestriction: [{ label: 'Test Group', value: GROUP_ID, type: 'Group' }],
          })],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          entityId: REPORT_ID,
          input: [
            {
              id: USER_ID,
              access_right: 'admin',
              groups_restriction_ids: [GROUP_ID],
            },
          ],
        }),
      );
    });
  });

  describe('when using dynamic access restrictions', () => {
    it('should resolve AUTHOR to created_by_ref_id when author is an organization', async () => {
      const authorOrgId = 'author-org-uuid';
      const mockAuthorizedMembers = [
        { id: authorOrgId, access_right: 'admin', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: {
            created_by_ref_id: authorOrgId,
            created_by_ref_type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
          },
        })],
        configuration: {
          access_restrictions: [createAccessRestriction('AUTHOR', 'admin')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          input: [
            expect.objectContaining({ id: authorOrgId }),
          ],
        }),
      );
      expect(result.output_port).toBe('out');
    });

    it('should not resolve AUTHOR when author is not an organization', async () => {
      buildRestrictedMembersSpy.mockResolvedValue([]);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: {
            created_by_ref_id: 'individual-id',
            created_by_ref_type: ENTITY_TYPE_IDENTITY_INDIVIDUAL,
          },
        })],
        configuration: {
          access_restrictions: [createAccessRestriction('AUTHOR', 'admin')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      // buildRestrictedMembers should not be called since no restrictions resolved
      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');
      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toBeUndefined();
    });

    it('should not resolve AUTHOR when no author is defined', async () => {
      buildRestrictedMembersSpy.mockResolvedValue([]);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
        })],
        configuration: {
          access_restrictions: [createAccessRestriction('AUTHOR', 'admin')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');
      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toBeUndefined();
    });

    it('should resolve CREATORS to creator_ids', async () => {
      const creatorId1 = 'creator-uuid-1';
      const creatorId2 = 'creator-uuid-2';
      const mockAuthorizedMembers = [
        { id: creatorId1, access_right: 'edit', groups_restriction_ids: [] },
        { id: creatorId2, access_right: 'edit', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: {
            creator_ids: [creatorId1, creatorId2],
          },
        })],
        configuration: {
          access_restrictions: [createAccessRestriction('CREATORS', 'edit')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          input: expect.arrayContaining([
            expect.objectContaining({ id: creatorId1, access_right: 'edit' }),
            expect.objectContaining({ id: creatorId2, access_right: 'edit' }),
          ]),
        }),
      );
      expect(result.output_port).toBe('out');
    });

    it('should resolve ASSIGNEES to assignee_ids', async () => {
      const assigneeId = 'assignee-uuid-1';
      const mockAuthorizedMembers = [
        { id: assigneeId, access_right: 'view', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: {
            assignee_ids: [assigneeId],
          },
        })],
        configuration: {
          access_restrictions: [createAccessRestriction('ASSIGNEES', 'view')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          input: [
            expect.objectContaining({ id: assigneeId, access_right: 'view' }),
          ],
        }),
      );
      expect(result.output_port).toBe('out');
    });

    it('should resolve PARTICIPANTS to participant_ids', async () => {
      const participantId = 'participant-uuid-1';
      const mockAuthorizedMembers = [
        { id: participantId, access_right: 'view', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: {
            participant_ids: [participantId],
          },
        })],
        configuration: {
          access_restrictions: [createAccessRestriction('PARTICIPANTS', 'view')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          input: [
            expect.objectContaining({ id: participantId, access_right: 'view' }),
          ],
        }),
      );
      expect(result.output_port).toBe('out');
    });

    it('should combine static and dynamic access restrictions', async () => {
      const creatorId = 'creator-uuid';
      const mockAuthorizedMembers = [
        { id: USER_ID, access_right: 'admin', groups_restriction_ids: [] },
        { id: creatorId, access_right: 'edit', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: {
            creator_ids: [creatorId],
          },
        })],
        configuration: {
          access_restrictions: [
            createAccessRestriction(USER_ID, 'admin'),
            createAccessRestriction('CREATORS', 'edit'),
          ],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          input: expect.arrayContaining([
            expect.objectContaining({ id: USER_ID, access_right: 'admin' }),
            expect.objectContaining({ id: creatorId, access_right: 'edit' }),
          ]),
        }),
      );
      expect(result.output_port).toBe('out');
    });
  });

  describe('when bundle contains multiple objects', () => {
    const expectedAccessRestriction = [{
      id: USER_ID,
      access_right: 'admin',
      groups_restriction_ids: [],
    }];

    const BUNDLE_OBJECTS = () => [
      testBundleObject({
        id: REPORT_ID,
        type: ENTITY_TYPE_CONTAINER_REPORT,
      }),
      testBundleObject({
        id: GROUPING_ID,
        type: ENTITY_TYPE_CONTAINER_GROUPING,
      }),
    ];

    it('should add authorized_members to all objects in the bundle', async () => {
      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: {
          access_restrictions: [createAccessRestriction(USER_ID, 'admin')],
          applyToElements: playbookBundleElementsToApply.allElements.value,
        },
      }));

      expect(result.output_port).toBe('out');
      // Check first object
      const reportExt = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(reportExt.authorized_members).toEqual(expectedAccessRestriction);
      // Check second object
      const secondReportExt = result.bundle.objects[1].extensions[STIX_EXT_OCTI];
      expect(secondReportExt.authorized_members).toEqual(expectedAccessRestriction);
    });

    it('should only add authorized_members to only main element of the bundle', async () => {
      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: {
          access_restrictions: [createAccessRestriction(USER_ID, 'admin')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(result.output_port).toBe('out');
      // Check first object - should have authorized_members
      const reportExt = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(reportExt.authorized_members).toEqual(expectedAccessRestriction);
      // Check second object - should NOT have authorized_members
      const secondReportExt = result.bundle.objects[1].extensions[STIX_EXT_OCTI];
      expect(secondReportExt.authorized_members).toBeUndefined();
    });

    it('should add authorized_members to all except main element of the bundle', async () => {
      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: {
          access_restrictions: [createAccessRestriction(USER_ID, 'admin')],
          applyToElements: playbookBundleElementsToApply.allExceptMain.value,
        },
      }));

      expect(result.output_port).toBe('out');
      // Check first object - should not have authorized_members
      const reportExt = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      console.log();
      expect(reportExt.authorized_members).toBeUndefined();
      // Check second object - should have authorized_members
      const secondReportExt = result.bundle.objects[1].extensions[STIX_EXT_OCTI];
      expect(secondReportExt.authorized_members).toEqual(expectedAccessRestriction);
    });
  });

  describe('when no changes are made', () => {
    it('should return bundle unchanged when no access restrictions resolve', async () => {
      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
        })],
        configuration: {
          access_restrictions: [createAccessRestriction('AUTHOR', 'admin')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');
      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toBeUndefined();
    });

    it('should return bundle unchanged when CREATORS is empty', async () => {
      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: {
            creator_ids: [],
          },
        })],
        configuration: {
          access_restrictions: [createAccessRestriction('CREATORS', 'edit')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');
      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toBeUndefined();
    });

    it('should return bundle unchanged when BUNDLE_ORGANIZATIONS has no organizations', async () => {
      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: [testBundleObject({
          id: REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
        })],
        configuration: {
          access_restrictions: [createAccessRestriction('BUNDLE_ORGANIZATIONS', 'view')],
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');
      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toBeUndefined();
    });
  });
});
