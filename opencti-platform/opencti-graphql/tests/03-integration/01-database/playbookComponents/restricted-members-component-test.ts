import { describe, expect, it, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import type { StixBundle, StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT } from '../../../../src/modules/playbook/playbook-components';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import * as access from '../../../../src/utils/access';
import * as authorizedMembers from '../../../../src/utils/authorizedMembers';

describe('PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT', () => {
  const reportId = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
  const secondReportId = 'report--second-report';
  const userId = 'user-uuid-1';
  const organizationId = 'org-uuid-1';
  const groupId = 'group-uuid-1';

  const baseBundle: StixBundle = {
    type: 'bundle',
    spec_version: '2.1',
    id: 'bundle--test-id',
    objects: [],
  } as StixBundle;

  const createBaseBundleObject = (options?: {
    id?: string;
    createdById?: string;
    createdByType?: string;
    creatorIds?: string[];
    assigneeIds?: string[];
    participantIds?: string[];
  }): StixObject => ({
    id: options?.id ?? reportId,
    spec_version: '2.1',
    type: 'report',
    name: 'Test Report',
    extensions: {
      [STIX_EXT_OCTI]: {
        id: 'internal-uuid',
        type: ENTITY_TYPE_CONTAINER_REPORT,
        extension_type: 'property-extension',
        ...(options?.createdById && { created_by_ref_id: options.createdById }),
        ...(options?.createdByType && { created_by_ref_type: options.createdByType }),
        ...(options?.creatorIds && { creator_ids: options.creatorIds }),
        ...(options?.assigneeIds && { assignee_ids: options.assigneeIds }),
        ...(options?.participantIds && { participant_ids: options.participantIds }),
      } as StixOpenctiExtension,
    },
  } as StixObject);

  const basePlaybookNode = {
    id: 'playbook-node-1',
    name: 'Access Restrictions Node',
    component_id: 'PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT',
  };

  const baseExecutorParams = {
    dataInstanceId: reportId,
    eventId: '',
    executionId: '',
    playbookId: '',
    previousPlaybookNodeId: undefined,
    previousStepBundle: null as StixBundle | null,
  };

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

  const createPlaybookNode = (
    accessRestrictions: ReturnType<typeof createAccessRestriction>[],
    all = false,
  ) => ({
    ...basePlaybookNode,
    configuration: {
      access_restrictions: accessRestrictions,
      all,
    },
  });

  type BuildRestrictedMembersSpy = MockInstance<typeof authorizedMembers.buildRestrictedMembers>;
  let buildRestrictedMembersSpy: BuildRestrictedMembersSpy;

  beforeEach(() => {
    vi.spyOn(access, 'executionContext').mockReturnValue({} as any);
    buildRestrictedMembersSpy = vi.spyOn(authorizedMembers, 'buildRestrictedMembers');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('when applying static access restrictions', () => {
    it('should add authorized_members to dataInstanceId object', async () => {
      const mockAuthorizedMembers = [
        { id: userId, access_right: 'admin', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject()],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction(userId, 'admin'),
        ], false),
      });

      expect(buildRestrictedMembersSpy).toHaveBeenCalled();
      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toBeDefined();
      expect(ext.authorized_members).toEqual(mockAuthorizedMembers);
    });

    it('should add authorized_members with groups restriction', async () => {
      const mockAuthorizedMembers = [
        { id: userId, access_right: 'edit', groups_restriction_ids: [groupId] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject()],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction(userId, 'edit', {
            groupsRestriction: [{ label: 'Test Group', value: groupId, type: 'Group' }],
          }),
        ], false),
      });

      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toEqual(mockAuthorizedMembers);
    });

    it('should add multiple authorized_members', async () => {
      const mockAuthorizedMembers = [
        { id: userId, access_right: 'admin', groups_restriction_ids: [] },
        { id: organizationId, access_right: 'view', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject()],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction(userId, 'admin'),
          createAccessRestriction(organizationId, 'view', { type: 'Organization' }),
        ], false),
      });

      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toEqual(mockAuthorizedMembers);
    });

    it('should call buildRestrictedMembers with correct input', async () => {
      const mockAuthorizedMembers = [
        { id: userId, access_right: 'admin', groups_restriction_ids: [groupId] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject()],
      };

      await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction(userId, 'admin', {
            groupsRestriction: [{ label: 'Test Group', value: groupId, type: 'Group' }],
          }),
        ], false),
      });

      expect(buildRestrictedMembersSpy).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          entityId: reportId,
          input: [
            {
              id: userId,
              access_right: 'admin',
              groups_restriction_ids: [groupId],
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

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject({
          createdById: authorOrgId,
          createdByType: ENTITY_TYPE_IDENTITY_ORGANIZATION,
        })],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction('AUTHOR', 'admin'),
        ], false),
      });

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

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject({
          createdById: 'individual-id',
          createdByType: 'Individual',
        })],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction('AUTHOR', 'admin'),
        ], false),
      });

      // buildRestrictedMembers should not be called since no restrictions resolved
      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');
    });

    it('should not resolve AUTHOR when no author is defined', async () => {
      buildRestrictedMembersSpy.mockResolvedValue([]);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject()],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction('AUTHOR', 'admin'),
        ], false),
      });

      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');
    });

    it('should resolve CREATORS to creator_ids', async () => {
      const creatorId1 = 'creator-uuid-1';
      const creatorId2 = 'creator-uuid-2';
      const mockAuthorizedMembers = [
        { id: creatorId1, access_right: 'edit', groups_restriction_ids: [] },
        { id: creatorId2, access_right: 'edit', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject({
          creatorIds: [creatorId1, creatorId2],
        })],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction('CREATORS', 'edit'),
        ], false),
      });

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

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject({
          assigneeIds: [assigneeId],
        })],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction('ASSIGNEES', 'view'),
        ], false),
      });

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

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject({
          participantIds: [participantId],
        })],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction('PARTICIPANTS', 'view'),
        ], false),
      });

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
        { id: userId, access_right: 'admin', groups_restriction_ids: [] },
        { id: creatorId, access_right: 'edit', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject({
          creatorIds: [creatorId],
        })],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction(userId, 'admin'),
          createAccessRestriction('CREATORS', 'edit'),
        ], false),
      });

      expect(buildRestrictedMembersSpy).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          input: expect.arrayContaining([
            expect.objectContaining({ id: userId, access_right: 'admin' }),
            expect.objectContaining({ id: creatorId, access_right: 'edit' }),
          ]),
        }),
      );
      expect(result.output_port).toBe('out');
    });
  });

  describe('when bundle contains multiple objects', () => {
    it('should add authorized_members to all objects when all=true', async () => {
      const mockAuthorizedMembers = [
        { id: userId, access_right: 'admin', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [
          createBaseBundleObject(),
          createBaseBundleObject({ id: secondReportId }),
        ],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction(userId, 'admin'),
        ], true),
      });

      expect(result.output_port).toBe('out');

      // Check first object
      const reportExt = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(reportExt.authorized_members).toEqual(mockAuthorizedMembers);

      // Check second object
      const secondReportExt = result.bundle.objects[1].extensions[STIX_EXT_OCTI];
      expect(secondReportExt.authorized_members).toEqual(mockAuthorizedMembers);
    });

    it('should only add authorized_members to dataInstanceId when all=false', async () => {
      const mockAuthorizedMembers = [
        { id: userId, access_right: 'admin', groups_restriction_ids: [] },
      ];
      buildRestrictedMembersSpy.mockResolvedValue(mockAuthorizedMembers);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [
          createBaseBundleObject(),
          createBaseBundleObject({ id: secondReportId }),
        ],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction(userId, 'admin'),
        ], false),
      });

      expect(result.output_port).toBe('out');

      // Check first object - should have authorized_members
      const reportExt = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(reportExt.authorized_members).toEqual(mockAuthorizedMembers);

      // Check second object - should NOT have authorized_members
      const secondReportExt = result.bundle.objects[1].extensions[STIX_EXT_OCTI];
      expect(secondReportExt.authorized_members).toBeUndefined();
    });
  });

  describe('when no changes are made', () => {
    it('should return bundle unchanged when no access restrictions resolve', async () => {
      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject()],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction('AUTHOR', 'admin'),
        ], false),
      });

      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toBeUndefined();
    });

    it('should return bundle unchanged when CREATORS is empty', async () => {
      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject({
          creatorIds: [],
        })],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction('CREATORS', 'edit'),
        ], false),
      });

      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');
    });

    it('should return bundle unchanged when BUNDLE_ORGANIZATIONS has no organizations', async () => {
      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject()],
      };

      const result = await PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([
          createAccessRestriction('BUNDLE_ORGANIZATIONS', 'view'),
        ], false),
      });

      expect(buildRestrictedMembersSpy).not.toHaveBeenCalled();
      expect(result.output_port).toBe('out');
    });
  });
});
