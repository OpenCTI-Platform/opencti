import { describe, expect, it } from 'vitest';
import type { StixBundle, StixObject } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT } from '../../../../src/modules/playbook/playbook-components';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../../src/schema/stixDomainObject';

describe('PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT', () => {
  const reportId = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
  const secondReportId = 'report--second-report';
  const baseBundle: StixBundle = {
    type: 'bundle',
    spec_version: '2.1',
    id: 'bundle--test-id',
    objects: [],
  } as StixBundle;

  const createBaseBundleObject = (options?: {
    id?: string;
    authorizedMembers?: any[];
    openctiUpsertOperations?: any[];
    restrictedMembers?: any[];
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
        ...(options?.authorizedMembers && { authorized_members: options.authorizedMembers }),
        ...(options?.openctiUpsertOperations && {
          opencti_upsert_operations: options.openctiUpsertOperations,
        }),
        ...(options?.restrictedMembers && { restrictedMembers: options.restrictedMembers }),
      },
    },
  } as unknown as StixObject);

  const basePlaybookNode = {
    id: 'playbook-node-1',
    name: 'Remove Access Restrictions Node',
    component_id: 'PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT',
  };

  const baseExecutorParams = {
    dataInstanceId: reportId,
    eventId: '',
    executionId: '',
    playbookId: '',
    previousPlaybookNodeId: undefined,
    previousStepBundle: null as StixBundle | null,
  };

  const createPlaybookNode = (all = false) => ({
    ...basePlaybookNode,
    configuration: {
      all,
    },
  });

  describe('when removing access restrictions', () => {
    it('should remove authorized_members from dataInstanceId object when all=false', async () => {
      const authorizedMembers = [
        { id: 'user-uuid-1', access_right: 'admin', groups_restriction_ids: [] },
      ];
      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject({ authorizedMembers })],
      };

      const result = await PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode(false),
      });

      const authorizedMembersResult = [
        { id: 'user-uuid-1', access_right: 'admin', groups_restriction_ids: [] },
      ];

      expect(result.output_port).toBe('out');
      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.authorized_members).toEqual(authorizedMembersResult);
    });

    // TODO: remove the skip when cascading of share/unshare/restrict will be done
    it.skip('should remove authorized_members from all objects when all=true', async () => {
      const authorizedMembers = [
        { id: 'user-uuid-1', access_right: 'admin', groups_restriction_ids: [] },
      ];
      const bundle: StixBundle = {
        ...baseBundle,
        objects: [
          createBaseBundleObject({ authorizedMembers }),
          createBaseBundleObject({ id: secondReportId, authorizedMembers }),
        ],
      };

      const result = await PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode(true),
      });

      const authorizedMembersResult = [
        { id: 'user-uuid-1', access_right: 'admin', groups_restriction_ids: [] },
      ];

      expect(result.output_port).toBe('out');
      const firstExt = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(firstExt.authorized_members).toEqual(authorizedMembersResult);
      const secondExt = result.bundle.objects[1].extensions[STIX_EXT_OCTI];
      expect(secondExt.authorized_members).toEqual([]);
    });

    it('should not modify bundle when dataInstanceId does not match any object', async () => {
      const authorizedMembers = [
        { id: 'user-uuid-1', access_right: 'admin', groups_restriction_ids: [] },
      ];
      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject({ id: secondReportId, authorizedMembers })],
      };

      const originalBundle = structuredClone(bundle);
      const result = await PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode(false),
      });

      expect(result.output_port).toBe('out');
      expect(result.bundle).toEqual(originalBundle);
    });

    it('should handle empty bundle', async () => {
      const bundle: StixBundle = {
        ...baseBundle,
        objects: [],
      };

      const result = await PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode(true),
      });

      expect(result.output_port).toBe('out');
      expect(result.bundle.objects).toEqual([]);
    });
  });
});
