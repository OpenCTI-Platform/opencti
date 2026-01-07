import { assert, describe, expect, it, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import type { StixBundle, StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import type { BasicStoreObject } from '../../../../src/types/store';
import type { StixId } from '../../../../src/types/stix-2-0-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { PLAYBOOK_UNSHARING_COMPONENT } from '../../../../src/modules/playbook/playbook-components';
import { generateStandardId } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../../src/schema/stixDomainObject';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import * as access from '../../../../src/utils/access';

describe('PLAYBOOK_UNSHARING_COMPONENT', () => {
  const reportId = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
  const secondObjectId = 'indicator--second-object';

  const baseBundle: StixBundle = {
    type: 'bundle',
    spec_version: '2.1',
    id: 'bundle--test-id',
    objects: [],
  } as StixBundle;

  const createBaseBundleObject = (grantedRefs?: string[]): StixObject => ({
    id: reportId,
    spec_version: '2.1',
    type: 'report',
    name: 'Test Report',
    extensions: {
      [STIX_EXT_OCTI]: {
        id: 'internal-uuid',
        type: ENTITY_TYPE_CONTAINER_REPORT,
        extension_type: 'property-extension',
        ...(grantedRefs && { granted_refs: grantedRefs }),
      } as StixOpenctiExtension,
    },
  } as StixObject);

  const createSecondObject = (grantedRefs?: string[]): StixObject => ({
    id: secondObjectId,
    spec_version: '2.1',
    type: 'indicator',
    name: 'Test Indicator',
    extensions: {
      [STIX_EXT_OCTI]: {
        id: 'second-internal-uuid',
        type: 'Indicator',
        extension_type: 'property-extension',
        ...(grantedRefs && { granted_refs: grantedRefs }),
      } as StixOpenctiExtension,
    },
  } as StixObject);

  const basePlaybookNode = {
    id: 'playbook-node-1',
    name: 'Unshare Node',
    component_id: 'PLAYBOOK_UNSHARING_COMPONENT',
  };

  const baseExecutorParams = {
    dataInstanceId: reportId,
    eventId: '',
    executionId: '',
    playbookId: '',
    previousPlaybookNodeId: undefined,
    previousStepBundle: null as StixBundle | null,
  };

  const createPlaybookNode = (organizations: string[], all = false) => ({
    ...basePlaybookNode,
    configuration: {
      organizations,
      all,
    },
  });

  const createPlaybookNodeWithObjectOrgs = (organizations: { label: string; value: string }[], all = false) => ({
    ...basePlaybookNode,
    configuration: {
      organizations,
      all,
    },
  });

  const createMockOrganization = (name: string): Partial<BasicStoreObject> => ({
    id: `org-internal-${name}`,
    standard_id: generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, { name }) as StixId,
  });

  type InternalFindByIdsSpy = MockInstance<typeof middlewareLoader.internalFindByIds>;
  let internalFindByIdsSpy: InternalFindByIdsSpy;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(access, 'executionContext').mockReturnValue({} as any);
    internalFindByIdsSpy = vi.spyOn(middlewareLoader, 'internalFindByIds');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('when organizations array is empty or not found', () => {
    it('should return bundle unchanged when organizations array is empty', async () => {
      internalFindByIdsSpy.mockResolvedValue([]);

      const orgToKeep = createMockOrganization('OrgToKeep');
      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject([orgToKeep.standard_id!])],
      };

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([]),
      });

      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.granted_refs).toContain(orgToKeep.standard_id);
      expect(ext.opencti_upsert_operations).toBeUndefined();
    });

    it('should return bundle unchanged when no matching organizations found in database', async () => {
      internalFindByIdsSpy.mockResolvedValue([]);

      const orgToKeep = createMockOrganization('OrgToKeep');
      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject([orgToKeep.standard_id!])],
      };

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode(['org-not-found']),
      });

      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.granted_refs).toContain(orgToKeep.standard_id);
      expect(ext.opencti_upsert_operations).toBeUndefined();
    });
  });

  describe('when removing granted_refs from single object', () => {
    it('should remove granted_refs and add upsert operation', async () => {
      const orgToRemove = createMockOrganization('OrgToRemove');

      internalFindByIdsSpy.mockResolvedValue([orgToRemove as BasicStoreObject]);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject([orgToRemove.standard_id!])],
      };

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([orgToRemove.id!], false),
      });

      expect(internalFindByIdsSpy).toHaveBeenCalled();
      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];

      // granted_refs should be removed
      expect(ext.granted_refs).toBeUndefined();

      // upsert operation should be added
      if (!ext.opencti_upsert_operations || !ext.opencti_upsert_operations[0]) {
        assert.fail('Upsert operation missing');
      }

      expect(ext.opencti_upsert_operations[0].operation).toBe('remove');
      expect(ext.opencti_upsert_operations[0].key).toBe('objectOrganization');
      expect(ext.opencti_upsert_operations[0].value).toContain(orgToRemove.standard_id);
    });

    it('should handle organizations as objects with label and value properties', async () => {
      const orgToRemove = createMockOrganization('OrgToRemove');

      internalFindByIdsSpy.mockResolvedValue([orgToRemove as BasicStoreObject]);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject([orgToRemove.standard_id!])],
      };

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNodeWithObjectOrgs([{ label: 'Org To Remove', value: orgToRemove.id! }], false),
      });

      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];

      if (!ext.opencti_upsert_operations || !ext.opencti_upsert_operations[0]) {
        assert.fail('Upsert operation missing');
      }

      expect(ext.opencti_upsert_operations[0].operation).toBe('remove');
      expect(ext.opencti_upsert_operations[0].key).toBe('objectOrganization');
      expect(ext.opencti_upsert_operations[0].value).toContain(orgToRemove.standard_id);
    });

    it('should remove multiple organizations with single upsert operation', async () => {
      const orgToRemove1 = createMockOrganization('OrgToRemove1');
      const orgToRemove2 = createMockOrganization('OrgToRemove2');

      internalFindByIdsSpy.mockResolvedValue([
        orgToRemove1 as BasicStoreObject,
        orgToRemove2 as BasicStoreObject,
      ]);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject([orgToRemove1.standard_id!, orgToRemove2.standard_id!])],
      };

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([orgToRemove1.id!, orgToRemove2.id!], false),
      });

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];

      expect(ext.granted_refs).toBeUndefined();

      if (!ext.opencti_upsert_operations || !ext.opencti_upsert_operations[0]) {
        assert.fail('Upsert operation missing');
      }

      expect(ext.opencti_upsert_operations[0].operation).toBe('remove');
      expect(ext.opencti_upsert_operations[0].key).toBe('objectOrganization');
      expect(ext.opencti_upsert_operations[0].value).toContain(orgToRemove1.standard_id);
      expect(ext.opencti_upsert_operations[0].value).toContain(orgToRemove2.standard_id);
    });

    it('should only remove specified organization and keep others in granted_refs', async () => {
      const orgToRemove = createMockOrganization('OrgToRemove');
      const orgToKeep = createMockOrganization('OrgToKeep');

      internalFindByIdsSpy.mockResolvedValue([orgToRemove as BasicStoreObject]);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject([orgToRemove.standard_id!, orgToKeep.standard_id!])],
      };

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([orgToRemove.id!], false),
      });

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];

      if (!ext.opencti_upsert_operations || !ext.opencti_upsert_operations[0]) {
        assert.fail('Upsert operation missing');
      }

      // Only removed org in upsert operation
      expect(ext.opencti_upsert_operations[0].operation).toBe('remove');
      expect(ext.opencti_upsert_operations[0].key).toBe('objectOrganization');
      expect(ext.opencti_upsert_operations[0].value).toContain(orgToRemove.standard_id);
      expect(ext.opencti_upsert_operations[0].value).not.toContain(orgToKeep.standard_id);
    });
  });

  describe('when bundle contains multiple objects', () => {
    // TODO: add test for all=false when cascading of sharing/unshare will be resolved
    it('should only add remove operation to dataInstanceId when all=false', async () => {
      const orgToRemove = createMockOrganization('OrgToRemove');

      internalFindByIdsSpy.mockResolvedValue([orgToRemove as BasicStoreObject]);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [
          createBaseBundleObject([orgToRemove.standard_id!]),
          createSecondObject([orgToRemove.standard_id!]),
        ],
      };

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([orgToRemove.id!], false),
      });

      // Check first object (report) - should have operation
      const reportExt = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      if (!reportExt.opencti_upsert_operations || !reportExt.opencti_upsert_operations[0]) {
        assert.fail('Upsert operation missing on report');
      }
      expect(reportExt.opencti_upsert_operations[0].operation).toBe('remove');

      // Check second object (indicator) - should NOT have operation
      const indicatorExt = result.bundle.objects[1].extensions[STIX_EXT_OCTI];
      expect(indicatorExt.granted_refs).toContain(orgToRemove.standard_id);
      expect(indicatorExt.opencti_upsert_operations).toBeUndefined();
    });
  });

  describe('when bundle has no granted_refs', () => {
    it('should return bundle unchanged when object has no granted_refs', async () => {
      const orgToRemove = createMockOrganization('OrgToRemove');

      internalFindByIdsSpy.mockResolvedValue([orgToRemove as BasicStoreObject]);

      const bundle: StixBundle = {
        ...baseBundle,
        objects: [createBaseBundleObject()],
      };

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor({
        ...baseExecutorParams,
        bundle,
        playbookNode: createPlaybookNode([orgToRemove.id!], false),
      });

      expect(result.output_port).toBe('unmodified');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.granted_refs).toBeUndefined();
    });
  });
});
