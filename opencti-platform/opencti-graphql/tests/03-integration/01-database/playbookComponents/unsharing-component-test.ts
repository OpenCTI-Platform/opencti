import { assert, describe, expect, it, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import type { BasicStoreObject } from '../../../../src/types/store';
import type { StixId } from '../../../../src/types/stix-2-0-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { generateStandardId } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../../src/schema/stixDomainObject';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import * as access from '../../../../src/utils/access';
import { PLAYBOOK_UNSHARING_COMPONENT } from '../../../../src/modules/playbook/components/unsharing-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';

describe('PLAYBOOK_UNSHARING_COMPONENT', () => {
  const MAIN_REPORT_ID = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
  const SECOND_OBJECT_ID = 'indicator--second-object';

  const inputBundleBaseObject = (grantedRefs?: StixId[]) => [
    testBundleObject({
      id: MAIN_REPORT_ID,
      type: ENTITY_TYPE_CONTAINER_REPORT,
      octiExtension: { granted_refs: grantedRefs },
    }),
  ];

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

      const bundleInputObject = inputBundleBaseObject([orgToKeep.standard_id!]);

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObject,
          configuration: {
            organizations: [],
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
          },
        }));

      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.granted_refs).toContain(orgToKeep.standard_id);
      expect(ext.opencti_upsert_operations).toBeUndefined();
    });

    it('should return bundle unchanged when no matching organizations found in database', async () => {
      internalFindByIdsSpy.mockResolvedValue([]);

      const orgToKeep = createMockOrganization('OrgToKeep');

      const bundleInputObject = inputBundleBaseObject([orgToKeep.standard_id!]);

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObject,
          configuration: {
            organizations: ['org-not-found'],
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
          },
        }));

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

      const bundleInputObject = inputBundleBaseObject([orgToRemove.standard_id!]);

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObject,
          configuration: {
            organizations: [orgToRemove.id!],
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
          },
        }));

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

      const bundleInputObject = inputBundleBaseObject([orgToRemove.standard_id!]);

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObject,
          configuration: {
            organizations: [{ label: 'Org To Remove', value: orgToRemove.id! }],
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
          },
        }));

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

      const bundleInputObject = inputBundleBaseObject([orgToRemove1.standard_id!, orgToRemove2.standard_id!]);

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObject,
          configuration: {
            organizations: [orgToRemove1.id!, orgToRemove2.id!],
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
          },
        }));

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

      const bundleInputObject = inputBundleBaseObject([orgToRemove.standard_id!, orgToKeep.standard_id!]);

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObject,
          configuration: {
            organizations: [orgToRemove.id!],
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
          },
        }));

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
    // TODO: add test for applyToElements equals only-main when cascading of sharing/unshare will be resolved
    it('should only add remove operation to dataInstanceId when applyToElements equals only-main', async () => {
      const orgToRemove = createMockOrganization('OrgToRemove');

      internalFindByIdsSpy.mockResolvedValue([orgToRemove as BasicStoreObject]);

      const bundleInputObjects = [
        testBundleObject({
          id: MAIN_REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: { granted_refs: [orgToRemove.standard_id!] },
        }),
        testBundleObject({
          id: SECOND_OBJECT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: { granted_refs: [orgToRemove.standard_id!] },
        })];

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObjects,
          configuration: {
            organizations: [orgToRemove.id!],
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
          },
        }));

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

    it('should add remove operation on all objects when applyToElements equals all-elements', async () => {
      const orgToRemove = createMockOrganization('OrgToRemove');

      internalFindByIdsSpy.mockResolvedValue([orgToRemove as BasicStoreObject]);

      const bundleInputObjects = [
        testBundleObject({
          id: MAIN_REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: { granted_refs: [orgToRemove.standard_id!] },
        }),
        testBundleObject({
          id: SECOND_OBJECT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: { granted_refs: [orgToRemove.standard_id!] },
        })];

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObjects,
          configuration: {
            organizations: [orgToRemove.id!],
            applyToElements: playbookBundleElementsToApply.allElements.value,
          },
        }));

      const reportExt = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      const indicatorExt = result.bundle.objects[1].extensions[STIX_EXT_OCTI];
      if (
        !reportExt.opencti_upsert_operations
        || !reportExt.opencti_upsert_operations[0]
        || !indicatorExt.opencti_upsert_operations
        || !indicatorExt.opencti_upsert_operations[0]
      ) {
        assert.fail('Upsert operation missing on report');
      }
      // Check first object (report) - should have operation
      expect(reportExt.opencti_upsert_operations[0].operation).toBe('remove');

      // Check second object (indicator) - should also have operation
      expect(indicatorExt.opencti_upsert_operations[0].operation).toBe('remove');
    });

    it('should add remove operation to all objects except main when applyToElements equals only-except-main', async () => {
      const orgToRemove = createMockOrganization('OrgToRemove');

      internalFindByIdsSpy.mockResolvedValue([orgToRemove as BasicStoreObject]);

      const bundleInputObjects = [
        testBundleObject({
          id: MAIN_REPORT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: { granted_refs: [orgToRemove.standard_id!] },
        }),
        testBundleObject({
          id: SECOND_OBJECT_ID,
          type: ENTITY_TYPE_CONTAINER_REPORT,
          octiExtension: { granted_refs: [orgToRemove.standard_id!] },
        })];

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObjects,
          configuration: {
            organizations: [orgToRemove.id!],
            applyToElements: playbookBundleElementsToApply.allExceptMain.value,
          },
        }));

      // Check first object (report) - should NOT have operation
      const reportExt = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(reportExt.granted_refs).toContain(orgToRemove.standard_id);
      expect(reportExt.opencti_upsert_operations).toBeUndefined();

      // Check second object (indicator) - should have operation
      const indicatorExt = result.bundle.objects[1].extensions[STIX_EXT_OCTI];
      if (!indicatorExt.opencti_upsert_operations || !indicatorExt.opencti_upsert_operations[0]
      ) {
        assert.fail('Upsert operation missing on report');
      }
      expect(indicatorExt.opencti_upsert_operations[0].operation).toBe('remove');
    });
  });

  describe('when bundle has no granted_refs', () => {
    it('should return bundle unchanged when object has no granted_refs', async () => {
      const orgToRemove = createMockOrganization('OrgToRemove');

      internalFindByIdsSpy.mockResolvedValue([orgToRemove as BasicStoreObject]);

      const bundleInputObject = inputBundleBaseObject();

      const result = await PLAYBOOK_UNSHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: bundleInputObject,
          configuration: {
            organizations: [orgToRemove.id!],
            applyToElements: playbookBundleElementsToApply.onlyMain.value,
          },
        }));

      expect(result.output_port).toBe('out');

      const ext = result.bundle.objects[0].extensions[STIX_EXT_OCTI];
      expect(ext.granted_refs).toBeUndefined();
    });
  });
});
