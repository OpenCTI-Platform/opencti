import { describe, expect, it, vi, afterEach, beforeEach, type MockInstance } from 'vitest';
import type { StixBundle, StixObject, StixOpenctiExtension } from '../../../../src/types/stix-2-1-common';
import type { BasicStoreObject } from '../../../../src/types/store';
import type { StixId } from '../../../../src/types/stix-2-0-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { generateStandardId } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../../src/modules/organization/organization-types';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import * as access from '../../../../src/utils/access';
import { PLAYBOOK_SHARING_COMPONENT } from '../../../../src/modules/playbook/components/sharing-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';

describe('PLAYBOOK_SHARING_COMPONENT', () => {
  const MAIN_REPORT_ID = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';

  const inputBundleObjects = () => [
    testBundleObject({ id: MAIN_REPORT_ID, type: 'report' }),
  ];

  const createMockOrganization = (name: string): Partial<BasicStoreObject> => ({
    id: `org-internal-${name}`,
    standard_id: generateStandardId(ENTITY_TYPE_IDENTITY_ORGANIZATION, { name }) as StixId,
  });

  const getExtension = (bundle: StixBundle, objectId: string): StixOpenctiExtension => {
    const obj = bundle.objects.find((o) => o.id === objectId) as StixObject;
    return obj.extensions![STIX_EXT_OCTI] as StixOpenctiExtension;
  };

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
      const result = await PLAYBOOK_SHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: inputBundleObjects(),
          configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, organizations: [] },
        }),
      );

      expect(result.output_port).toBe('out');
      expect(getExtension(result.bundle, MAIN_REPORT_ID).granted_refs).toBeUndefined();
    });

    it('should return bundle unchanged when no matching organizations found in database', async () => {
      const result = await PLAYBOOK_SHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: inputBundleObjects(),
          configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, organizations: ['org-not-found'] },
        }),
      );

      expect(result.output_port).toBe('out');
      expect(getExtension(result.bundle, MAIN_REPORT_ID).granted_refs).toBeUndefined();
    });
  });

  describe('when adding granted_refs to single object', () => {
    it('should add granted_refs to dataInstanceId object', async () => {
      const mockOrg = createMockOrganization('TestOrg');

      internalFindByIdsSpy.mockResolvedValue([mockOrg as BasicStoreObject]);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: inputBundleObjects(),
          configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, organizations: [mockOrg.id!] },
        }),
      );

      expect(internalFindByIdsSpy).toHaveBeenCalled();
      expect(result.output_port).toBe('out');

      const ext = getExtension(result.bundle, MAIN_REPORT_ID);
      expect(ext.granted_refs).toBeDefined();
      expect(ext.granted_refs).toContain(mockOrg.standard_id);
      expect(ext.granted_refs).toHaveLength(1);
    });

    it('should handle organizations as objects with label and value properties', async () => {
      const mockOrg = createMockOrganization('TestOrg');

      internalFindByIdsSpy.mockResolvedValue([mockOrg as BasicStoreObject]);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: inputBundleObjects(),
          configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, organizations: [{ label: 'Test Organization', value: mockOrg.id! }] },
        }),
      );

      expect(result.output_port).toBe('out');

      const ext = getExtension(result.bundle, MAIN_REPORT_ID);
      expect(ext.granted_refs).toContain(mockOrg.standard_id);
    });

    it('should add multiple organizations to granted_refs', async () => {
      const mockOrg1 = createMockOrganization('Org1');
      const mockOrg2 = createMockOrganization('Org2');

      internalFindByIdsSpy.mockResolvedValue([
        mockOrg1 as BasicStoreObject,
        mockOrg2 as BasicStoreObject,
      ]);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: inputBundleObjects(),
          configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, organizations: [mockOrg1.id!, mockOrg2.id!] },
        }),
      );

      const ext = getExtension(result.bundle, MAIN_REPORT_ID);
      expect(ext.granted_refs).toContain(mockOrg1.standard_id);
      expect(ext.granted_refs).toContain(mockOrg2.standard_id);
      expect(ext.granted_refs).toHaveLength(2);
    });

    it('should append to existing granted_refs', async () => {
      const existingOrg = createMockOrganization('ExistingOrg');
      const newOrg = createMockOrganization('NewOrg');
      const inputBundleObjectsWithRefs = [
        testBundleObject({ id: MAIN_REPORT_ID, type: 'report', octiExtension: { granted_refs: [existingOrg.standard_id!] } }),
      ];

      internalFindByIdsSpy.mockResolvedValue([newOrg as BasicStoreObject]);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: inputBundleObjectsWithRefs,
          configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, organizations: [newOrg.id!] },
        }),
      );

      const ext = getExtension(result.bundle, MAIN_REPORT_ID);
      expect(ext.granted_refs).toContain(existingOrg.standard_id);
      expect(ext.granted_refs).toContain(newOrg.standard_id);
      expect(ext.granted_refs).toHaveLength(2);
    });
  });

  describe('when bundle contains multiple objects', () => {
    const MALWARE_ID = 'malware--09bd862a-f030-55f2-920a-900c4913d9ff';
    const CAMPAIGN_ID = 'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b';

    const inputBundleMultipleObjects = () => [
      testBundleObject({
        id: MAIN_REPORT_ID,
        type: 'report',
      }),
      testBundleObject({
        id: MALWARE_ID,
        type: 'Malware',
      }),
      testBundleObject({
        id: CAMPAIGN_ID,
        type: 'Campaign',
      }),
    ];

    it('should add granted_refs to all objects when elementsToApply=all-elements', async () => {
      const mockOrg = createMockOrganization('TestOrg');

      internalFindByIdsSpy.mockResolvedValue([mockOrg as BasicStoreObject]);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: inputBundleMultipleObjects(),
          configuration: { applyToElements: playbookBundleElementsToApply.allElements.value, organizations: [mockOrg.id!] },
        }),
      );

      const mainElementExtension = getExtension(result.bundle, MAIN_REPORT_ID);
      expect(mainElementExtension.granted_refs).toContain(mockOrg.standard_id);

      const secondElementExtension = getExtension(result.bundle, MALWARE_ID);
      expect(secondElementExtension.granted_refs).toContain(mockOrg.standard_id);

      const thirdElementExtension = getExtension(result.bundle, MALWARE_ID);
      expect(thirdElementExtension.granted_refs).toContain(mockOrg.standard_id);
    });

    it('should add granted_refs to only main when option is only main', async () => {
      const mockOrg = createMockOrganization('TestOrg');

      internalFindByIdsSpy.mockResolvedValue([mockOrg as BasicStoreObject]);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: inputBundleMultipleObjects(),
          configuration: { applyToElements: playbookBundleElementsToApply.onlyMain.value, organizations: [mockOrg.id!] },
        }),
      );

      const mainElementExtension = getExtension(result.bundle, MAIN_REPORT_ID);
      expect(mainElementExtension.granted_refs).toContain(mockOrg.standard_id);

      const secondElementExtension = getExtension(result.bundle, MALWARE_ID);
      expect(secondElementExtension.granted_refs).not.toBeDefined();

      const thirdElementExtension = getExtension(result.bundle, MALWARE_ID);
      expect(thirdElementExtension.granted_refs).not.toBeDefined();
    });

    it('should add granted_refs to all objects except main when all except main option chosen', async () => {
      const mockOrg = createMockOrganization('TestOrg');

      internalFindByIdsSpy.mockResolvedValue([mockOrg as BasicStoreObject]);

      const result = await PLAYBOOK_SHARING_COMPONENT.executor(
        testExecutor({
          mainId: MAIN_REPORT_ID,
          bundleObjects: inputBundleMultipleObjects(),
          configuration: { applyToElements: playbookBundleElementsToApply.allExceptMain.value, organizations: [mockOrg.id!] },
        }),
      );

      const mainElementExtension = getExtension(result.bundle, MAIN_REPORT_ID);
      expect(mainElementExtension.granted_refs).not.toBeDefined();

      const secondElementExtension = getExtension(result.bundle, MALWARE_ID);
      expect(secondElementExtension.granted_refs).toContain(mockOrg.standard_id);

      const thirdElementExtension = getExtension(result.bundle, MALWARE_ID);
      expect(thirdElementExtension.granted_refs).toContain(mockOrg.standard_id);
    });
  });
});
