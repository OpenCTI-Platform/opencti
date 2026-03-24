import { describe, expect, it } from 'vitest';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../../src/schema/stixDomainObject';
import { PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT } from '../../../../src/modules/playbook/components/remove-access-restrictions-component';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../../../../src/modules/grouping/grouping-types';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';

describe('PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT', () => {
  const REPORT_ID = 'report--5f78a68b-2c4d-5e6f-beaa-7b987b0e7165';
  const GROUPING_ID = 'grouping--09bd862a-f030-55f2-920a-900c4913d9ff';

  const access = [{
    id: 'user-uuid-1',
    access_right: 'admin',
    groups_restriction_ids: [],
  }];

  describe('Bundle scope', () => {
    const BUNDLE_OBJECTS = () => [
      testBundleObject({
        id: REPORT_ID,
        type: ENTITY_TYPE_CONTAINER_REPORT,
        octiExtension: {
          authorized_members: access,
        },
      }),
      testBundleObject({
        id: GROUPING_ID,
        type: ENTITY_TYPE_CONTAINER_GROUPING,
        octiExtension: {
          authorized_members: access,
        },
      }),
    ];

    it('should remove authorized_members only on main element', async () => {
      const result = await PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: {
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
        },
      }));

      expect(result.output_port).toBe('out');
      const reportResult = result.bundle.objects.find((o) => o.id === REPORT_ID);
      const reportExtension = reportResult?.extensions[STIX_EXT_OCTI];
      const groupingResult = result.bundle.objects.find((o) => o.id === GROUPING_ID);
      const groupingExtension = groupingResult?.extensions[STIX_EXT_OCTI];
      expect(reportExtension?.opencti_upsert_operations?.length).toEqual(1);
      expect(reportExtension?.opencti_upsert_operations?.[0].key).toEqual('restricted_members');
      expect(reportExtension?.opencti_upsert_operations?.[0].value).toEqual([]);
      expect(groupingExtension?.opencti_upsert_operations).toBeUndefined();
    });

    it('should remove authorized_members of all objects in the bundle', async () => {
      const result = await PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: {
          applyToElements: playbookBundleElementsToApply.allElements.value,
        },
      }));

      expect(result.output_port).toBe('out');
      const reportResult = result.bundle.objects.find((o) => o.id === REPORT_ID);
      const reportExtension = reportResult?.extensions[STIX_EXT_OCTI];
      const groupingResult = result.bundle.objects.find((o) => o.id === GROUPING_ID);
      const groupingExtension = groupingResult?.extensions[STIX_EXT_OCTI];
      expect(reportExtension?.opencti_upsert_operations?.length).toEqual(1);
      expect(reportExtension?.opencti_upsert_operations?.[0].key).toEqual('restricted_members');
      expect(reportExtension?.opencti_upsert_operations?.[0].value).toEqual([]);
      expect(groupingExtension?.opencti_upsert_operations?.length).toEqual(1);
      expect(groupingExtension?.opencti_upsert_operations?.[0].key).toEqual('restricted_members');
      expect(groupingExtension?.opencti_upsert_operations?.[0].value).toEqual([]);
    });

    it('should remove authorized_members of all objects except main in the bundle', async () => {
      const result = await PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
        mainId: REPORT_ID,
        bundleObjects: BUNDLE_OBJECTS(),
        configuration: {
          applyToElements: playbookBundleElementsToApply.allExceptMain.value,
        },
      }));

      expect(result.output_port).toBe('out');
      const reportResult = result.bundle.objects.find((o) => o.id === REPORT_ID);
      const reportExtension = reportResult?.extensions[STIX_EXT_OCTI];
      const groupingResult = result.bundle.objects.find((o) => o.id === GROUPING_ID);
      const groupingExtension = groupingResult?.extensions[STIX_EXT_OCTI];
      expect(reportExtension?.opencti_upsert_operations).toBeUndefined();
      expect(groupingExtension?.opencti_upsert_operations?.length).toEqual(1);
      expect(groupingExtension?.opencti_upsert_operations?.[0].key).toEqual('restricted_members');
      expect(groupingExtension?.opencti_upsert_operations?.[0].value).toEqual([]);
    });
  });

  it('should not modify bundle when dataInstanceId does not match any object', async () => {
    const result = await PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
      mainId: REPORT_ID,
      bundleObjects: [testBundleObject({
        id: 'report--wrong-id',
        type: ENTITY_TYPE_CONTAINER_REPORT,
        octiExtension: {
          authorized_members: access,
        },
      })],
      configuration: {
        applyToElements: playbookBundleElementsToApply.onlyMain.value,
      },
    }));

    expect(result.output_port).toBe('out');
    result.bundle.objects.forEach((object) => {
      const extension = object.extensions[STIX_EXT_OCTI];
      expect(extension?.opencti_upsert_operations).toBeUndefined();
    });
  });

  it('should handle empty bundle', async () => {
    const result = await PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.executor(testExecutor({
      mainId: REPORT_ID,
      bundleObjects: [],
      configuration: {
        applyToElements: playbookBundleElementsToApply.onlyMain.value,
      },
    }));

    expect(result.output_port).toBe('out');
    expect(result.bundle.objects).toEqual([]);
  });
});
