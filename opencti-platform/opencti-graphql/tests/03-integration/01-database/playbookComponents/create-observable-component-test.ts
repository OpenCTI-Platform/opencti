import { describe, expect, it } from 'vitest';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import { PLAYBOOK_CREATE_OBSERVABLE_COMPONENT } from '../../../../src/modules/playbook/components/create-observable-component';
import type { StixCyberObject } from '../../../../src/types/stix-2-1-common';
import type { StixRelation } from '../../../../src/types/stix-2-1-sro';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../../src/types/stix-2-1-extensions';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';
import type { StixIndicator } from '../../../../src/modules/indicator/indicator-types';

describe('PLAYBOOK_CREATE_OBSERVABLE_COMPONENT', () => {
  const MALWARE_ID = 'malware--09bd862a-f030-55f2-920a-900c4913d9ff';
  const CAMPAIGN_ID = 'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b';
  const MAIN_INDICATOR_ID = 'indicator--08e64f51-e890-5bec-be34-3344746f1b0c';
  const SECOND_INDICATOR_ID = 'indicator--3e01a7d8-997b-5e7b-a1a3-32f8956ca752';

  const BUNDLE_OBJECTS = [
    testBundleObject<StixIndicator>({
      id: MAIN_INDICATOR_ID,
      type: 'indicator',
      octiExtension: { type: 'Indicator' },
      pattern: "[domain-name:value = 'example.org']",
    }),
    testBundleObject({
      id: MALWARE_ID,
      type: 'Malware',
    }),
    testBundleObject({
      id: CAMPAIGN_ID,
      type: 'Campaign',
    }),
    testBundleObject<StixIndicator>({
      id: SECOND_INDICATOR_ID,
      type: 'indicator',
      octiExtension: { type: 'Indicator' },
      pattern: "[ipv4-addr:value = '8.8.8.8']",
    }),
  ];
  it('should extract observables from indicators for all indicators when applyToElements = all-elements', async () => {
    const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
      mainId: MAIN_INDICATOR_ID,
      bundleObjects: BUNDLE_OBJECTS,
      configuration: {
        applyToElements: playbookBundleElementsToApply.allElements.value,
        wrap_in_container: false,
      },
    }));

    // It should have created 4 new objects in the bundle : 2 relationships, and 2 observables
    expect(result.bundle.objects.length).toEqual(8);

    // Check if the relationships has been created as expected
    const relationships = result.bundle.objects.filter((object) => object.type === 'relationship') as unknown as StixRelation[];
    const relationshipBasedOnMainIndicator = relationships.filter((relationship) => relationship.source_ref === MAIN_INDICATOR_ID);
    const relationshipBasedOnSecondIndicator = relationships.filter((relationship) => relationship.source_ref === SECOND_INDICATOR_ID);
    expect(relationshipBasedOnMainIndicator.length).toEqual(1);
    expect(relationshipBasedOnMainIndicator[0].extensions[STIX_EXT_OCTI].type).toEqual('based-on');
    expect(relationshipBasedOnSecondIndicator.length).toEqual(1);
    expect(relationshipBasedOnSecondIndicator[0].extensions[STIX_EXT_OCTI].type).toEqual('based-on');

    // Check if the observables has been created as expected
    const firstObservable = result.bundle.objects.filter((object) => object.type === 'domain-name') as unknown as StixCyberObject[];
    expect(firstObservable.length).toEqual(1);
    expect(firstObservable[0].extensions[STIX_EXT_OCTI_SCO]?.description).toContain('Simple observable of indicator');

    const secondObservable = result.bundle.objects.filter((object) => object.type === 'ipv4-addr') as unknown as StixCyberObject[];
    expect(secondObservable.length).toEqual(1);
    expect(secondObservable[0].extensions[STIX_EXT_OCTI_SCO]?.description).toContain('Simple observable of indicator');
  });

  it('should extract observables only from the main indicator when applyToElements = only-main', async () => { // changer le titre
    const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
      mainId: MAIN_INDICATOR_ID,
      bundleObjects: BUNDLE_OBJECTS,
      configuration: {
        applyToElements: playbookBundleElementsToApply.onlyMain.value,
        wrap_in_container: false,
      },
    }));

    // It should have created 2 new objects in the bundle : 1 relationships, and 1 observables for main indicator
    expect(result.bundle.objects.length).toEqual(6);

    // Check if the relationship has been created as expected
    const relationships = result.bundle.objects.filter((object) => object.type === 'relationship') as unknown as StixRelation[];
    const relationshipBasedOnMainIndicator = relationships.filter((relationship) => relationship.source_ref === MAIN_INDICATOR_ID);
    const relationshipBasedOnSecondIndicator = relationships.filter((relationship) => relationship.source_ref === SECOND_INDICATOR_ID);
    expect(relationshipBasedOnMainIndicator.length).toEqual(1);
    expect(relationshipBasedOnMainIndicator[0].extensions[STIX_EXT_OCTI].type).toEqual('based-on');
    expect(relationshipBasedOnSecondIndicator.length).toEqual(0);

    // Check if the observable has been created as expected
    const firstObservable = result.bundle.objects.filter((object) => object.type === 'domain-name') as unknown as StixCyberObject[];
    expect(firstObservable.length).toEqual(1);
    expect(firstObservable[0].extensions[STIX_EXT_OCTI_SCO]?.description).toContain('Simple observable of indicator');

    const secondObservable = result.bundle.objects.filter((object) => object.type === 'ipv4-addr') as unknown as StixCyberObject[];
    expect(secondObservable.length).toEqual(0);
  });

  it('should extract observables from all indicators except the main indicator when applyToElements = all-except-main', async () => {
    const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
      mainId: MAIN_INDICATOR_ID,
      bundleObjects: BUNDLE_OBJECTS,
      configuration: {
        applyToElements: playbookBundleElementsToApply.allExceptMain.value,
        wrap_in_container: false,
      },
    }));

    // It should have created 2 new objects in the bundle : 1 relationships, and 1 observables for second indicator
    expect(result.bundle.objects.length).toEqual(6);

    // Check if the relationship has been created as expected
    const relationships = result.bundle.objects.filter((object) => object.type === 'relationship') as unknown as StixRelation[];
    const relationshipBasedOnMainIndicator = relationships.filter((relationship) => relationship.source_ref === MAIN_INDICATOR_ID);
    const relationshipBasedOnSecondIndicator = relationships.filter((relationship) => relationship.source_ref === SECOND_INDICATOR_ID);
    expect(relationshipBasedOnMainIndicator.length).toEqual(0);
    expect(relationshipBasedOnSecondIndicator.length).toEqual(1);
    expect(relationshipBasedOnSecondIndicator[0].extensions[STIX_EXT_OCTI].type).toEqual('based-on');

    // Check if the observable has been created as expected
    const firstObservable = result.bundle.objects.filter((object) => object.type === 'domain-name') as unknown as StixCyberObject[];
    expect(firstObservable.length).toEqual(0);

    const secondObservable = result.bundle.objects.filter((object) => object.type === 'ipv4-addr') as unknown as StixCyberObject[];
    expect(secondObservable.length).toEqual(1);
    expect(secondObservable[0].extensions[STIX_EXT_OCTI_SCO]?.description).toContain('Simple observable of indicator');
  });

  describe('when using filters on bundle containing multiple objects', () => {
    const filterAllIndicators = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["Indicator"],"mode":"or"}],"filterGroups":[]}';
    const filterNotMatching = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["Campaign"],"mode":"or"}],"filterGroups":[]}';

    it('should extract observables from all indicators when applyToElements = "all-elements" and filter matches all indicators', async () => {
      const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
        mainId: MAIN_INDICATOR_ID,
        bundleObjects: BUNDLE_OBJECTS,
        configuration: {
          applyToElements: playbookBundleElementsToApply.allElements.value,
          applyWithFilters: filterAllIndicators,
          wrap_in_container: false,
        },
      }));

      // Both indicators matched: 2 observables + 2 relationships
      expect(result.bundle.objects.length).toEqual(8);

      const relationships = result.bundle.objects.filter((o) => o.type === 'relationship') as unknown as StixRelation[];
      expect(relationships.filter((r) => r.source_ref === MAIN_INDICATOR_ID).length).toEqual(1);
      expect(relationships.filter((r) => r.source_ref === SECOND_INDICATOR_ID).length).toEqual(1);

      expect(result.bundle.objects.filter((o) => o.type === 'domain-name').length).toEqual(1);
      expect(result.bundle.objects.filter((o) => o.type === 'ipv4-addr').length).toEqual(1);
    });

    it('should not extract any observable when applyToElements = "all-elements" and filter does not match any indicator', async () => {
      const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
        mainId: MAIN_INDICATOR_ID,
        bundleObjects: BUNDLE_OBJECTS,
        configuration: {
          applyToElements: playbookBundleElementsToApply.allElements.value,
          applyWithFilters: filterNotMatching,
          wrap_in_container: false,
        },
      }));

      expect(result.output_port).toBe('out');
      expect(result.bundle.objects.length).toEqual(4);

      expect(result.bundle.objects.filter((o) => o.type === 'relationship').length).toEqual(0);
      expect(result.bundle.objects.filter((o) => o.type === 'domain-name').length).toEqual(0);
      expect(result.bundle.objects.filter((o) => o.type === 'ipv4-addr').length).toEqual(0);
    });

    it('should extract observables only from main indicator when applyToElements = "only-main" and filter matches all indicators', async () => {
      const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
        mainId: MAIN_INDICATOR_ID,
        bundleObjects: BUNDLE_OBJECTS,
        configuration: {
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
          applyWithFilters: filterAllIndicators,
          wrap_in_container: false,
        },
      }));

      // applyToElements restricts to main only, filter matches both but scope wins
      expect(result.bundle.objects.length).toEqual(6);

      const relationships = result.bundle.objects.filter((o) => o.type === 'relationship') as unknown as StixRelation[];
      expect(relationships.filter((r) => r.source_ref === MAIN_INDICATOR_ID).length).toEqual(1);
      expect(relationships.filter((r) => r.source_ref === SECOND_INDICATOR_ID).length).toEqual(0);

      expect(result.bundle.objects.filter((o) => o.type === 'domain-name').length).toEqual(1);
      expect(result.bundle.objects.filter((o) => o.type === 'ipv4-addr').length).toEqual(0);
    });

    it('should not extract any observable when applyToElements = "only-main" and filter does not match any indicator', async () => {
      const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
        mainId: MAIN_INDICATOR_ID,
        bundleObjects: BUNDLE_OBJECTS,
        configuration: {
          applyToElements: playbookBundleElementsToApply.onlyMain.value,
          applyWithFilters: filterNotMatching,
          wrap_in_container: false,
        },
      }));

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle.objects.length).toEqual(4);

      expect(result.bundle.objects.filter((o) => o.type === 'relationship').length).toEqual(0);
      expect(result.bundle.objects.filter((o) => o.type === 'domain-name').length).toEqual(0);
      expect(result.bundle.objects.filter((o) => o.type === 'ipv4-addr').length).toEqual(0);
    });

    it('should extract observables only from second indicator when applyToElements = "all-except-main" and filter matches all indicators', async () => {
      const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
        mainId: MAIN_INDICATOR_ID,
        bundleObjects: BUNDLE_OBJECTS,
        configuration: {
          applyToElements: playbookBundleElementsToApply.allExceptMain.value,
          applyWithFilters: filterAllIndicators,
          wrap_in_container: false,
        },
      }));

      // applyToElements excludes main, filter matches both: only second indicator processed
      expect(result.bundle.objects.length).toEqual(6);

      const relationships = result.bundle.objects.filter((o) => o.type === 'relationship') as unknown as StixRelation[];
      expect(relationships.filter((r) => r.source_ref === MAIN_INDICATOR_ID).length).toEqual(0);
      expect(relationships.filter((r) => r.source_ref === SECOND_INDICATOR_ID).length).toEqual(1);

      expect(result.bundle.objects.filter((o) => o.type === 'domain-name').length).toEqual(0);
      expect(result.bundle.objects.filter((o) => o.type === 'ipv4-addr').length).toEqual(1);
    });

    it('should not extract any observable when applyToElements = "all-except-main" and filter does not match any indicator', async () => {
      const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
        mainId: MAIN_INDICATOR_ID,
        bundleObjects: BUNDLE_OBJECTS,
        configuration: {
          applyToElements: playbookBundleElementsToApply.allExceptMain.value,
          applyWithFilters: filterNotMatching,
          wrap_in_container: false,
        },
      }));

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle.objects.length).toEqual(4);

      expect(result.bundle.objects.filter((o) => o.type === 'relationship').length).toEqual(0);
      expect(result.bundle.objects.filter((o) => o.type === 'domain-name').length).toEqual(0);
      expect(result.bundle.objects.filter((o) => o.type === 'ipv4-addr').length).toEqual(0);
    });

    it('should extract observables only from filtered indicators when applyToElements = "all-elements" and filter matches partial bundle', async () => {
      const THIRD_INDICATOR_ID = 'indicator--7a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d';
      const bundleObjects = [
        testBundleObject<StixIndicator>({
          id: MAIN_INDICATOR_ID,
          type: 'indicator',
          octiExtension: { type: 'Indicator' },
          pattern: "[domain-name:value = 'example.org']",
        }),
        testBundleObject<StixIndicator>({
          id: SECOND_INDICATOR_ID,
          type: 'indicator',
          octiExtension: { type: 'Indicator' },
          pattern: "[ipv4-addr:value = '8.8.8.8']",
        }),
        testBundleObject({
          id: THIRD_INDICATOR_ID,
          type: 'Malware',
        }),
      ];

      const filterIndicator = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["Indicator"],"mode":"or"}],"filterGroups":[]}';

      const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
        mainId: MAIN_INDICATOR_ID,
        bundleObjects,
        configuration: {
          applyToElements: playbookBundleElementsToApply.allElements.value,
          applyWithFilters: filterIndicator,
          wrap_in_container: false,
        },
      }));

      // Only the 2 indicators matched the filter, Malware is ignored
      // 2 observables + 2 relationships added = 3 original + 4 new = 7
      expect(result.output_port).toBe('out');
      expect(result.bundle.objects.length).toEqual(7);

      const relationships = result.bundle.objects.filter((o) => o.type === 'relationship') as unknown as StixRelation[];
      expect(relationships.filter((r) => r.source_ref === MAIN_INDICATOR_ID).length).toEqual(1);
      expect(relationships.filter((r) => r.source_ref === SECOND_INDICATOR_ID).length).toEqual(1);

      // Malware did not produce any observable
      expect(result.bundle.objects.filter((o) => o.type === 'domain-name').length).toEqual(1);
      expect(result.bundle.objects.filter((o) => o.type === 'ipv4-addr').length).toEqual(1);
    });

    it('should extract observables only from filtered indicators except main when applyToElements = "all-except-main" and filter matches partial bundle', async () => {
      const THIRD_INDICATOR_ID = 'indicator--7a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d';
      const bundleObjects = [
        testBundleObject<StixIndicator>({
          id: MAIN_INDICATOR_ID,
          type: 'indicator',
          octiExtension: { type: 'Indicator' },
          pattern: "[domain-name:value = 'example.org']",
        }),
        testBundleObject<StixIndicator>({
          id: SECOND_INDICATOR_ID,
          type: 'indicator',
          octiExtension: { type: 'Indicator' },
          pattern: "[ipv4-addr:value = '8.8.8.8']",
        }),
        testBundleObject({
          id: THIRD_INDICATOR_ID,
          type: 'Malware',
        }),
      ];

      const filterIndicator = '{"mode":"and","filters":[{"key":["entity_type"],"operator":"eq","values":["Indicator"],"mode":"or"}],"filterGroups":[]}';

      const result = await PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.executor(testExecutor({
        mainId: MAIN_INDICATOR_ID,
        bundleObjects,
        configuration: {
          applyToElements: playbookBundleElementsToApply.allExceptMain.value,
          applyWithFilters: filterIndicator,
          wrap_in_container: false,
        },
      }));

      // Filter matches both indicators but applyToElements excludes main:
      // only SECOND_INDICATOR processed, Malware ignored
      // 1 observable + 1 relationship added = 3 original + 2 new = 5
      expect(result.output_port).toBe('out');
      expect(result.bundle.objects.length).toEqual(5);

      const relationships = result.bundle.objects.filter((o) => o.type === 'relationship') as unknown as StixRelation[];
      expect(relationships.filter((r) => r.source_ref === MAIN_INDICATOR_ID).length).toEqual(0);
      expect(relationships.filter((r) => r.source_ref === SECOND_INDICATOR_ID).length).toEqual(1);

      // Main indicator did not produce any observable
      expect(result.bundle.objects.filter((o) => o.type === 'domain-name').length).toEqual(0);
      // Second indicator produced its observable
      expect(result.bundle.objects.filter((o) => o.type === 'ipv4-addr').length).toEqual(1);
      // Malware did not produce any observable
      expect(result.bundle.objects.filter((o) => o.type === 'Malware').length).toEqual(1);
    });
  });
});
