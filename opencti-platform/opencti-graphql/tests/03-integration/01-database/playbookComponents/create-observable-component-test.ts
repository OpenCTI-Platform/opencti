import { describe, expect, it } from 'vitest';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import { PLAYBOOK_CREATE_OBSERVABLE_COMPONENT } from '../../../../src/modules/playbook/components/create-observable-component';
import type { StixCyberObject } from '../../../../src/types/stix-2-1-common';
import type { StixRelation } from '../../../../src/types/stix-2-1-sro';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../../../src/types/stix-2-1-extensions';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';

describe('PLAYBOOK_CREATE_OBSERVABLE_COMPONENT', () => {
  const MALWARE_ID = 'malware--09bd862a-f030-55f2-920a-900c4913d9ff';
  const CAMPAIGN_ID = 'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b';
  const MAIN_INDICATOR_ID = 'indicator--08e64f51-e890-5bec-be34-3344746f1b0c';
  const SECOND_INDICATOR_ID = 'indicator--3e01a7d8-997b-5e7b-a1a3-32f8956ca752';

  const BUNDLE_OBJECTS = [
    testBundleObject({
      id: MAIN_INDICATOR_ID,
      type: 'indicator',
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
    testBundleObject({
      id: SECOND_INDICATOR_ID,
      type: 'indicator',
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
});
