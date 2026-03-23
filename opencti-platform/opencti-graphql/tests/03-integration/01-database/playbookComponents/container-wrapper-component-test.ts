import { describe, expect, it } from 'vitest';
import { PLAYBOOK_CONTAINER_WRAPPER_COMPONENT, type ContainerWrapperConfiguration } from '../../../../src/modules/playbook/components/container-wrapper-component';
import type { StixContainer, StixIncident } from '../../../../src/types/stix-2-1-sdo';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import type { StixRelation } from '../../../../src/types/stix-2-1-sro';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

const componentConfig = (config: Partial<ContainerWrapperConfiguration>) => {
  return {
    applyToElements: playbookBundleElementsToApply.onlyMain.value,
    copyFiles: false,
    caseTemplates: [],
    newContainer: true,
    container_type: 'Report',
    ...config,
  };
};

describe('PLAYBOOK_CONTAINER_WRAPPER_COMPONENT', () => {
  const MALWARE_ID = 'malware--09bd862a-f030-55f2-920a-900c4913d9ff';
  const CAMPAIGN_ID = 'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b';
  const REL_ID = 'relationship--08e64f51-e890-5bec-be34-3344746f1b0c';

  const BUNDLE_OBJECTS = [
    testBundleObject({
      id: MALWARE_ID,
      type: 'Malware',
    }),
    testBundleObject({
      id: CAMPAIGN_ID,
      type: 'Campaign',
    }),
    testBundleObject<StixRelation>({
      id: REL_ID,
      type: 'Relationship',
      relationship_type: 'related-to',
      source_ref: MALWARE_ID,
      target_ref: CAMPAIGN_ID,
    }),
  ];

  it('should wrap only main element in Container', async () => {
    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor(testExecutor({
      mainId: MALWARE_ID,
      bundleObjects: BUNDLE_OBJECTS,
      configuration: componentConfig({
        applyToElements: playbookBundleElementsToApply.onlyMain.value,
      }),
    }));

    const reportResult = result.bundle.objects
      .find((element) => element.type === 'report') as StixContainer;
    expect(reportResult.object_refs).toEqual([MALWARE_ID]);
  });

  it('should wrap all elements in Container', async () => {
    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor(testExecutor({
      mainId: MALWARE_ID,
      bundleObjects: BUNDLE_OBJECTS,
      configuration: componentConfig({
        applyToElements: playbookBundleElementsToApply.allElements.value,
      }),
    }));

    const reportResult = result.bundle.objects
      .find((element) => element.type === 'report') as StixContainer;
    expect(reportResult.object_refs).toEqual([MALWARE_ID, CAMPAIGN_ID, REL_ID]);
  });

  it('should wrap all elements in Container except main element', async () => {
    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor(testExecutor({
      mainId: MALWARE_ID,
      bundleObjects: BUNDLE_OBJECTS,
      configuration: componentConfig({
        applyToElements: playbookBundleElementsToApply.allExceptMain.value,
      }),
    }));

    const reportResult = result.bundle.objects
      .find((element) => element.type === 'report') as StixContainer;
    expect(reportResult.object_refs).toEqual([CAMPAIGN_ID, REL_ID]);
  });

  it('should wrap Incident in Incident Response container', async () => {
    const INCIDENT_ID = 'incident--c6c2b96d-fe70-5099-a033-87cbfe2d6be2';

    const incidentBundleObject = testBundleObject<StixIncident>({
      id: INCIDENT_ID,
      type: 'Incident',
      revoked: false,
      confidence: 100,
      lang: 'en',
      name: 'Test Incident',
      description: '',
      external_references: [],
      octiExtension: {
        created_at: '2025-02-25T08:13:45.863Z',
        updated_at: '2025-05-09T10:03:11.288Z',
        is_inferred: false,
      },
    });

    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor(testExecutor({
      mainId: INCIDENT_ID,
      bundleObjects: [incidentBundleObject],
      configuration: {
        container_type: 'Case-Incident',
        applyToElements: playbookBundleElementsToApply.onlyMain.value,
        caseTemplates: [],
        copyFiles: false,
        newContainer: false,
      },
    }));
    expect(result.bundle.objects.length).toEqual(2);
    expect(result.bundle.objects[1].extensions[STIX_EXT_OCTI].type).toEqual('Case-Incident');
    expect(result.bundle.objects[1].object_refs).toContain(INCIDENT_ID);
  });
});
