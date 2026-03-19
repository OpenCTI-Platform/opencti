import { describe, expect, it } from 'vitest';
import { PLAYBOOK_CONTAINER_WRAPPER_COMPONENT, type ContainerWrapperConfiguration } from '../../../../src/modules/playbook/components/container-wrapper-component';
import type { StixContainer } from '../../../../src/types/stix-2-1-sdo';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import type { StixRelation } from '../../../../src/types/stix-2-1-sro';
import { playbookBundleElementsToApply } from '../../../../src/modules/playbook/playbook-types';
import type { StixBundle } from '../../../../src/types/stix-2-1-common';
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

    const incidentBundleObject = testBundleObject({
      id: INCIDENT_ID,
      type: 'Incident',
      octiExtension: {
        created_at: '2025-02-25T08:13:45.863Z',
        updated_at: '2025-05-09T10:03:11.288Z',
        is_inferred: false,
        granted_refs: ['34a50091-acd7-5b12-88f4-086155cf40d4'],
        creator_ids: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'],
      } as unknown as StixRelation });

    const container_wrapper_component_bundle: StixBundle = {
      id: '1c775f39-6cea-4b14-92f8-7843d2443af7',
      spec_version: '2.1',
      type: 'bundle',
      objects: [
        {
          ...incidentBundleObject,
          external_references: [
            {
              source_name: 'upload_file',
              external_id: 'upload_file_example.pdf',
            },
          ],
          severity: 'high',
          revoked: false,
          confidence: 100,
          lang: 'en',
          name: 'Test Incident',
          description: '',

        },
      ],
    } as unknown as StixBundle;
    const dataInstanceId = INCIDENT_ID;
    const playbookNode = {
      id: 'fb1d0a03-eb72-426a-ab48-505a2ca399d0',
      name: 'Container wrapper',
      position: {
        x: 0,
        y: 150,
      },
      component_id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
      configuration: {
        container_type: 'Case-Incident',
        applyToElements: playbookBundleElementsToApply.onlyMain.value,
        copyFiles: false,
        newContainer: false,
        caseTemplates: [],
      },
    };
    const expectedBundleToIngest = {
      id: '1c775f39-6cea-4b14-92f8-7843d2443af7',
      spec_version: '2.1',
      type: 'bundle',
      objects: [
        {
          id: INCIDENT_ID,
          spec_version: '2.1',
          type: 'incident',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'new-sdo',
              id: '25cab01c-46be-48ed-832f-857d35347f15',
              type: 'Incident',
              is_inferred: false,
              creator_ids: [
                '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
              ],
            },
          },
          created: '2025-02-25T08:13:45.851Z',
          modified: '2025-05-09T10:03:11.288Z',
          revoked: false,
          confidence: 100,
          lang: 'en',
          name: 'Test Incident',
          description: '',
        },
        {
          id: 'case-incident--b52ce838-2972-51ea-a538-005b36189e19',
          spec_version: '2.1',
          type: 'case-incident',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'new-sdo',
              id: 'fe30c5e6-d68d-4cbe-a318-a046abaaacc8',
              type: 'Case-Incident',
            },
          },
          created: '2025-02-25T08:13:45.863Z',
          name: 'Test Incident',
          object_refs: [
            INCIDENT_ID,
          ],
        },
      ],
    } as unknown as StixBundle;

    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor({
      dataInstanceId,
      eventId: '',
      executionId: '',
      playbookId: '',
      previousPlaybookNodeId: '',
      previousStepBundle: container_wrapper_component_bundle,
      playbookNode,
      bundle: container_wrapper_component_bundle,
    });
    expect(result.bundle.objects.length).toEqual(2);
    expect(result.bundle.objects[1].id).toEqual(expectedBundleToIngest.objects[1].id);
    expect(result.bundle.objects[1].extensions[STIX_EXT_OCTI].type).toEqual(expectedBundleToIngest.objects[1].extensions[STIX_EXT_OCTI].type);
  });
});
