import { describe, expect, it } from 'vitest';
import { PLAYBOOK_CONTAINER_WRAPPER_COMPONENT, type ContainerWrapperConfiguration } from '../../../../src/modules/playbook/components/container-wrapper-component';
import type { StixContainer } from '../../../../src/types/stix-2-1-sdo';
import { testBundleObject, testExecutor } from './playbook-components-test-utils';
import type { StixRelation } from '../../../../src/types/stix-2-1-sro';

const componentConfig = (config: Partial<ContainerWrapperConfiguration>) => {
  return {
    all: false,
    copyFiles: false,
    caseTemplates: [],
    newContainer: true,
    container_type: 'Report',
    excludeMainElement: false,
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
        all: false,
        excludeMainElement: false,
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
        all: true,
        excludeMainElement: false,
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
        all: true,
        excludeMainElement: true,
      }),
    }));

    const reportResult = result.bundle.objects
      .find((element) => element.type === 'report') as StixContainer;
    expect(reportResult.object_refs).toEqual([CAMPAIGN_ID, REL_ID]);
  });
});
