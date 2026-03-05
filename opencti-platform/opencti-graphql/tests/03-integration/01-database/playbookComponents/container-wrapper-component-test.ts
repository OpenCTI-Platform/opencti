import { describe, expect, it } from 'vitest';
import { PLAYBOOK_CONTAINER_WRAPPER_COMPONENT, type ContainerWrapperConfiguration } from '../../../../src/modules/playbook/components/container-wrapper-component';
import type { StixBundle } from '../../../../src/types/stix-2-1-common';
import type { ExecutorParameters } from '../../../../src/modules/playbook/playbook-types';
import type { StixContainer } from '../../../../src/types/stix-2-1-sdo';

const dataInstanceIdMock = 'malware--09bd862a-f030-55f2-920a-900c4913d9ff';

const playbookNodeMock = (args: { configurationAll: boolean; configurationExcludeMainElement: boolean }) => {
  return {
    id: '4eb0be9f-e826-4b49-89bf-ced3f4c6e2ba',
    name: 'Container wrapper',
    position: { x: 0, y: 150 },
    component_id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
    configuration: {
      all: args.configurationAll,
      caseTemplates: [],
      container_type: 'Report',
      copyFiles: false,
      excludeMainElement: args.configurationExcludeMainElement,
      newContainer: true,
    },
  };
};

const bundleMock = () => {
  return {
    id: 'id',
    spec_version: '2.1',
    type: 'bundle',
    objects: [
      {
        id: 'malware--09bd862a-f030-55f2-920a-900c4913d9ff',
        type: 'malware',
        extensions: {
          'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
            extension_type: 'property-extension',
            id: 'f5233051-049e-49c6-8be3-909a22dccc88',
            type: 'Malware',
          },
        },
      },
      {
        id: 'relationship--08e64f51-e890-5bec-be34-3344746f1b0c',
        spec_version: '2.1',
        type: 'relationship',
        relationship_type: 'related-to',
        source_ref: 'malware--09bd862a-f030-55f2-920a-900c4913d9ff',
        target_ref: 'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b',
      },
      {
        id: 'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b',
        spec_version: '2.1',
        type: 'campaign',
      },
    ],
  } as unknown as StixBundle;
};

describe('PLAYBOOK_CONTAINER_WRAPPER_COMPONENT', () => {
  it('should wrap only main element', async () => {
    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor({
      dataInstanceId: dataInstanceIdMock,
      playbookNode: playbookNodeMock({ configurationAll: false, configurationExcludeMainElement: false }),
      bundle: bundleMock(),
    } as unknown as ExecutorParameters<ContainerWrapperConfiguration>);

    const reportResult = result.bundle.objects.find((element) => element.type === 'report') as StixContainer;

    const expectedReportRefs = [
      'malware--09bd862a-f030-55f2-920a-900c4913d9ff',
    ];

    expect(reportResult.object_refs).toEqual(expectedReportRefs);
  });

  it('should wrap all elements', async () => {
    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor({
      dataInstanceId: dataInstanceIdMock,
      playbookNode: playbookNodeMock({ configurationAll: true, configurationExcludeMainElement: false }),
      bundle: bundleMock(),
    } as unknown as ExecutorParameters<ContainerWrapperConfiguration>);

    const reportResult = result.bundle.objects.find((element) => element.type === 'report') as StixContainer;

    const expectedReportRefs = [
      'malware--09bd862a-f030-55f2-920a-900c4913d9ff',
      'relationship--08e64f51-e890-5bec-be34-3344746f1b0c',
      'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b',
    ];

    expect(reportResult.object_refs).toEqual(expectedReportRefs);
  });

  it('should wrap all elements except main', async () => {
    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor({
      dataInstanceId: dataInstanceIdMock,
      playbookNode: playbookNodeMock({ configurationAll: true, configurationExcludeMainElement: true }),
      bundle: bundleMock(),
    } as unknown as ExecutorParameters<ContainerWrapperConfiguration>);

    const reportResult = result.bundle.objects.find((element) => element.type === 'report') as StixContainer;

    const expectedReportRefs = [
      'relationship--08e64f51-e890-5bec-be34-3344746f1b0c',
      'campaign--6bcf59ca-70c8-55ae-ac7d-a6f9b107a35b',
    ];

    expect(reportResult.object_refs).toEqual(expectedReportRefs);
  });
});
