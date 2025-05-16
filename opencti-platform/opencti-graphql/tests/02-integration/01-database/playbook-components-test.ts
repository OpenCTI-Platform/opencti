import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PLAYBOOK_CONTAINER_WRAPPER_COMPONENT, PLAYBOOK_SHARING_COMPONENT } from '../../../src/modules/playbook/playbook-components';
import type { StixBundle } from '../../../src/types/stix-2-1-common';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { enableCEAndUnSetOrganization, enableEEAndSetOrganization } from '../../utils/testQueryHelper';
import { PLATFORM_ORGANIZATION, TEST_ORGANIZATION } from '../../utils/testQuery';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';
import { sharing_component_bundle } from './playbookComponents/playbook-sharing-component';
import { container_wrapper_component_bundle, container_wrapper_apply_case_template_bundle } from './playbookComponents/playbook-container-wrapper-component';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

describe('playbook sharing component', () => {
  let externalOrganizationEntity: BasicStoreEntityOrganization;

  beforeAll(async () => {
    await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);

    externalOrganizationEntity = await getOrganizationEntity(TEST_ORGANIZATION);
  });

  afterAll(async () => {
    await enableCEAndUnSetOrganization();
  });

  it('should share report and contained entities with "all" option', async () => {
    const dataInstanceId = 'report--b70b1781-f963-5790-9fe7-55aec16c05f4';
    const playbookNode = {
      component_id: 'PLAYBOOK_SHARING_COMPONENT',
      configuration: {
        organizations: [
          {
            label: externalOrganizationEntity.name,
            value: externalOrganizationEntity.id
          }
        ],
        all: true
      },
      id: '651475c0-04ae-423d-88d3-734c35e65c07',
      name: 'Share with organizations',
      position: {
        y: 150
      }
    };
    const bundleToIngest = {
      id: '411628bf-745b-43f6-8194-cbe441edecfd',
      objects: [
        {
          confidence: 100,
          created: '2025-03-25T09:59:10.000Z',
          description: 'fff',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              created_at: '2025-03-25T09:59:17.024Z',
              creator_ids: [
                '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
              ],
              extension_type: 'property-extension',
              granted_refs: [externalOrganizationEntity.standard_id],
              id: '82e80255-9793-4283-b34b-872b30f23f57',
              type: 'Report',
              updated_at: '2025-03-25T09:59:44.832Z',
              workflow_id: 'a4b90e6f-06ae-461a-8dac-666cdb4a5ae7'
            }
          },
          id: 'report--b70b1781-f963-5790-9fe7-55aec16c05f4',
          lang: 'en',
          modified: '2025-03-25T09:59:44.832Z',
          name: 'report 28',
          object_refs: [
            'campaign--fdcacc8e-de4d-5a13-8886-401d363664fd'
          ],
          published: '2025-03-25T09:59:10.000Z',
          spec_version: '2.1',
          type: 'report'
        },
        {
          id: 'campaign--fdcacc8e-de4d-5a13-8886-401d363664fd',
          spec_version: '2.1',
          type: 'campaign',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'property-extension',
              id: '21df79ac-4edf-40c5-bc04-a0122dbc4e39',
              type: 'Campaign',
              created_at: '2015-05-15T09:12:16.432Z',
              updated_at: '2025-03-26T10:00:10.363Z',
              is_inferred: false,
              creator_ids: [
                '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
              ],
              granted_refs: [externalOrganizationEntity.standard_id]
            }
          },
          created: '2020-02-29T14:48:31.601Z',
          modified: '2025-04-10T16:34:18.572Z',
          revoked: false,
          confidence: 100,
          lang: 'en',
          labels: [
            'campaign'
          ],
          name: 'admin@338',
          description: 'description',
          first_seen: '2008-01-07T00:00:00.000Z',
        },
      ],
      spec_version: '2.1',
      type: 'bundle'
    } as unknown as StixBundle;

    const result = await PLAYBOOK_SHARING_COMPONENT.executor({
      dataInstanceId,
      eventId: '',
      executionId: '',
      playbookId: '',
      previousPlaybookNodeId: '',
      previousStepBundle: sharing_component_bundle,
      playbookNode,
      bundle: sharing_component_bundle
    });
    expect(result.bundle).toEqual(bundleToIngest);
  });
});

describe('playbook container wrapper component', () => {
  beforeAll(async () => {
    await enableEEAndSetOrganization(PLATFORM_ORGANIZATION);
  });

  afterAll(async () => {
    await enableCEAndUnSetOrganization();
  });
  it('should wrap Incident in Incident Response container', async () => {
    const dataInstanceId = 'incident--c6c2b96d-fe70-5099-a033-87cbfe2d6be2';
    const playbookNode = {
      id: 'fb1d0a03-eb72-426a-ab48-505a2ca399d0',
      name: 'Container wrapper',
      position: {
        x: 0,
        y: 150
      },
      component_id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
      configuration: {
        container_type: 'Case-Incident',
        all: false,
        newContainer: false,
        caseTemplates: [],
      }
    };
    const expectedBundleToIngest = {
      id: '1c775f39-6cea-4b14-92f8-7843d2443af7',
      spec_version: '2.1',
      type: 'bundle',
      objects: [
        {
          id: 'incident--c6c2b96d-fe70-5099-a033-87cbfe2d6be2',
          spec_version: '2.1',
          type: 'incident',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'new-sdo',
              id: '25cab01c-46be-48ed-832f-857d35347f15',
              type: 'Incident',
              created_at: '2025-02-25T08:13:45.863Z',
              updated_at: '2025-05-09T10:03:11.288Z',
              is_inferred: false,
              creator_ids: [
                '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
              ]
            }
          },
          created: '2025-02-25T08:13:45.851Z',
          modified: '2025-05-09T10:03:11.288Z',
          revoked: false,
          confidence: 100,
          lang: 'en',
          name: 'Test Incident',
          description: ''
        },
        {
          id: 'case-incident--b52ce838-2972-51ea-a538-005b36189e19',
          spec_version: '2.1',
          type: 'case-incident',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'new-sdo',
              id: 'fe30c5e6-d68d-4cbe-a318-a046abaaacc8',
              type: 'Case-Incident'
            }
          },
          created: '2025-02-25T08:13:45.863Z',
          name: 'Test Incident',
          object_refs: [
            'incident--c6c2b96d-fe70-5099-a033-87cbfe2d6be2'
          ]
        }
      ]
    } as unknown as StixBundle;

    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor({
      dataInstanceId,
      eventId: '',
      executionId: '',
      playbookId: '',
      previousPlaybookNodeId: '',
      previousStepBundle: container_wrapper_component_bundle,
      playbookNode,
      bundle: container_wrapper_component_bundle
    });
    expect(result.bundle.objects.length).toEqual(2);
    expect(result.bundle.objects[1].id).toEqual(expectedBundleToIngest.objects[1].id);
    expect(result.bundle.objects[1].extensions[STIX_EXT_OCTI].type).toEqual(expectedBundleToIngest.objects[1].extensions[STIX_EXT_OCTI].type);
  });
  it('should wrap Incident in Incident Response container and apply case template', async () => {
    const dataInstanceId = 'incident--e97b1203-fa52-5803-8115-e4144a468189';
    const playbookNode = {
      id: 'fb1d0a03-eb72-426a-ab48-505a2ca399d0',
      name: 'Container wrapper',
      position: {
        x: -100,
        y: 300
      },
      component_id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
      configuration: {
        container_type: 'Case-Incident',
        all: false,
        newContainer: false,
        caseTemplates: [
          {
            label: 'template for incident',
            value: '5d327b9d-cb0e-400f-aa7e-80f748c75f84'
          },
          {
            label: 'case template test',
            value: 'c4f7df8d-c6a8-418e-a761-536587ec50c1'
          }
        ],
      }
    };
    const expectedBundleToIngest = {
      id: '1c7f9935-6f38-43fc-98f2-07e09da062df',
      spec_version: '2.1',
      type: 'bundle',
      objects: [
        {
          id: 'incident--e97b1203-fa52-5803-8115-e4144a468189',
          spec_version: '2.1',
          type: 'incident',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'new-sdo',
              id: '477d1af5-cf3c-4648-89df-254c11fc54b0',
              type: 'Incident',
              created_at: '2025-05-15T09:30:28.035Z',
              updated_at: '2025-05-16T09:54:40.393Z',
              is_inferred: false,
              creator_ids: [
                '88ec0c6a-13ce-5e39-b486-354fe4a7084f'
              ],
              labels_ids: [
                '88600fff-88fd-4c09-8d27-f6c8847ee7a4'
              ]
            }
          },
          created: '2025-05-15T09:30:28.019Z',
          modified: '2025-05-16T09:54:40.393Z',
          revoked: false,
          confidence: 100,
          lang: 'en',
          labels: [
            'akira'
          ],
          object_marking_refs: [
            'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
          ],
          name: 'incident playbook'
        },
        {
          id: 'task--a4c3bf5a-f8cd-5f64-a769-f295fbafbc98',
          spec_version: '2.1',
          type: 'task',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'new-sdo',
              id: '46c29218-6233-48f4-b1ca-f97d331f6485',
              type: 'Task'
            }
          },
          name: 'analayse data',
          object_refs: [
            'case-incident--e2a5b146-81f8-5d0d-8b58-6cfcd282c167'
          ],
          object_marking_refs: [
            'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
          ]
        },
        {
          id: 'task--20b30fa9-56bd-5b7b-9764-b072aa5f2ee6',
          spec_version: '2.1',
          type: 'task',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'new-sdo',
              id: '475122ba-bdef-4a94-bd5a-560021f93eb9',
              type: 'Task'
            }
          },
          name: 'ingest data',
          object_refs: [
            'case-incident--e2a5b146-81f8-5d0d-8b58-6cfcd282c167'
          ],
          object_marking_refs: [
            'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
          ]
        },
        {
          id: 'task--af7b713a-a10e-5f5e-8a57-7341ab87a2c6',
          spec_version: '2.1',
          type: 'task',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'new-sdo',
              id: '3304bb36-73ac-469b-b1ba-44998aeb01e6',
              type: 'Task'
            }
          },
          name: 'read logs',
          object_refs: [
            'case-incident--e2a5b146-81f8-5d0d-8b58-6cfcd282c167'
          ],
          object_marking_refs: [
            'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
          ]
        },
        {
          id: 'case-incident--e2a5b146-81f8-5d0d-8b58-6cfcd282c167',
          spec_version: '2.1',
          type: 'case-incident',
          extensions: {
            'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': {
              extension_type: 'new-sdo',
              id: '5d922071-de7f-4466-a6c1-ba80101da33a',
              type: 'Case-Incident'
            }
          },
          created: '2025-05-15T09:30:28.035Z',
          name: 'incident playbook',
          object_refs: [
            'incident--e97b1203-fa52-5803-8115-e4144a468189'
          ],
          object_marking_refs: [
            'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
          ],
          labels: [
            'akira'
          ]
        }
      ]
    } as unknown as StixBundle;

    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor({
      dataInstanceId,
      eventId: '',
      executionId: '',
      playbookId: '',
      previousPlaybookNodeId: '',
      previousStepBundle: container_wrapper_component_bundle,
      playbookNode,
      bundle: container_wrapper_apply_case_template_bundle
    });
    expect(result.bundle.objects.length).toEqual(5); // 1 Incident + 3 Tasks + 1 Case Incident
    expect(result.bundle.objects[1].id).toEqual(expectedBundleToIngest.objects[1].id);
    expect(result.bundle.objects[1].extensions[STIX_EXT_OCTI].type).toEqual(expectedBundleToIngest.objects[1].extensions[STIX_EXT_OCTI].type);
  });
});
