import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { PLAYBOOK_CONTAINER_WRAPPER_COMPONENT, PLAYBOOK_SHARING_COMPONENT } from '../../../src/modules/playbook/playbook-components';
import type { StixBundle } from '../../../src/types/stix-2-1-common';
import type { BasicStoreEntityOrganization } from '../../../src/modules/organization/organization-types';
import { unSetOrganization, setOrganization } from '../../utils/testQueryHelper';
import { PLATFORM_ORGANIZATION, TEST_ORGANIZATION } from '../../utils/testQuery';
import { getOrganizationEntity } from '../../utils/domainQueryHelper';
import { sharing_component_bundle } from './playbookComponents/playbook-sharing-component';
import { container_wrapper_component_bundle } from './playbookComponents/playbook-container-wrapper-component';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import * as entrepriseEdition from '../../../src/enterprise-edition/ee';

describe('playbook sharing component', () => {
  let externalOrganizationEntity: BasicStoreEntityOrganization;

  beforeAll(async () => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    await setOrganization(PLATFORM_ORGANIZATION);

    externalOrganizationEntity = await getOrganizationEntity(TEST_ORGANIZATION);
  });

  afterAll(async () => {
    // Deactivate EE at the end of this test - back to CE
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockRejectedValue('Enterprise edition is not enabled');
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);
    await unSetOrganization();
  });

  it('should share report and contained entities with "all" option', async () => {
    const dataInstanceId = 'report--b70b1781-f963-5790-9fe7-55aec16c05f4';
    const playbookNode = {
      component_id: 'PLAYBOOK_SHARING_COMPONENT',
      configuration: {
        organizations: [
          {
            label: externalOrganizationEntity.name,
            value: externalOrganizationEntity.id,
          },
        ],
        all: true,
      },
      id: '651475c0-04ae-423d-88d3-734c35e65c07',
      name: 'Share with organizations',
      position: {
        y: 150,
      },
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
                '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
              ],
              extension_type: 'property-extension',
              granted_refs: [externalOrganizationEntity.standard_id],
              id: '82e80255-9793-4283-b34b-872b30f23f57',
              type: 'Report',
              updated_at: '2025-03-25T09:59:44.832Z',
              workflow_id: 'a4b90e6f-06ae-461a-8dac-666cdb4a5ae7',
            },
          },
          id: 'report--b70b1781-f963-5790-9fe7-55aec16c05f4',
          lang: 'en',
          modified: '2025-03-25T09:59:44.832Z',
          name: 'report 28',
          object_refs: [
            'campaign--fdcacc8e-de4d-5a13-8886-401d363664fd',
          ],
          published: '2025-03-25T09:59:10.000Z',
          spec_version: '2.1',
          type: 'report',
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
                '88ec0c6a-13ce-5e39-b486-354fe4a7084f',
              ],
              granted_refs: [externalOrganizationEntity.standard_id],
            },
          },
          created: '2020-02-29T14:48:31.601Z',
          modified: '2025-04-10T16:34:18.572Z',
          revoked: false,
          confidence: 100,
          lang: 'en',
          labels: [
            'campaign',
          ],
          name: 'admin@338',
          description: 'description',
          first_seen: '2008-01-07T00:00:00.000Z',
        },
      ],
      spec_version: '2.1',
      type: 'bundle',
    } as unknown as StixBundle;

    const result = await PLAYBOOK_SHARING_COMPONENT.executor({
      dataInstanceId,
      eventId: '',
      executionId: '',
      playbookId: '',
      previousPlaybookNodeId: '',
      previousStepBundle: sharing_component_bundle,
      playbookNode,
      bundle: sharing_component_bundle,
    });
    expect(result.bundle).toEqual(bundleToIngest);
  });
});

describe('playbook container wrapper component', () => {
  beforeAll(async () => {
    // Activate EE for this test
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockResolvedValue();
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
    await setOrganization(PLATFORM_ORGANIZATION);
  });

  afterAll(async () => {
    // Deactivate EE at the end of this test - back to CE
    vi.spyOn(entrepriseEdition, 'checkEnterpriseEdition').mockRejectedValue('Enterprise edition is not enabled');
    vi.spyOn(entrepriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);
    await unSetOrganization();
  });
  it('should wrap Incident in Incident Response container', async () => {
    const dataInstanceId = 'incident--c6c2b96d-fe70-5099-a033-87cbfe2d6be2';
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
        all: false,
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
            'incident--c6c2b96d-fe70-5099-a033-87cbfe2d6be2',
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
