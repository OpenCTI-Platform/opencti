import { describe, it, expect } from 'vitest';
import type { StixBundle } from '../../../../src/types/stix-2-1-common';
import type { StixCaseIncident } from '../../../../src/modules/case/case-incident/case-incident-types';
import { PLAYBOOK_CONTAINER_WRAPPER_COMPONENT } from '../../../../src/modules/playbook/playbook-components';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../../../../src/modules/case/case-incident/case-incident-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

const INCIDENT_ID = 'incident--c6c2b96d-fe70-5099-a033-87cbfe2d6be2';

export const container_wrapper_component_bundle: StixBundle = {
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
          created_at: '2025-02-25T08:13:45.863Z',
          updated_at: '2025-05-09T10:03:11.288Z',
          is_inferred: false,
          granted_refs: ['34a50091-acd7-5b12-88f4-086155cf40d4'],
          creator_ids: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'],
        },
      },
      external_references: [
        {
          source_name: 'upload_file',
          external_id: 'upload_file_example.pdf',
        },
      ],
      severity: 'high',
      created: '2025-02-25T08:13:45.851Z',
      modified: '2025-05-09T10:03:11.288Z',
      revoked: false,
      confidence: 100,
      lang: 'en',
      name: 'Test Incident',
      description: '',
    },
  ],
} as unknown as StixBundle;

const buildPlaybookNode = () => ({
  id: 'playbook-node',
  name: 'share-node',
  component_id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
  configuration: {
    container_type: ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
    all: false,
    excludeMainElement: false,
    copyFiles: false,
    newContainer: false,
    caseTemplates: [],
  },
});

describe('PLAYBOOK_CONTAINER_WRAPPER_COMPONENT — Incident → Case Incident mapping', () => {
  it('should map all three incident-specific attributes in a single execution', async () => {
    const result = await PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.executor({
      eventId: '',
      executionId: '',
      playbookId: '',
      previousPlaybookNodeId: undefined,
      previousStepBundle: null as StixBundle | null,
      dataInstanceId: INCIDENT_ID,
      playbookNode: buildPlaybookNode(),
      bundle: structuredClone(container_wrapper_component_bundle),
    });

    const caseIncident = result.bundle.objects[1] as StixCaseIncident;

    expect(caseIncident).toBeDefined();
    expect(caseIncident.severity).toBe('high');
    expect(caseIncident.external_references).toEqual([
      {
        source_name: 'upload_file',
        external_id: 'upload_file_example.pdf',
      },
    ]);
    expect(caseIncident.extensions[STIX_EXT_OCTI].granted_refs).toEqual([
      '34a50091-acd7-5b12-88f4-086155cf40d4',
    ]);
  });
});
