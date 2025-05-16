import type { StixBundle } from '../../../../src/types/stix-2-1-common';

export const container_wrapper_component_bundle = {
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
    }
  ]
} as unknown as StixBundle;

export const container_wrapper_apply_case_template_bundle = {
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
    }
  ]
};
