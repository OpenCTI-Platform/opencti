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
