import type { StixBundle } from '../../../../src/types/stix-2-1-common';

export const sharing_component_bundle = {
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
