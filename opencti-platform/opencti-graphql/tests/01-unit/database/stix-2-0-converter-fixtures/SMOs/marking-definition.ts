import type { StoreEntity } from '../../../../../src/types/store';

export const MARKING_DEFINITION_INSTANCE = {
  id: '32171810-784c-48a6-9841-ff36ce0a8c52',
  entity_type: 'Marking-Definition',
  standard_id: 'marking-definition--826578e1-40ad-459f-bc73-ede076f81f37',
  definition_type: 'TLP',
  definition: 'TLP:AMBER+STRICT',
  x_opencti_color: '#d84315',
  x_opencti_order: 3,
  created: '2024-11-18T08:57:58.528Z',
} as unknown as StoreEntity;

export const EXPECTED_MARKING_DEFINITION = {
  id: 'marking-definition--826578e1-40ad-459f-bc73-ede076f81f37',
  type: 'marking-definition',
  spec_version: '2.0',
  // The stored date is replaced by the creation date of the STIX TLP markings.
  created: '2017-01-20T00:00:00.000Z',
  name: 'TLP:AMBER+STRICT',
  definition_type: 'tlp',
  definition: { tlp: 'amber+strict' },
  x_opencti_order: 3,
  x_opencti_color: '#d84315',
  x_opencti_id: '32171810-784c-48a6-9841-ff36ce0a8c52',
  x_opencti_type: 'Marking-Definition',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  object_marking_refs: [],
  external_references: [],
};

// PAP marking: definition value is NOT stripped (only "tlp:" prefix is stripped, matching Python client behavior)
export const PAP_MARKING_DEFINITION_INSTANCE = {
  id: 'd69d35e4-d4dc-4a6a-a7a9-580c362b71b9',
  entity_type: 'Marking-Definition',
  standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1',
  definition_type: 'PAP',
  definition: 'PAP:GREEN',
  x_opencti_color: '#2e7d32',
  x_opencti_order: 2,
  created: '2026-03-12T16:20:23.380Z',
} as unknown as StoreEntity;

export const EXPECTED_PAP_MARKING_DEFINITION = {
  id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1',
  type: 'marking-definition',
  spec_version: '2.0',
  created: '2026-03-12T16:20:23.380Z',
  name: 'PAP:GREEN',
  definition_type: 'pap',
  definition: { pap: 'pap:green' },
  x_opencti_order: 2,
  x_opencti_color: '#2e7d32',
  x_opencti_id: 'd69d35e4-d4dc-4a6a-a7a9-580c362b71b9',
  x_opencti_type: 'Marking-Definition',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  object_marking_refs: [],
  external_references: [],
};

// Statement marking: the value keeps its spaces, and every `tlp:` is removed
// (python `str.replace`), as in the legacy python export.
export const STATEMENT_MARKING_DEFINITION_INSTANCE = {
  id: '6a4c2bd0-1f5c-4c47-9a39-2f7b1b7e1a01',
  entity_type: 'Marking-Definition',
  standard_id: 'marking-definition--0c0f1b6e-7f1e-5d2c-9c3a-4d1a2b3c4d5e',
  definition_type: 'statement',
  definition: 'TLP:Copy tlp:shared ',
  x_opencti_color: '#ffffff',
  x_opencti_order: 0,
  created: '2026-03-12T16:20:23.380Z',
} as unknown as StoreEntity;

export const EXPECTED_STATEMENT_MARKING_DEFINITION = {
  id: 'marking-definition--0c0f1b6e-7f1e-5d2c-9c3a-4d1a2b3c4d5e',
  type: 'marking-definition',
  spec_version: '2.0',
  created: '2026-03-12T16:20:23.380Z',
  name: 'TLP:Copy tlp:shared ',
  definition_type: 'statement',
  definition: { statement: 'copy shared ' },
  x_opencti_order: 0,
  x_opencti_color: '#ffffff',
  x_opencti_id: '6a4c2bd0-1f5c-4c47-9a39-2f7b1b7e1a01',
  x_opencti_type: 'Marking-Definition',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  object_marking_refs: [],
  external_references: [],
};
