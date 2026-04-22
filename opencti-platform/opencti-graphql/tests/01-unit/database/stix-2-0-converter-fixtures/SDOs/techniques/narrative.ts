import type { StoreEntityNarrative } from '../../../../../../src/modules/narrative/narrative-types';

export const NARRATIVE_INSTANCE = {
  id: 'a645ba79-46a5-4b4f-b3b7-bcab5b6344bf',
  standard_id: 'narrative--d1745fb3-f2f9-5f44-a9da-ed22e14d3e6e',
  entity_type: 'Narrative',
  created: '2026-03-18T10:04:59.276Z',
  modified: '2026-03-18T10:24:35.407Z',
  confidence: 100,
  revoked: false,
  name: 'Narrative STIX 2.0',
  description: 'description',
  createdBy: { standard_id: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb' },
  objectLabel: [{ value: 'stix 2.0' }],
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
} as unknown as StoreEntityNarrative;

export const EXPECTED_NARRATIVE = {
  id: 'narrative--d1745fb3-f2f9-5f44-a9da-ed22e14d3e6e',
  type: 'narrative',
  spec_version: '2.0',
  x_opencti_id: 'a645ba79-46a5-4b4f-b3b7-bcab5b6344bf',
  x_opencti_type: 'Narrative',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  created: '2026-03-18T10:04:59.276Z',
  modified: '2026-03-18T10:24:35.407Z',
  revoked: false,
  confidence: 100,
  labels: ['stix 2.0'],
  object_marking_refs: ['marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'],
  created_by_ref: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb',
  external_references: [],
  name: 'Narrative STIX 2.0',
  description: 'description',
  narrative_types: [],
  aliases: [],
};
