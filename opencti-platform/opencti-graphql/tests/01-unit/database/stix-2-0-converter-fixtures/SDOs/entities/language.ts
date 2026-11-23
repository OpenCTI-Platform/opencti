import type { StoreEntityLanguage } from '../../../../../../src/modules/language/language-types';

export const LANGUAGE_INSTANCE = {
  id: '3c7a1f0e-5b2d-4e8a-9f61-2d4b8c0a7e15',
  standard_id: 'language--0a7b3f5c-1d2e-5f60-8a9b-4c3d2e1f0a9b',
  entity_type: 'Language',
  created: '2026-03-18T10:04:59.276Z',
  modified: '2026-03-18T10:24:35.407Z',
  confidence: 100,
  revoked: false,
  name: 'French',
  aliases: ['fr'],
  createdBy: { standard_id: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb' },
  objectLabel: [{ value: 'stix 2.0' }],
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
  externalReferences: [{ source_name: 'iso-639', external_id: 'fr' }],
} as unknown as StoreEntityLanguage;

export const EXPECTED_LANGUAGE = {
  id: 'language--0a7b3f5c-1d2e-5f60-8a9b-4c3d2e1f0a9b',
  type: 'language',
  spec_version: '2.0',
  x_opencti_id: '3c7a1f0e-5b2d-4e8a-9f61-2d4b8c0a7e15',
  x_opencti_type: 'Language',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  created: '2026-03-18T10:04:59.276Z',
  modified: '2026-03-18T10:24:35.407Z',
  revoked: false,
  confidence: 100,
  labels: ['stix 2.0'],
  object_marking_refs: ['marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'],
  created_by_ref: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb',
  external_references: [{ source_name: 'iso-639', external_id: 'fr' }],
  name: 'French',
  aliases: ['fr'],
};
