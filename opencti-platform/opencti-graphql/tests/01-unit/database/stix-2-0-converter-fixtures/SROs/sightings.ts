import type { StoreRelation } from '../../../../../src/types/store';

export const SIGHTING_INSTANCE = {
  id: '11cad6c5-98f1-4491-899a-15b7789e1492',
  standard_id: 'sighting--22799cbd-e9b5-5b7c-8733-5c2a5cc49ebe',
  internal_id: '11cad6c5-98f1-4491-899a-15b7789e1492',
  entity_type: 'stix-sighting-relationship',
  base_type: 'RELATION',
  relationship_type: 'stix-sighting-relationship',
  attribute_count: 1,
  first_seen: '2025-07-30T22:00:00.000Z',
  last_seen: '2025-07-30T22:00:00.000Z',
  created: '2025-07-31T07:26:56.885Z',
  modified: '2025-07-31T07:28:43.240Z',
  confidence: 100,
  description: 'descri',
  revoked: false,
  x_opencti_negative: true,
  from: {
    standard_id: 'indicator--3e01a7d8-997b-5e7b-a1a3-32f8956ca752',
    internal_id: 'a07241c5-8d5f-413c-9a19-8eba1245359d',
    entity_type: 'Indicator',
  },
  to: {
    standard_id: 'identity--4f347cc9-4658-59ee-9707-134f434f9d1c',
    internal_id: '47cffe73-dcad-4830-884d-8d10f66780c5',
    entity_type: 'Organization',
  },
  fromId: 'a07241c5-8d5f-413c-9a19-8eba1245359d',
  fromRole: 'stix-sighting-relationship_from',
  fromType: 'Indicator',
  toId: '47cffe73-dcad-4830-884d-8d10f66780c5',
  toRole: 'stix-sighting-relationship_to',
  toType: 'Organization',
  objectOrganization: [{ standard_id: 'identity--18fe5225-fee1-5627-ad3e-20c14435b024' }],
  createdBy: { standard_id: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6' },
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
  externalReferences: [{ source_name: 'cve', external_id: 'CVE-2012-0158' }],
  objectLabel: [{ value: 'indicator' }],
} as unknown as StoreRelation;

export const EXPECTED_SIGHTING = {
  id: 'sighting--22799cbd-e9b5-5b7c-8733-5c2a5cc49ebe',
  spec_version: '2.0',
  revoked: false,
  description: 'descri',
  first_seen: '2025-07-30T22:00:00.000Z',
  last_seen: '2025-07-30T22:00:00.000Z',
  x_opencti_negative: true,
  created: '2025-07-31T07:26:56.885Z',
  modified: '2025-07-31T07:28:43.240Z',
  confidence: 100,
  labels: [
    'indicator'
  ],
  external_references: [
    {
      source_name: 'cve',
      external_id: 'CVE-2012-0158'
    }
  ],
  x_opencti_id: '11cad6c5-98f1-4491-899a-15b7789e1492',
  x_opencti_type: 'stix-sighting-relationship',
  type: 'sighting',
  created_by_ref: 'identity--072d8aaa-93a9-5ded-89e4-1ad87d8b91c6',
  x_opencti_granted_refs: [
    'identity--18fe5225-fee1-5627-ad3e-20c14435b024'
  ],
  object_marking_refs: [
    'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'
  ],
  count: 1,
  sighting_of_ref: 'indicator--3e01a7d8-997b-5e7b-a1a3-32f8956ca752',
  where_sighted_refs: [
    'identity--4f347cc9-4658-59ee-9707-134f434f9d1c'
  ],
  x_opencti_files: [],
};
