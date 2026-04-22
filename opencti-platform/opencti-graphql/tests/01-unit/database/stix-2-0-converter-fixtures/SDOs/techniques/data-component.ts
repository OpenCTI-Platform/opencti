import type { StoreEntityDataComponent } from '../../../../../../src/modules/dataComponent/dataComponent-types';

/** Only `standard_id` is read by convertDataComponentToStix_2_0 via INPUT_DATA_SOURCE */
const DATA_SOURCE_REF = {
  standard_id: 'data-source--d9ad9c14-1310-53f0-85ad-3654c552cc2d',
};

export const DATA_COMPONENT_INSTANCE = {
  id: '9b98e5a8-e4a9-44a0-ad49-5e26affd779d',
  standard_id: 'data-component--e83a6698-2379-5c7c-8cd6-e0cdf2c4842f',
  entity_type: 'Data-Component',
  created: '2026-03-18T10:06:27.555Z',
  modified: '2026-03-18T13:11:47.212Z',
  confidence: 100,
  revoked: false,
  name: 'Data Component STIX 2.0',
  description: 'descriptions',
  dataSource: DATA_SOURCE_REF,
  createdBy: { standard_id: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb' },
  objectLabel: [{ value: 'stix 2.0' }],
  objectMarking: [{ standard_id: 'marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1' }],
} as unknown as StoreEntityDataComponent;

export const EXPECTED_DATA_COMPONENT = {
  id: 'x-mitre-data-component--e83a6698-2379-5c7c-8cd6-e0cdf2c4842f',
  type: 'x-mitre-data-component',
  spec_version: '2.0',
  x_opencti_id: '9b98e5a8-e4a9-44a0-ad49-5e26affd779d',
  x_opencti_type: 'Data-Component',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  created: '2026-03-18T10:06:27.555Z',
  modified: '2026-03-18T13:11:47.212Z',
  revoked: false,
  confidence: 100,
  labels: ['stix 2.0'],
  object_marking_refs: ['marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'],
  created_by_ref: 'identity--c801c762-92e8-58b6-9bcb-6fa805f902cb',
  external_references: [],
  name: 'Data Component STIX 2.0',
  description: 'descriptions',
  aliases: [],
  x_mitre_data_source_ref: 'x-mitre-data-source--d9ad9c14-1310-53f0-85ad-3654c552cc2d',
};
