import type { StoreEntity } from '../../../../../src/types/store';

export const LABEL_INSTANCE = {
  id: 'ac88f87e-ce89-46aa-a68e-fc863117d1cd',
  entity_type: 'Label',
  standard_id: 'label--0008ca88-56ff-5e8e-a0a8-1734b84cdd01',
  value: 'small',
  color: '#3fb64a',
} as unknown as StoreEntity;

export const EXPECTED_LABEL = {
  id: 'label--0008ca88-56ff-5e8e-a0a8-1734b84cdd01',
  type: 'label',
  spec_version: '2.0',
  value: 'small',
  color: '#3fb64a',
  x_opencti_id: 'ac88f87e-ce89-46aa-a68e-fc863117d1cd',
  x_opencti_type: 'Label',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
};
