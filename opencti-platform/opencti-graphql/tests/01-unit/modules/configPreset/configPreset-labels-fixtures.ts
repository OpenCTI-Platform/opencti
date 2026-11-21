import type { BasicStoreEntityLabel } from '../../../../src/modules/label/label-types';

export const customLabel = {
  id: 'custom-label-id',
  internal_id: 'custom-label-id',
  standard_id: 'label--5d2c1a7e-3b4f-5c6d-8e9f-0a1b2c3d4e5f',
  entity_type: 'Label',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  value: 'tlp:amber',
  color: '#ffc107',
} as unknown as BasicStoreEntityLabel;

export const otherLabel = {
  ...customLabel,
  id: 'other-label-id',
  internal_id: 'other-label-id',
  standard_id: 'label--9a8b7c6d-5e4f-5a3b-9c2d-1e0f9a8b7c6d',
  value: 'APT',
  color: '#ff0000',
} as unknown as BasicStoreEntityLabel;

export const ALL_LABELS = [customLabel, otherLabel];
