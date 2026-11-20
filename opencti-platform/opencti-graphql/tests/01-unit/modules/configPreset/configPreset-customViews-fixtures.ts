import type { BasicStoreEntityCustomView } from '../../../../src/modules/customView/customView-types';
import { toB64 } from '../../../../src/utils/base64';

// A custom view of the reports: enabled and the default of its entity type, with a widget, next to the attributes that must never be exported.
// The manifest has no filter, so that exporting it reads nothing on the platform
export const executiveCustomView = {
  id: 'executive-custom-view-id',
  internal_id: 'executive-custom-view-id',
  standard_id: 'customview--2c5e8f1a-4b3d-5e6f-8a9b-0c1d2e3f4a5b',
  entity_type: 'CustomView',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Executive overview',
  description: 'The view of the executives',
  slug: 'executive-overview',
  target_entity_type: 'Report',
  enabled: true,
  default: true,
  manifest: toB64({ widgets: { 'widget-1': { id: 'widget-1', type: 'text', dataSelection: [{ label: 'Summary' }] } }, config: {} }),
} as unknown as BasicStoreEntityCustomView;

// A view of another entity type, without description nor manifest, neither enabled nor the default
export const malwareCustomView = {
  ...executiveCustomView,
  id: 'malware-custom-view-id',
  internal_id: 'malware-custom-view-id',
  standard_id: 'customview--7a8b9c0d-1e2f-5a3b-9c4d-5e6f7a8b9c0d',
  name: 'Malware triage',
  description: undefined,
  slug: 'malware-triage',
  target_entity_type: 'Malware',
  enabled: false,
  default: false,
  manifest: undefined,
} as unknown as BasicStoreEntityCustomView;

export const ALL_CUSTOM_VIEWS = [executiveCustomView, malwareCustomView];
