import { groupStandardId } from '../../../../src/modules/user/configPreset/group-import';
import type { BasicStoreEntityGroup } from '../../../../src/modules/user/configPreset/group-export';
import { administratorRole, analystRole } from './configPreset-roles-fixtures';
import { ALL_MARKINGS, papRed, tlpAmber } from './configPreset-markings-fixtures';

export const administratorsGroup = {
  id: 'administrators-group-id',
  internal_id: 'administrators-group-id',
  standard_id: groupStandardId('Administrators'),
  entity_type: 'Group',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Administrators',
  description: 'Administrator group',
  default_assignation: false,
  auto_integration_assignation: [],
  no_creators: false,
  restrict_delete: true,
  auto_new_marking: true,
  group_confidence_level: { max_confidence: 100, overrides: [{ entity_type: 'Report', max_confidence: 80 }] },
  default_hidden_types: ['Malware', 'Channel'],
  default_marking: [{ entity_type: 'GLOBAL', values: [tlpAmber.id, 'deleted-marking-id'] }],
  max_shareable_markings: [{ type: 'TLP', value: tlpAmber.id }, { type: 'PAP', value: 'none' }, { type: 'Deleted', value: 'deleted-marking-id' }],
} as unknown as BasicStoreEntityGroup;

export const analystsGroup = {
  id: 'analysts-group-id',
  internal_id: 'analysts-group-id',
  standard_id: groupStandardId('Analysts'),
  entity_type: 'Group',
  name: 'Analysts',
} as unknown as BasicStoreEntityGroup;

export const ALL_GROUPS = [administratorsGroup, analystsGroup];

export const GROUP_ROLE_RELATIONS = [
  { fromId: administratorsGroup.id, toId: administratorRole.id },
  { fromId: analystsGroup.id, toId: analystRole.id },
];

export const GROUP_ALLOWED_MARKINGS: Record<string, typeof ALL_MARKINGS> = {
  [administratorsGroup.id]: [tlpAmber, papRed],
  [analystsGroup.id]: [],
};
