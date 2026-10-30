import { roleStandardId } from '../../../../src/modules/user/configPreset/role-import';
import type { BasicStoreEntityRole } from '../../../../src/modules/user/configPreset/role-export';

// A role with, next to the import format fields, attributes that must never be exported
export const administratorRole = {
  id: 'administrator-role-id',
  internal_id: 'administrator-role-id',
  standard_id: roleStandardId('Administrator'),
  entity_type: 'Role',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Administrator',
  description: 'Administrator role that bypass every capabilities',
  can_manage_sensitive_config: false,
} as unknown as BasicStoreEntityRole;

// A role with neither description nor sensitive flag set
export const analystRole = {
  ...administratorRole,
  id: 'analyst-role-id',
  internal_id: 'analyst-role-id',
  standard_id: roleStandardId('Analyst'),
  name: 'Analyst',
  description: undefined,
  can_manage_sensitive_config: undefined,
} as unknown as BasicStoreEntityRole;

export const ALL_ROLES = [administratorRole, analystRole];

// The capabilities of each role, by relationship type, in no particular order
export const ROLE_CAPABILITIES: Record<string, Record<string, string[]>> = {
  [administratorRole.id]: { 'has-capability': ['BYPASS'], 'has-capability-in-draft': [] },
  [analystRole.id]: { 'has-capability': ['KNOWLEDGE_KNUPDATE', 'KNOWLEDGE', 'EXPLORE'], 'has-capability-in-draft': ['KNOWLEDGE_KNUPDATE'] },
};
