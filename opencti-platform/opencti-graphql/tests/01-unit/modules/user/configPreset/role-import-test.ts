import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/user/user-domain', () => ({
  findRoleById: vi.fn(),
  roleAddRelation: vi.fn(),
  roleCapabilities: vi.fn(),
  roleDeleteRelation: vi.fn(),
  roleEditField: vi.fn(),
}));
vi.mock('../../../../../src/domain/grant', () => ({ addRole: vi.fn() }));
vi.mock('../../../../../src/database/middleware-loader', () => ({ fullEntitiesList: vi.fn() }));

import { findRoleById, roleAddRelation, roleCapabilities, roleDeleteRelation, roleEditField } from '../../../../../src/modules/user/user-domain';
import { addRole } from '../../../../../src/domain/grant';
import { fullEntitiesList } from '../../../../../src/database/middleware-loader';
import { importRole, roleStandardId } from '../../../../../src/modules/user/configPreset/role-import';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { generateStandardId } from '../../../../../src/schema/identifier';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;

const PLATFORM_CAPABILITIES = ['BYPASS', 'KNOWLEDGE', 'KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNUPDATE_KNDELETE', 'EXPLORE', 'SETTINGS_SETACCESSES'];

const roleConfiguration = (overrides: Record<string, unknown> = {}) => ({
  name: 'Analyst',
  description: 'Analysts of the SOC',
  can_manage_sensitive_config: false,
  capabilities: ['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE'],
  capabilities_in_draft: ['KNOWLEDGE_KNUPDATE'],
  ...overrides,
});

const existingRole = (name: string, overrides: Record<string, unknown> = {}) => ({
  id: `${name}-internal-id`,
  standard_id: roleStandardId(name),
  name,
  description: 'Analysts of the SOC',
  can_manage_sensitive_config: false,
  ...overrides,
});

// The roles of the platform, found by their standard id like the store does, and the capabilities of each, by relationship type
const withRoles = (roles: ReturnType<typeof existingRole>[], capabilities: Record<string, Record<string, string[]>> = {}) => {
  vi.mocked(findRoleById).mockImplementation(async (_ctx, _user, id) => roles.find((role) => role.standard_id === id || role.id === id) as never);
  vi.mocked(roleCapabilities).mockImplementation(async (_ctx, _user, roleId, type = 'has-capability') => {
    return (capabilities[roleId]?.[type] ?? []).map((name) => ({ id: `${name}-internal-id`, name })) as never;
  });
};

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(fullEntitiesList).mockResolvedValue(PLATFORM_CAPABILITIES.map((name) => ({ name })) as never);
  vi.mocked(addRole).mockImplementation(async (_ctx, _user, role) => ({ id: 'created-id', ...role }));
  withRoles([]);
});

const expectNothingWritten = () => {
  expect(addRole).not.toHaveBeenCalled();
  expect(roleEditField).not.toHaveBeenCalled();
  expect(roleAddRelation).not.toHaveBeenCalled();
  expect(roleDeleteRelation).not.toHaveBeenCalled();
};

describe('importRole validation', () => {
  it.each([
    ['an unknown key', { standard_id: 'role--1' }],
    ['a name of one character', { name: 'A' }],
    ['a blank name', { name: '   ' }],
    ['capabilities that are not a list', { capabilities: 'KNOWLEDGE' }],
    ['no capabilities in draft', { capabilities_in_draft: undefined }],
  ])('refuses %s, without writing', async (_, overrides) => {
    const result = await importRole(context, user, roleConfiguration(overrides), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false, configuration: undefined });
    expectNothingWritten();
  });

  it('refuses a capability the platform does not know, rather than importing fewer rights', async () => {
    const result = await importRole(context, user, roleConfiguration({ capabilities: ['KNOWLEDGE', 'RENAMED_ONE', 'OTHER'] }), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'unknown_capability', reason: 'Unknown capabilities: RENAMED_ONE, OTHER' });
    expectNothingWritten();
  });

  it('refuses a capability in draft that a draft does not offer', async () => {
    const result = await importRole(context, user, roleConfiguration({ capabilities_in_draft: ['SETTINGS_SETACCESSES'] }), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'unknown_capability', reason: 'Capabilities not available in draft: SETTINGS_SETACCESSES' });
    expectNothingWritten();
  });
});

describe('importRole add', () => {
  it('creates a role that does not exist', async () => {
    const result = await importRole(context, user, roleConfiguration(), { mode: ConfigImportMode.Add });
    expect(result).toMatchObject({ status: 'created', exists: false, role: { id: 'created-id' } });
    expect(addRole).toHaveBeenCalledWith(context, user, {
      name: 'Analyst',
      description: 'Analysts of the SOC',
      can_manage_sensitive_config: false,
      capabilities: ['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE'],
      capabilitiesInDraft: ['KNOWLEDGE_KNUPDATE'],
    });
  });

  it('refuses a role whose name exists, whatever its case', async () => {
    withRoles([existingRole('analyst')]);
    expect(await importRole(context, user, roleConfiguration(), { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    expectNothingWritten();
  });
});

describe('importRole overwrite', () => {
  const analyst = existingRole('Analyst', { description: 'Old description' });
  beforeEach(() => {
    withRoles([analyst], {
      [analyst.id]: { 'has-capability': ['KNOWLEDGE', 'EXPLORE'], 'has-capability-in-draft': ['KNOWLEDGE_KNUPDATE'] },
    });
  });

  it('decides on a dry run without writing', async () => {
    const result = await importRole(context, user, roleConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ status: 'overwritten', exists: true, reason: undefined });
    expect(result.role).toBeUndefined();
    expectNothingWritten();
  });

  it('patches the fields that changed and replaces the capabilities as a whole', async () => {
    const result = await importRole(context, user, roleConfiguration(), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'overwritten', exists: true, role: analyst });
    expect(roleEditField).toHaveBeenCalledWith(context, user, analyst.id, [{ key: 'description', value: ['Analysts of the SOC'] }]);
    expect(roleAddRelation).toHaveBeenCalledTimes(1);
    expect(roleAddRelation).toHaveBeenCalledWith(context, user, analyst.id, {
      toId: generateStandardId('Capability', { name: 'KNOWLEDGE_KNUPDATE' }),
      relationship_type: 'has-capability',
    });
    expect(roleDeleteRelation).toHaveBeenCalledTimes(1);
    expect(roleDeleteRelation).toHaveBeenCalledWith(context, user, analyst.id, 'EXPLORE-internal-id', 'has-capability');
    expect(addRole).not.toHaveBeenCalled();
  });

  it('removes every capability in draft when the configuration has none', async () => {
    await importRole(context, user, roleConfiguration({ capabilities_in_draft: [] }), { mode: ConfigImportMode.Overwrite });
    expect(roleDeleteRelation).toHaveBeenCalledWith(context, user, analyst.id, 'KNOWLEDGE_KNUPDATE-internal-id', 'has-capability-in-draft');
  });

  it('leaves a description or a flag that is null or absent untouched', async () => {
    await importRole(context, user, roleConfiguration({ description: null, can_manage_sensitive_config: undefined }), { mode: ConfigImportMode.Overwrite });
    expect(roleEditField).not.toHaveBeenCalled();
  });

  it('creates the role when it does not exist', async () => {
    const result = await importRole(context, user, roleConfiguration({ name: 'Hunter' }), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'created', exists: false });
    expect(addRole).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Hunter' }));
  });
});

describe('importRole copy', () => {
  it('creates the role under its own name when it is free', async () => {
    const result = await importRole(context, user, roleConfiguration(), { mode: ConfigImportMode.Copy });
    expect(result).toMatchObject({ status: 'created', exists: false, reason: undefined });
    expect(addRole).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Analyst' }));
  });

  it('creates another role under the first free name, never touching the existing one', async () => {
    withRoles([existingRole('Analyst'), existingRole('Analyst (1)')]);
    const result = await importRole(context, user, roleConfiguration(), { mode: ConfigImportMode.Copy });
    expect(result).toMatchObject({ status: 'created', exists: true, reason: 'Added as "Analyst (2)"' });
    expect(addRole).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Analyst (2)' }));
    expect(roleEditField).not.toHaveBeenCalled();
    expect(roleAddRelation).not.toHaveBeenCalled();
  });

  it('reserves on a dry run the names the earlier items would take', async () => {
    withRoles([existingRole('Analyst')]);
    const reservedIds = new Set<string>();
    const first = await importRole(context, user, roleConfiguration(), { mode: ConfigImportMode.Copy, dryRun: true, reservedIds });
    const second = await importRole(context, user, roleConfiguration(), { mode: ConfigImportMode.Copy, dryRun: true, reservedIds });
    expect([first.reason, second.reason]).toEqual(['Added as "Analyst (1)"', 'Added as "Analyst (2)"']);
    expectNothingWritten();
  });
});

describe('importRole sensitive rights', () => {
  const administrator = existingRole('Administrator', { can_manage_sensitive_config: true });

  it('never removes the bypass capability from the Administrator role', async () => {
    withRoles([administrator], { [administrator.id]: { 'has-capability': ['BYPASS'], 'has-capability-in-draft': [] } });
    const configuration = roleConfiguration({ name: 'Administrator', capabilities: ['KNOWLEDGE'], capabilities_in_draft: [] });
    const result = await importRole(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'overwritten', reason: 'The Administrator role keeps the bypass capability' });
    expect(roleDeleteRelation).not.toHaveBeenCalled();
    expect(roleAddRelation).toHaveBeenCalledWith(context, user, administrator.id, expect.objectContaining({ toId: generateStandardId('Capability', { name: 'KNOWLEDGE' }) }));
  });

  it('keeps the bypass capability of a copy only when the copy is the Administrator role', async () => {
    withRoles([administrator]);
    await importRole(context, user, roleConfiguration({ name: 'Administrator', capabilities: ['KNOWLEDGE'] }), { mode: ConfigImportMode.Copy });
    expect(addRole).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Administrator (1)', capabilities: ['KNOWLEDGE'] }));
  });

  it.each([
    ['the bypass capability', { capabilities: ['BYPASS'] }],
    ['the management of sensitive configuration', { can_manage_sensitive_config: true }],
  ])('imports %s, and says so when the role does not have it yet', async (_, overrides) => {
    const analyst = existingRole('Analyst');
    withRoles([analyst], { [analyst.id]: { 'has-capability': ['KNOWLEDGE'], 'has-capability-in-draft': [] } });
    const result = await importRole(context, user, roleConfiguration(overrides), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'overwritten', reason: 'Grants sensitive rights' });
  });

  it('says nothing of a sensitive right the role already has', async () => {
    withRoles([administrator], { [administrator.id]: { 'has-capability': ['BYPASS'], 'has-capability-in-draft': [] } });
    const configuration = roleConfiguration({ name: 'Administrator', capabilities: ['BYPASS'], capabilities_in_draft: [], can_manage_sensitive_config: true });
    const result = await importRole(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ status: 'overwritten', reason: undefined });
  });
});
