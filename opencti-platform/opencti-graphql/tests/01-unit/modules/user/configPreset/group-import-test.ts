import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/user/user-domain', () => ({ findRoleById: vi.fn(), roleCapabilities: vi.fn() }));
vi.mock('../../../../../src/domain/grant', () => ({ addGroup: vi.fn() }));
vi.mock('../../../../../src/domain/group', () => ({
  findById: vi.fn(),
  groupAddRelation: vi.fn(),
  groupAllowedMarkings: vi.fn(),
  groupDeleteRelation: vi.fn(),
  groupEditField: vi.fn(),
}));
vi.mock('../../../../../src/database/middleware-loader', () => ({ fullEntitiesThroughRelationsToList: vi.fn(), storeLoadById: vi.fn() }));
vi.mock('../../../../../src/database/cache', () => ({ getEntitiesMapFromCache: vi.fn() }));
vi.mock('../../../../../src/modules/user/configPreset/sensitive-config-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/user/configPreset/sensitive-config-import')>()),
  isConfigImportSensitiveChangeAllowed: vi.fn(),
}));

import { findRoleById, roleCapabilities } from '../../../../../src/modules/user/user-domain';
import { addGroup } from '../../../../../src/domain/grant';
import { findById as findGroupById, groupAddRelation, groupAllowedMarkings, groupDeleteRelation, groupEditField } from '../../../../../src/domain/group';
import { fullEntitiesThroughRelationsToList, storeLoadById } from '../../../../../src/database/middleware-loader';
import { getEntitiesMapFromCache } from '../../../../../src/database/cache';
import { groupStandardId, importGroup } from '../../../../../src/modules/user/configPreset/group-import';
import { roleStandardId } from '../../../../../src/modules/user/configPreset/role-import';
import { isConfigImportSensitiveChangeAllowed } from '../../../../../src/modules/user/configPreset/sensitive-config-import';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;

const marking = (definitionType: string, definition: string) => ({
  id: `${definition}-internal-id`,
  standard_id: `marking-definition--${definition}`,
  definition_type: definitionType,
  definition,
});
const TLP_AMBER = marking('TLP', 'TLP:AMBER');
const PAP_RED = marking('PAP', 'PAP:RED');
const markingReference = ({ standard_id, definition_type, definition }: ReturnType<typeof marking>) => ({ standard_id, definition_type, definition });

const analystRole = { id: 'analyst-internal-id', standard_id: roleStandardId('Analyst'), name: 'Analyst' };
const hunterRole = { id: 'hunter-internal-id', standard_id: roleStandardId('Hunter'), name: 'Hunter' };
const dashboard = { id: 'dashboard-internal-id', standard_id: 'workspace--1', name: 'SOC overview' };

const groupConfiguration = (overrides: Record<string, unknown> = {}) => ({
  name: 'Analysts',
  description: 'Analysts of the SOC',
  default_assignation: false,
  auto_integration_assignation: [],
  no_creators: false,
  restrict_delete: false,
  auto_new_marking: false,
  group_confidence_level: { max_confidence: 80, overrides: [] },
  default_hidden_types: ['Channel'],
  default_dashboard: { standard_id: dashboard.standard_id, name: dashboard.name },
  roles: [{ standard_id: analystRole.standard_id, name: 'Analyst' }],
  allowed_markings: [markingReference(TLP_AMBER)],
  default_marking: [{ entity_type: 'GLOBAL', values: [markingReference(TLP_AMBER)] }],
  max_shareable_markings: [{ type: 'TLP', value: markingReference(TLP_AMBER) }, { type: 'PAP', value: 'none' }],
  ...overrides,
});

const existingGroup = (name: string, overrides: Record<string, unknown> = {}) => ({
  id: `${name}-internal-id`,
  standard_id: groupStandardId(name),
  name,
  description: 'Analysts of the SOC',
  default_assignation: false,
  auto_integration_assignation: [] as string[],
  no_creators: false,
  restrict_delete: false,
  auto_new_marking: false,
  group_confidence_level: { max_confidence: 80, overrides: [] },
  default_hidden_types: ['Channel'],
  default_dashboard: dashboard.id,
  default_marking: [{ entity_type: 'GLOBAL', values: [TLP_AMBER.id] }],
  max_shareable_markings: [{ type: 'TLP', value: TLP_AMBER.id }, { type: 'PAP', value: 'none' }],
  ...overrides,
});

// The groups, roles, markings and dashboards of the platform, found by standard id like the store does
const withPlatform = ({ groups = [] as ReturnType<typeof existingGroup>[], roles = [analystRole, hunterRole], markings = [TLP_AMBER, PAP_RED], dashboards = [dashboard] } = {}) => {
  vi.mocked(findGroupById).mockImplementation(async (_ctx: unknown, _user: unknown, id: string) => groups.find((g) => g.standard_id === id || g.id === id) as never);
  vi.mocked(findRoleById).mockImplementation(async (_ctx, _user, id) => roles.find((role) => role.standard_id === id) as never);
  vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map(markings.flatMap((m) => [[m.id, m], [m.standard_id, m]])) as never);
  vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => dashboards.find((d) => d.standard_id === id) as never);
};

// The relations of an existing group: its roles and its allowed markings
const withRelations = (roles: { id: string }[], markings: { id: string }[]) => {
  vi.mocked(fullEntitiesThroughRelationsToList).mockResolvedValue(roles as never);
  vi.mocked(groupAllowedMarkings).mockResolvedValue(markings as never);
};

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(isConfigImportSensitiveChangeAllowed).mockResolvedValue(true);
  vi.mocked(roleCapabilities).mockResolvedValue([]);
  vi.mocked(addGroup).mockImplementation(async (_ctx: unknown, _user: unknown, group: Record<string, unknown>) => ({ id: 'created-id', ...group }));
  withPlatform();
  withRelations([], []);
});

const expectNothingWritten = () => {
  expect(addGroup).not.toHaveBeenCalled();
  expect(groupEditField).not.toHaveBeenCalled();
  expect(groupAddRelation).not.toHaveBeenCalled();
  expect(groupDeleteRelation).not.toHaveBeenCalled();
};

describe('importGroup validation', () => {
  it.each([
    ['an unknown key', { members: [] }],
    ['a name of one character', { name: 'A' }],
    ['a confidence over 100', { group_confidence_level: { max_confidence: 101, overrides: [] } }],
    ['a marking without its definition', { allowed_markings: [{ standard_id: TLP_AMBER.standard_id }] }],
    ['no roles', { roles: undefined }],
  ])('refuses %s, without writing', async (_, overrides) => {
    const result = await importGroup(context, user, groupConfiguration(overrides), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', configuration: undefined });
    expectNothingWritten();
  });

  it('fails with a role that could not be imported', async () => {
    withPlatform({ roles: [] });
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'role_missing', reason: 'Roles could not be imported: Analyst' });
    expectNothingWritten();
  });

  it('accepts on a dry run a role the same import creates', async () => {
    withPlatform({ roles: [] });
    const plannedRoles = new Map([[analystRole.standard_id, { grantsSensitiveRights: false }]]);
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true, plannedRoles });
    expect(result).toMatchObject({ status: 'created', exists: false });
  });
});

describe('importGroup create', () => {
  it('creates the group with what it references on this platform, by internal id', async () => {
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Add });
    expect(result).toMatchObject({ status: 'created', exists: false, reason: undefined, group: { id: 'created-id' } });
    expect(addGroup).toHaveBeenCalledWith(context, user, {
      name: 'Analysts',
      description: 'Analysts of the SOC',
      default_assignation: false,
      auto_integration_assignation: [],
      no_creators: false,
      restrict_delete: false,
      auto_new_marking: false,
      group_confidence_level: { max_confidence: 80, overrides: [] },
      default_hidden_types: ['Channel'],
      default_dashboard: dashboard.id,
      default_marking: [{ entity_type: 'GLOBAL', values: [TLP_AMBER.id] }],
      max_shareable_markings: [{ type: 'TLP', value: TLP_AMBER.id }, { type: 'PAP', value: 'none' }],
    });
    expect(groupAddRelation).toHaveBeenCalledWith(context, user, 'created-id', { toId: analystRole.id, relationship_type: 'has-role' });
    expect(groupAddRelation).toHaveBeenCalledWith(context, user, 'created-id', { toId: TLP_AMBER.id, relationship_type: 'accesses-to' });
  });

  it('keeps each reported name on its line, so that a name cannot add a reason', async () => {
    withPlatform({ dashboards: [] });
    const configuration = groupConfiguration({ default_dashboard: { standard_id: 'workspace--forged', name: 'X\nThe Administrators group keeps the Administrator role' } });
    const result = await importGroup(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result.reason).toEqual('Default dashboard not found: X The Administrators group keeps the Administrator role');
  });

  it('leaves out and reports the markings and the dashboard that are not on this platform', async () => {
    withPlatform({ markings: [PAP_RED], dashboards: [] });
    const configuration = groupConfiguration({ allowed_markings: [markingReference(TLP_AMBER), markingReference(PAP_RED)] });
    const result = await importGroup(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    expect(result.reason).toEqual('Markings not found: TLP:AMBER\nDefault dashboard not found: SOC overview');
    const created = vi.mocked(addGroup).mock.calls[0][2];
    expect(created).not.toHaveProperty('default_dashboard');
    expect(created).toMatchObject({ default_marking: [{ entity_type: 'GLOBAL', values: [] }], max_shareable_markings: [{ type: 'TLP', value: 'none' }, { type: 'PAP', value: 'none' }] });
    expect(groupAddRelation).toHaveBeenCalledTimes(2);
    expect(groupAddRelation).toHaveBeenCalledWith(context, user, 'created-id', { toId: PAP_RED.id, relationship_type: 'accesses-to' });
  });

  it('refuses a group whose name exists, whatever its case', async () => {
    withPlatform({ groups: [existingGroup('analysts')] });
    expect(await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    expectNothingWritten();
  });
});

describe('importGroup overwrite', () => {
  const analysts = existingGroup('Analysts', { description: 'Old description', group_confidence_level: { max_confidence: 50, overrides: [] } });
  beforeEach(() => {
    withPlatform({ groups: [analysts] });
    withRelations([hunterRole], [PAP_RED]);
  });

  it('decides on a dry run without writing', async () => {
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ status: 'overwritten', exists: true });
    expectNothingWritten();
  });

  it('says which roles and markings of the group the overwrite removes', async () => {
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result.reason).toEqual('Roles removed: Hunter\nMarkings removed: PAP:RED');
    withRelations([analystRole], [TLP_AMBER]);
    expect((await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true })).reason).toBeUndefined();
  });

  it('patches the fields that changed and replaces the roles and the allowed markings as a whole', async () => {
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'overwritten', exists: true });
    expect(groupEditField).toHaveBeenCalledWith(context, user, analysts.id, [
      { key: 'description', value: ['Analysts of the SOC'] },
      { key: 'group_confidence_level', value: [{ max_confidence: 80, overrides: [] }] },
    ]);
    expect(groupAddRelation).toHaveBeenCalledWith(context, user, analysts.id, { toId: analystRole.id, relationship_type: 'has-role' });
    expect(groupDeleteRelation).toHaveBeenCalledWith(context, user, analysts.id, undefined, hunterRole.id, 'has-role');
    expect(groupAddRelation).toHaveBeenCalledWith(context, user, analysts.id, { toId: TLP_AMBER.id, relationship_type: 'accesses-to' });
    expect(groupDeleteRelation).toHaveBeenCalledWith(context, user, analysts.id, undefined, PAP_RED.id, 'accesses-to');
    expect(addGroup).not.toHaveBeenCalled();
  });

  it('leaves the values that are null or absent untouched, the dashboard of a missing reference too', async () => {
    withPlatform({ groups: [analysts], dashboards: [] });
    const configuration = groupConfiguration({ description: null, group_confidence_level: undefined });
    await importGroup(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    expect(groupEditField).not.toHaveBeenCalled();
  });

  it('mentions the automatic assignments the group does not have yet', async () => {
    withRelations([analystRole], [TLP_AMBER]);
    const configuration = groupConfiguration({ default_assignation: true, auto_integration_assignation: ['global'] });
    const result = await importGroup(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result.reason).toEqual('New users join this group automatically\nNew integration users join this group automatically');
    withPlatform({ groups: [{ ...analysts, default_assignation: true, auto_integration_assignation: ['global'] }] });
    expect((await importGroup(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true })).reason).toBeUndefined();
  });
});

describe('importGroup copy', () => {
  it('creates another group under the first free name, never touching the existing one', async () => {
    withPlatform({ groups: [existingGroup('Analysts'), existingGroup('Analysts (1)')] });
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Copy });
    expect(result).toMatchObject({ status: 'created', exists: true, reason: 'Added as "Analysts (2)"' });
    expect(addGroup).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Analysts (2)' }));
    expect(groupEditField).not.toHaveBeenCalled();
    expect(groupDeleteRelation).not.toHaveBeenCalled();
  });

  it('reserves on a dry run the names the earlier items would take', async () => {
    withPlatform({ groups: [existingGroup('Analysts')] });
    const reservedIds = new Set<string>();
    const first = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Copy, dryRun: true, reservedIds });
    const second = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Copy, dryRun: true, reservedIds });
    expect([first.reason, second.reason]).toEqual(['Added as "Analysts (1)"', 'Added as "Analysts (2)"']);
    expectNothingWritten();
  });
});

describe('importGroup protected sensitive configuration', () => {
  it('refuses a protected group to a user who cannot manage the sensitive configuration, without writing', async () => {
    withPlatform({ groups: [existingGroup('Administrators')] });
    vi.mocked(isConfigImportSensitiveChangeAllowed).mockResolvedValue(false);
    const result = await importGroup(context, user, groupConfiguration({ name: 'Administrators' }), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'sensitive_config', reason: 'Requires the right to manage the sensitive configuration', exists: true });
    expect(isConfigImportSensitiveChangeAllowed).toHaveBeenCalledWith(context, user, 'groups', groupStandardId('Administrators'));
    expectNothingWritten();
  });
});

describe('importGroup Administrators group', () => {
  const administratorRole = { id: 'administrator-internal-id', standard_id: roleStandardId('Administrator'), name: 'Administrator' };
  const administrators = existingGroup('Administrators');

  it('never removes the Administrator role from the Administrators group', async () => {
    withPlatform({ groups: [administrators], roles: [analystRole, administratorRole] });
    withRelations([administratorRole], []);
    const result = await importGroup(context, user, groupConfiguration({ name: 'Administrators' }), { mode: ConfigImportMode.Overwrite });
    expect(result.reason).toEqual('The Administrators group keeps the Administrator role');
    expect(groupDeleteRelation).not.toHaveBeenCalledWith(context, user, administrators.id, undefined, administratorRole.id, 'has-role');
    expect(groupAddRelation).toHaveBeenCalledWith(context, user, administrators.id, { toId: analystRole.id, relationship_type: 'has-role' });
  });

  it('leaves the roles of any other group as the bundle has them', async () => {
    withPlatform({ groups: [existingGroup('Analysts')], roles: [analystRole, administratorRole] });
    withRelations([administratorRole], []);
    await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite });
    expect(groupDeleteRelation).toHaveBeenCalledWith(context, user, 'Analysts-internal-id', undefined, administratorRole.id, 'has-role');
  });

  it('does not keep it in a copy of the Administrators group', async () => {
    withPlatform({ groups: [administrators], roles: [analystRole, administratorRole] });
    await importGroup(context, user, groupConfiguration({ name: 'Administrators' }), { mode: ConfigImportMode.Copy });
    expect(groupAddRelation).not.toHaveBeenCalledWith(context, user, 'created-id', { toId: administratorRole.id, relationship_type: 'has-role' });
  });
});

describe('importGroup role imported as COPY', () => {
  const analystCopy = { id: 'analyst-copy-internal-id', standard_id: roleStandardId('Analyst (1)'), name: 'Analyst (1)' };
  const roleTargets = new Map([[analystRole.standard_id, analystCopy.standard_id]]);

  it('gets the copy of the role, never the local role of the same name', async () => {
    withPlatform({ roles: [analystRole, analystCopy] });
    await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Add, roleTargets });
    expect(groupAddRelation).toHaveBeenCalledWith(context, user, 'created-id', { toId: analystCopy.id, relationship_type: 'has-role' });
    expect(groupAddRelation).not.toHaveBeenCalledWith(context, user, 'created-id', { toId: analystRole.id, relationship_type: 'has-role' });
  });

  it('reads in a dry run the rights of the copy, not the ones of the local role', async () => {
    withPlatform({ roles: [analystRole] });
    vi.mocked(roleCapabilities).mockResolvedValue([{ name: 'BYPASS' }] as never);
    const plannedRoles = new Map([[analystCopy.standard_id, { grantsSensitiveRights: false }]]);
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Add, dryRun: true, roleTargets, plannedRoles });
    expect(result).toMatchObject({ status: 'created', reason: undefined });
  });

  it('fails when the copy could not be written', async () => {
    withPlatform({ roles: [analystRole] });
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Add, roleTargets });
    expect(result).toMatchObject({ status: 'failed', code: 'role_missing' });
    expectNothingWritten();
  });
});

describe('importGroup sensitive rights', () => {
  it('reads in a dry run the rights of a role the same import creates', async () => {
    withPlatform({ roles: [] });
    const options = { mode: ConfigImportMode.Overwrite, dryRun: true };
    const planned = (grantsSensitiveRights: boolean) => new Map([[analystRole.standard_id, { grantsSensitiveRights }]]);
    const sensitive = await importGroup(context, user, groupConfiguration(), { ...options, plannedRoles: planned(true) });
    expect(sensitive).toMatchObject({ status: 'created', reason: 'Grants sensitive rights' });
    const notSensitive = await importGroup(context, user, groupConfiguration(), { ...options, plannedRoles: planned(false) });
    expect(notSensitive.reason).toBeUndefined();
  });

  it('reads in a dry run the rights a role overwritten by the same import will have, not its current ones', async () => {
    vi.mocked(roleCapabilities).mockResolvedValue([{ name: 'BYPASS' }] as never);
    const planned = (grantsSensitiveRights: boolean) => new Map([[analystRole.standard_id, { grantsSensitiveRights }]]);
    const overwritten = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true, plannedRoles: planned(false) });
    expect(overwritten.reason).toBeUndefined();
    vi.mocked(roleCapabilities).mockResolvedValue([]);
    const granted = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true, plannedRoles: planned(true) });
    expect(granted.reason).toEqual('Grants sensitive rights');
  });

  it('says so when the group gets a role with the bypass capability', async () => {
    vi.mocked(roleCapabilities).mockImplementation(async (_ctx, _user, roleId) => (roleId === analystRole.id ? [{ name: 'BYPASS' }] : []) as never);
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result.reason).toEqual('Grants sensitive rights');
  });

  it('says so when the group gets a role that manages the sensitive configuration', async () => {
    withPlatform({ roles: [{ ...analystRole, can_manage_sensitive_config: true } as typeof analystRole] });
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result.reason).toEqual('Grants sensitive rights');
  });

  it('says so when the overwrite takes away a role that gives sensitive rights', async () => {
    withPlatform({ groups: [existingGroup('Analysts')] });
    withRelations([analystRole, hunterRole], [TLP_AMBER]);
    vi.mocked(roleCapabilities).mockImplementation(async (_ctx, _user, roleId) => (roleId === hunterRole.id ? [{ name: 'BYPASS' }] : []) as never);
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result.reason).toEqual('Removes sensitive rights\nRoles removed: Hunter');
    vi.mocked(roleCapabilities).mockResolvedValue([]);
    expect((await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true })).reason).toEqual('Roles removed: Hunter');
  });

  it('says nothing of a sensitive role the group already has', async () => {
    withPlatform({ groups: [existingGroup('Analysts')] });
    withRelations([analystRole], [TLP_AMBER]);
    vi.mocked(roleCapabilities).mockResolvedValue([{ name: 'BYPASS' }] as never);
    const result = await importGroup(context, user, groupConfiguration(), { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result.reason).toBeUndefined();
  });
});
