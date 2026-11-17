import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
  internalFindByIdsMapped: vi.fn(),
}));
vi.mock('../../../../src/modules/playbook/playbook-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/playbook/playbook-domain')>()),
  playbookEdit: vi.fn(),
  playbookAddFromImport: vi.fn(),
}));
vi.mock('../../../../src/modules/playbook/components/ai-agent-shared', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/playbook/components/ai-agent-shared')>()),
  sanitizeDefinitionRunAs: vi.fn(async (_context: unknown, _user: unknown, definition: string) => definition),
}));

import { fullEntitiesList, internalFindByIdsMapped } from '../../../../src/database/middleware-loader';
import { playbookAddFromImport, playbookEdit } from '../../../../src/modules/playbook/playbook-domain';
import { sanitizeDefinitionRunAs } from '../../../../src/modules/playbook/components/ai-agent-shared';
import { AMBIGUOUS_PLAYBOOK_REASON, importConfigPresetPlaybook } from '../../../../src/modules/playbook/playbook-import';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'admin-id', name: 'admin' } as AuthUser;

const MARKING_ID = '3c8f2a1e-5b6d-4e7f-8a9b-0c1d2e3f4a5b';
const GROUP_ID = '4d9a3b2f-6c7e-4f8a-9b0c-1d2e3f4a5b6c';
const JANE = { internal_id: '0f6d5b0a-4f4d-4a8b-9c1e-2f6a8d1c3b01', standard_id: 'user--6b1a3c0e-7f2d-5e4a-9b8c-1d2e3f4a5b6c' };
const JOHN_STANDARD_ID = 'user--7c2b4d1f-8a3e-5f6b-0c9d-2e3f4a5b6c7d';

const node = (id: string, componentId: string, configuration: object) => ({
  id,
  name: id,
  position: { x: 0, y: 0 },
  component_id: componentId,
  configuration: JSON.stringify(configuration),
});

const definitionOf = (runAs: string, members: { label: string; value: string }[] = [], runAsLabel = 'Jane') => JSON.stringify({
  nodes: [
    node('start', 'PLAYBOOK_INTERNAL_DATA_STREAM', { filters: JSON.stringify({ mode: 'and', filters: [{ key: ['objectMarking'], values: [MARKING_ID] }], filterGroups: [] }) }),
    node('agent', 'PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT', { run_as: { label: runAsLabel, value: runAs }, prompt: 'Summarize' }),
    node('notify', 'PLAYBOOK_NOTIFIER_COMPONENT', { notifiers: [], authorized_members: members }),
  ],
  links: [],
});

const bundlePlaybook = (overrides: Record<string, unknown> = {}) => ({
  name: 'Enrich reports',
  description: 'Enrich the incoming reports',
  playbook_start: 'start',
  playbook_definition: definitionOf(JANE.standard_id, [{ label: 'Analysts', value: GROUP_ID }]),
  ...overrides,
});

const storedPlaybook = (overrides: Record<string, unknown> = {}) => ({
  id: 'playbook-id',
  internal_id: 'playbook-id',
  entity_type: 'Playbook',
  name: 'Enrich reports',
  description: 'Enrich the incoming reports',
  playbook_start: 'start',
  playbook_running: true,
  playbook_definition: definitionOf(JANE.internal_id, [{ label: 'Analysts', value: GROUP_ID }]),
  ...overrides,
});

// The platform has Jane, the marking and the group; a user or an id it does not have is missing
const withPlatform = (playbooks: unknown[], known: Record<string, unknown> = { [JANE.standard_id]: JANE, [JANE.internal_id]: JANE, [MARKING_ID]: {}, [GROUP_ID]: {} }) => {
  vi.mocked(fullEntitiesList).mockResolvedValue(playbooks as never);
  vi.mocked(internalFindByIdsMapped).mockImplementation(async (_ctx, _user, ids) => {
    return Object.fromEntries((ids as string[]).filter((id) => known[id]).map((id) => [id, known[id]])) as never;
  });
};

const writtenDefinition = () => JSON.parse(vi.mocked(playbookAddFromImport).mock.calls[0][2].playbook_definition as string);
const nodeConfiguration = (definition: { nodes: { id: string; configuration: string }[] }, id: string) => JSON.parse(definition.nodes.find((n) => n.id === id)!.configuration);

describe('Playbook import of a configuration preset', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(playbookAddFromImport).mockResolvedValue({ id: 'created-id' } as never);
  });

  it('refuses a configuration that is not a playbook', async () => {
    withPlatform([]);
    const result = await importConfigPresetPlaybook(context, user, { name: 'No definition' }, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    const unparsable = await importConfigPresetPlaybook(context, user, bundlePlaybook({ playbook_definition: '{"nodes":' }), { mode: ConfigImportMode.Overwrite });
    expect(unparsable).toMatchObject({ status: 'failed', code: 'invalid' });
  });

  it('creates a new playbook stopped, its users found by standard id, and writes nothing in a dry run', async () => {
    withPlatform([]);
    const dryRun = await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(dryRun).toMatchObject({ status: 'created', exists: false, name: 'Enrich reports' });
    expect(dryRun.reason).toBeUndefined();
    expect(playbookAddFromImport).not.toHaveBeenCalled();
    const result = await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Overwrite });
    expect(result.status).toBe('created');
    expect(playbookAddFromImport).toHaveBeenCalledWith(context, user, expect.objectContaining({
      name: 'Enrich reports',
      description: 'Enrich the incoming reports',
      playbook_start: 'start',
      playbook_running: false,
    }));
    expect(nodeConfiguration(writtenDefinition(), 'agent').run_as).toEqual({ label: 'Jane', value: JANE.internal_id });
    expect(sanitizeDefinitionRunAs).toHaveBeenCalled();
  });

  it('reports the users the platform does not have and leaves them out of the members, the run_as being reset to the importer', async () => {
    withPlatform([]);
    const configuration = bundlePlaybook({ playbook_definition: definitionOf(JOHN_STANDARD_ID, [{ label: 'John', value: JOHN_STANDARD_ID }, { label: 'Analysts', value: GROUP_ID }], 'John') });
    const result = await importConfigPresetPlaybook(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'created', reason: 'Users not found: John' });
    const definition = writtenDefinition();
    expect(nodeConfiguration(definition, 'notify').authorized_members).toEqual([{ label: 'Analysts', value: GROUP_ID }]);
    expect(nodeConfiguration(definition, 'agent').run_as).toEqual({ label: 'John', value: JOHN_STANDARD_ID });
  });

  it('imports the definition as it is and reports the ids the platform does not have, by label when the configuration has one', async () => {
    withPlatform([], { [JANE.standard_id]: JANE, [JANE.internal_id]: JANE });
    const result = await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'created', reason: `References not found: ${MARKING_ID}, Analysts` });
    expect(nodeConfiguration(writtenDefinition(), 'notify').authorized_members).toEqual([{ label: 'Analysts', value: GROUP_ID }]);
  });

  it('never reports the ids that are the same on every platform', async () => {
    withPlatform([]);
    const configuration = bundlePlaybook({
      playbook_definition: JSON.stringify({
        nodes: [node('notify', 'PLAYBOOK_NOTIFIER_COMPONENT', { notifiers: ['f4ee7b33-006a-4b0d-b57d-411ad288653d'], authorized_members: [{ value: '88ec0c6a-13ce-5e39-b486-354fe4a7084f' }] })],
        links: [],
      }),
    });
    const result = await importConfigPresetPlaybook(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ status: 'created' });
    expect(result.reason).toBeUndefined();
  });

  it('is already up to date when the playbook of the same name has the same configuration', async () => {
    withPlatform([storedPlaybook()]);
    const result = await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true });
    expect(playbookEdit).not.toHaveBeenCalled();
  });

  it('overwrites only the fields that differ, and keeps the running state of the playbook', async () => {
    withPlatform([storedPlaybook({ description: 'Old' })]);
    const dryRun = await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(dryRun).toMatchObject({ status: 'overwritten', exists: true });
    expect(playbookEdit).not.toHaveBeenCalled();
    await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Overwrite });
    expect(playbookEdit).toHaveBeenCalledWith(context, user, 'playbook-id', [{ key: 'description', value: ['Enrich the incoming reports'] }]);
    expect(playbookAddFromImport).not.toHaveBeenCalled();
  });

  it('overwrites the definition when a node differs', async () => {
    withPlatform([storedPlaybook({ playbook_definition: definitionOf(JANE.internal_id) })]);
    await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Overwrite });
    expect(vi.mocked(playbookEdit).mock.calls[0][3].map(({ key }) => key)).toEqual(['playbook_definition']);
  });

  it('adds a copy under a free name', async () => {
    withPlatform([storedPlaybook(), storedPlaybook({ id: 'other', name: 'Enrich reports (1)' })]);
    const result = await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Copy });
    expect(result).toMatchObject({ status: 'created', exists: true, name: 'Enrich reports (2)', reason: 'Added as "Enrich reports (2)"' });
    expect(playbookAddFromImport).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Enrich reports (2)', playbook_running: false }));
  });

  it('takes a free name among the names the earlier items of the import take', async () => {
    withPlatform([]);
    const result = await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Copy, dryRun: true, reservedNames: new Set(['Enrich reports']) });
    expect(result).toMatchObject({ status: 'created', name: 'Enrich reports (1)' });
  });

  it('refuses to overwrite when several playbooks have the name, or an earlier item of the import takes it', async () => {
    withPlatform([storedPlaybook(), storedPlaybook({ id: 'homonym' })]);
    expect(await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Overwrite })).toMatchObject({
      status: 'failed',
      code: 'ambiguous',
      reason: AMBIGUOUS_PLAYBOOK_REASON,
      exists: true,
    });
    withPlatform([]);
    expect(await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Overwrite, reservedNames: new Set(['Enrich reports']) }))
      .toMatchObject({ status: 'failed', code: 'ambiguous', exists: false });
    expect(playbookEdit).not.toHaveBeenCalled();
    expect(playbookAddFromImport).not.toHaveBeenCalled();
  });

  it('refuses a playbook that exists in add mode', async () => {
    withPlatform([storedPlaybook()]);
    expect(await importConfigPresetPlaybook(context, user, bundlePlaybook(), { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
  });
});
