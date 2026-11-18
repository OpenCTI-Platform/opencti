import { beforeEach, describe, expect, it, vi } from 'vitest';

// The overwrite of a dashboard by an import of a bundle: the dashboard is read again under the lock of its manifest (the one the presets and the
// variables are written under), so that what another writer saved since it was found is not written back.
const state = vi.hoisted(() => ({ locked: false, readUnderLock: [] as boolean[] }));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  updateAttribute: vi.fn(),
  createEntity: vi.fn(),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  notify: vi.fn(async (_topic: string, element: unknown) => element),
}));
vi.mock('../../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../../src/modules/workspace/workspace-variables-domain', () => ({
  withWorkspaceManifestLock: vi.fn(async (_id: string, callback: () => Promise<unknown>) => {
    state.locked = true;
    try {
      return await callback();
    } finally {
      state.locked = false;
    }
  }),
}));
vi.mock('../../../../src/modules/workspace/workspace-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/workspace/workspace-domain')>()),
  findAllWorkspaces: vi.fn(),
  findById: vi.fn(),
}));
vi.mock('../../../../src/modules/workspace/workspace-utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/workspace/workspace-utils')>()),
  convertDashboardIds: vi.fn(),
}));

import { createEntity, updateAttribute } from '../../../../src/database/middleware';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { FunctionalError } from '../../../../src/config/errors';
import { findAllWorkspaces, findById } from '../../../../src/modules/workspace/workspace-domain';
import { convertDashboardIds } from '../../../../src/modules/workspace/workspace-utils';
import { importDashboard } from '../../../../src/modules/workspace/workspace-import';
import { fromB64, toB64 } from '../../../../src/utils/base64';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const widgetOf = (entityType: string) => ({
  id: 'widget1',
  type: 'number',
  dataSelection: [{ filters: { mode: 'and', filters: [{ key: ['entity_type'], values: [entityType], operator: 'eq', mode: 'or' }], filterGroups: [] } }],
});
const manifestOf = (entityType: string, presets?: unknown[], variables?: unknown[]) => toB64({
  config: {},
  widgets: { widget1: widgetOf(entityType) },
  ...(presets ? { presets } : {}),
  ...(variables ? { variables } : {}),
}) as string;
const variableOf = (id: string, name: string) => ({ id, name, type: 'text', restriction: { mode: 'none' }, defaultValue: 'phishing' });
const presetOf = (id: string) => ({ id, name: `Preset ${id}`, values: {}, config: { startDate: null, endDate: null, relativeDate: null } });
const workspaceOf = (manifest: string) => ({ id: 'workspace-id', name: 'SOC overview', type: 'dashboard', manifest, restricted_members: [] });
const imported = { name: 'SOC overview', manifest: manifestOf('Malware') };

beforeEach(() => {
  vi.clearAllMocks();
  state.readUnderLock = [];
  vi.mocked(findById).mockImplementation(async () => {
    state.readUnderLock.push(state.locked);
    return workspaceOf(manifestOf('Report', [presetOf('first'), presetOf('saved-meanwhile')])) as never;
  });
  vi.mocked(updateAttribute).mockResolvedValue({ element: { id: 'workspace-id', name: 'SOC overview' } } as never);
});

describe('Overwrite of a dashboard by a bundle, what is written under the lock', () => {
  it('keeps the presets saved after the dashboard was found, not the ones it had then', async () => {
    // Found with one preset; another writer saves a second one before the lock is taken (what findById returns)
    vi.mocked(findAllWorkspaces).mockResolvedValue([workspaceOf(manifestOf('Report', [presetOf('first')]))] as never);
    expect(await importDashboard(context, user, imported, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'overwritten', exists: true });
    expect(state.readUnderLock).toEqual([true]);
    const [, , workspaceId, , inputs] = vi.mocked(updateAttribute).mock.calls[0];
    expect(workspaceId).toBe('workspace-id');
    const written = fromB64(inputs.find(({ key }) => key === 'manifest')?.value?.[0] as string);
    expect(written.presets.map(({ id }: { id: string }) => id)).toEqual(['first', 'saved-meanwhile']);
    expect(written.widgets.widget1.dataSelection[0].filters.filters[0].values).toEqual(['Malware']);
    expect(publishUserAction).toHaveBeenCalledTimes(1);
  });

  it('writes nothing when the dashboard read under the lock already is what the bundle says', async () => {
    vi.mocked(findAllWorkspaces).mockResolvedValue([workspaceOf(manifestOf('Report'))] as never);
    vi.mocked(findById).mockImplementation(async () => workspaceOf(manifestOf('Malware', [presetOf('first')])) as never);
    expect(await importDashboard(context, user, imported, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'overwritten' });
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
  });

  it('does not read the dashboard again, nor write, on a dry run', async () => {
    vi.mocked(findAllWorkspaces).mockResolvedValue([workspaceOf(manifestOf('Report'))] as never);
    expect(await importDashboard(context, user, imported, { mode: ConfigImportMode.Overwrite, dryRun: true })).toMatchObject({ status: 'overwritten' });
    expect(findById).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('keeps the variables of the dashboard when the bundle has none, and replaces them when it has some, an empty list included', async () => {
    const variables = [variableOf('0b1c9a52-6f2b-4d5e-9a64-6c1f0a0f9a11', 'First')];
    const variablesWritten = () => {
      const [, , , , inputs] = vi.mocked(updateAttribute).mock.calls[0];
      return fromB64(inputs.find(({ key }) => key === 'manifest')?.value?.[0] as string).variables;
    };
    vi.mocked(findAllWorkspaces).mockResolvedValue([workspaceOf(manifestOf('Report', undefined, variables))] as never);
    vi.mocked(findById).mockImplementation(async () => workspaceOf(manifestOf('Report', undefined, variables)) as never);
    // A bundle of a platform without the feature flag has no `variables`: they are neither compared nor wiped
    expect(await importDashboard(context, user, { name: 'SOC overview', manifest: manifestOf('Report') }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    expect(await importDashboard(context, user, imported, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'overwritten' });
    expect(variablesWritten()).toEqual(variables);
    // A bundle that has `variables` replaces them, an empty list clears them
    vi.mocked(updateAttribute).mockClear();
    expect(await importDashboard(context, user, { name: 'SOC overview', manifest: manifestOf('Report', undefined, []) }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'overwritten' });
    expect(variablesWritten()).toEqual([]);
  });

  it('creates the dashboard when it was deleted between its search and the lock, instead of failing', async () => {
    vi.mocked(findAllWorkspaces).mockResolvedValue([workspaceOf(manifestOf('Report'))] as never);
    vi.mocked(findById).mockResolvedValue(undefined as never);
    vi.mocked(createEntity).mockResolvedValue({ id: 'new-id', name: 'SOC overview' } as never);
    expect(await importDashboard(context, user, imported, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'created', exists: false });
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(createEntity).toHaveBeenCalledTimes(1);
  });
});

describe('Conversion of the manifest of a bundle, what is a refusal of the item', () => {
  it('refuses an item whose manifest is invalid, but lets a failure of the platform be an error', async () => {
    vi.mocked(findAllWorkspaces).mockResolvedValue([] as never);
    const bad = { name: 'SOC overview', manifest: manifestOf('Report', undefined, [{ id: 'not-a-variable' }]) };
    expect(await importDashboard(context, user, bad, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    vi.mocked(convertDashboardIds).mockRejectedValueOnce(new Error('Elasticsearch timeout'));
    await expect(importDashboard(context, user, imported, { mode: ConfigImportMode.Overwrite })).rejects.toThrow('Elasticsearch timeout');
    vi.mocked(convertDashboardIds).mockRejectedValueOnce(FunctionalError('Duplicated dashboard variable id'));
    expect(await importDashboard(context, user, imported, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'failed', code: 'invalid', reason: expect.stringContaining('Duplicated') });
  });
});

describe('Overwrite of a dashboard by a bundle that has variables, the presets it keeps', () => {
  const first = variableOf('0b1c9a52-6f2b-4d5e-9a64-6c1f0a0f9a11', 'First');
  const second = variableOf('1c2d0b63-7a3c-4e6f-8b75-7d2a1b1a0b22', 'Second');
  const presetWith = (id: string, values: Record<string, string>) => ({ ...presetOf(id), values });
  const presetsWritten = () => {
    const [, , , , inputs] = vi.mocked(updateAttribute).mock.calls[0];
    return fromB64(inputs.find(({ key }) => key === 'manifest')?.value?.[0] as string).presets;
  };
  const overwrite = (stored: string, variables: unknown[]) => {
    vi.mocked(findAllWorkspaces).mockResolvedValue([workspaceOf(stored)] as never);
    vi.mocked(findById).mockResolvedValue(workspaceOf(stored) as never);
    return importDashboard(context, user, { name: 'SOC overview', manifest: manifestOf('Malware', undefined, variables) }, { mode: ConfigImportMode.Overwrite });
  };

  it('removes the value of a variable the bundle no longer has, and keeps the rest of the preset', async () => {
    const stored = manifestOf('Report', [presetWith('p1', { [first.id]: 'phishing', [second.id]: 'malware' })], [first, second]);
    expect(await overwrite(stored, [first])).toMatchObject({ status: 'overwritten' });
    expect(presetsWritten()).toEqual([presetWith('p1', { [first.id]: 'phishing' })]);
  });

  it('removes the value that its variable, as the bundle defines it, no longer accepts', async () => {
    const stored = manifestOf('Report', [presetWith('p1', { [first.id]: 'phishing', [second.id]: 'malware' })], [first, second]);
    const narrowed = { ...first, restriction: { mode: 'selection', values: ['ransomware'] }, defaultValue: 'ransomware' };
    expect(await overwrite(stored, [narrowed, second])).toMatchObject({ status: 'overwritten' });
    expect(presetsWritten()).toEqual([presetWith('p1', { [second.id]: 'malware' })]);
  });

  it('keeps the presets as they are when the variables are the same', async () => {
    const presets = [presetWith('p1', { [first.id]: 'phishing' })];
    expect(await overwrite(manifestOf('Report', presets, [first]), [first])).toMatchObject({ status: 'overwritten' });
    expect(presetsWritten()).toEqual(presets);
  });

  it('keeps the presets as they are when the bundle has no variables: the stored ones are kept too', async () => {
    const presets = [presetWith('p1', { [first.id]: 'phishing' })];
    vi.mocked(findAllWorkspaces).mockResolvedValue([workspaceOf(manifestOf('Report', presets, [first]))] as never);
    vi.mocked(findById).mockResolvedValue(workspaceOf(manifestOf('Report', presets, [first])) as never);
    expect(await importDashboard(context, user, imported, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'overwritten' });
    const written = fromB64(vi.mocked(updateAttribute).mock.calls[0][4].find(({ key }) => key === 'manifest')?.value?.[0] as string);
    expect(written.presets).toEqual(presets);
    expect(written.variables).toEqual([first]);
  });
});
