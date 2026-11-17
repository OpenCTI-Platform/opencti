import { beforeEach, describe, expect, it, vi } from 'vitest';

// The overwrite of a dashboard by an import of a bundle: the dashboard is read again under the lock of its manifest (the one the presets and the
// variables are written under), so that what another writer saved since it was found is not written back.
const state = vi.hoisted(() => ({ locked: false, readUnderLock: [] as boolean[] }));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  updateAttribute: vi.fn(),
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

import { updateAttribute } from '../../../../src/database/middleware';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { findAllWorkspaces, findById } from '../../../../src/modules/workspace/workspace-domain';
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
const manifestOf = (entityType: string, presets?: unknown[]) => toB64({ config: {}, widgets: { widget1: widgetOf(entityType) }, ...(presets ? { presets } : {}) }) as string;
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
});
