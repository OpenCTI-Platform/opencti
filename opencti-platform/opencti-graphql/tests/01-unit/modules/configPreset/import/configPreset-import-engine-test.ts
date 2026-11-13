import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/domain/settings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/domain/settings')>()),
  getSettings: vi.fn(async () => ({ platform_bootstrap_status: 'completed' })),
  setPlatformBootstrapStatus: vi.fn(async () => undefined),
}));
vi.mock('../../../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn(async () => undefined) }));
vi.mock('../../../../../src/modules/entitySetting/entitySetting-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/entitySetting/entitySetting-domain')>()),
  findAllEntitySettings: vi.fn(async () => []),
}));
vi.mock('../../../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/user/user-domain')>()),
  resolveUserByIdFromCache: vi.fn(),
}));
vi.mock('../../../../../src/modules/user/role-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/user/role-import')>()),
  importRole: vi.fn(),
}));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/configPreset/import/configPreset-import-domain')>()),
  loadConfigPresetImportZip: vi.fn(),
}));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-bundle', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/configPreset/import/configPreset-import-bundle')>()),
  readConfigPresetBundle: vi.fn(),
}));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-report', () => ({
  writeConfigPresetImportReport: vi.fn(async () => ({ reportId: 'report-id', folder: 'config_preset/history', fileName: 'report.json' })),
}));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-lock', () => ({
  withConfigPresetImportLock: vi.fn(async (_context: unknown, run: (lock: { signal: AbortSignal }) => unknown) => run({ signal: new AbortController().signal })),
}));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-running', () => ({
  endConfigPresetImportRunning: vi.fn(async () => undefined),
  findConfigPresetImportRunning: vi.fn(async () => ({})),
  startConfigPresetImportRunning: vi.fn(async () => undefined),
  updateConfigPresetImportRunning: vi.fn(async () => undefined),
}));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-session-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/configPreset/import/configPreset-import-session-domain')>()),
  applyConfigPresetImportEvent: vi.fn(async () => undefined),
  applyConfigPresetImportRunEvent: vi.fn(async () => undefined),
  readConfigPresetImportSession: vi.fn(),
}));

import { resolveUserByIdFromCache } from '../../../../../src/modules/user/user-domain';
import { importRole, roleStandardId } from '../../../../../src/modules/user/role-import';
import { groupStandardId } from '../../../../../src/modules/user/group-import';
import { bundleRefused, readConfigPresetBundle } from '../../../../../src/modules/configPreset/import/configPreset-import-bundle';
import { readConfigPresetImportSession } from '../../../../../src/modules/configPreset/import/configPreset-import-session-domain';
import { configPresetImport } from '../../../../../src/modules/configPreset/import/configPreset-import-engine';
import type { ConfigPresetBundle, ConfigPresetBundleItem } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { BYPASS } from '../../../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id', capabilities: [{ name: BYPASS }] } as AuthUser;
const FILE_ID = 'import/config_preset/bundle.zip';

const roleItem = (id: string): ConfigPresetBundleItem => ({ type: 'roles', id, path: 'security_access/roles/analyst.json', configuration: { name: 'Analyst' } });
const groupItem: ConfigPresetBundleItem = {
  type: 'groups',
  id: groupStandardId('SOC'),
  path: 'security_access/groups/soc.json',
  configuration: { name: 'SOC', roles: [{ standard_id: roleStandardId('Analyst'), name: 'Analyst' }], allowed_markings: [], default_marking: [], max_shareable_markings: [] },
};

const withBundle = (items: ConfigPresetBundleItem[]) => {
  const bundle: ConfigPresetBundle = { metadata: { openCTI_version: '7.0.0', generated_at: '2026-11-05T00:00:00.000Z', bundle_name: null }, items, dependencies: {}, ignored: [] };
  vi.mocked(readConfigPresetBundle).mockResolvedValue(bundle);
};

// The role imported as COPY, then its group: the role fails, so the group must not get the local role of the same name
const importInCopy = (roleId: string) => configPresetImport(context, user, FILE_ID, [
  { type: 'roles', item_modes: [{ key: roleId, mode: ConfigImportMode.Copy }] },
  { type: 'groups', item_modes: [{ key: groupItem.id, mode: ConfigImportMode.Copy }] },
], false);

beforeEach(() => {
  vi.mocked(resolveUserByIdFromCache).mockResolvedValue(user as never);
  vi.mocked(readConfigPresetImportSession).mockResolvedValue({ file_id: FILE_ID } as never);
  vi.mocked(importRole).mockReset();
});

describe('Config preset real import of a role in COPY and a group that depends on it', () => {
  it('fails the group when the role fails while it is written', async () => {
    const id = roleStandardId('Analyst');
    withBundle([roleItem(id), groupItem]);
    vi.mocked(importRole).mockImplementation(async (_context, _user, _configuration, { dryRun }) => {
      if (!dryRun) {
        throw new Error('Elasticsearch is unavailable');
      }
      return { status: 'created', exists: true, targetId: roleStandardId('Analyst (1)'), grantsSensitiveRights: false };
    });
    const { results } = await importInCopy(id);
    expect(results.map(({ type, status, reason }) => [type, status, reason])).toEqual([
      ['roles', 'FAILED', 'Elasticsearch is unavailable'],
      ['groups', 'FAILED', 'Roles could not be imported: Analyst'],
    ]);
  });

  it('fails the group when the role fails while it is computed', async () => {
    const id = roleStandardId('Analyst');
    withBundle([roleItem(id), groupItem]);
    vi.mocked(importRole).mockRejectedValue(new Error('Elasticsearch is unavailable'));
    const { results } = await importInCopy(id);
    expect(results.map(({ type, status }) => [type, status])).toEqual([['roles', 'FAILED'], ['groups', 'FAILED']]);
    expect(results[1].reason).toEqual('Roles could not be imported: Analyst');
  });

  it('fails the group when the bundle id of the role is not the standard id of its name', async () => {
    const id = roleStandardId('Analyst');
    withBundle([{ ...roleItem(id), configuration: { name: 'Hunter' } }, groupItem]);
    const { results } = await importInCopy(id);
    expect(results.map(({ type, status, reason }) => [type, status, reason])).toEqual([
      ['roles', 'FAILED', 'The standard id of the role does not match its name'],
      ['groups', 'FAILED', 'Roles could not be imported: Analyst'],
    ]);
    expect(importRole).not.toHaveBeenCalled();
  });
});

describe('Config preset real import of a bundle that cannot be read to the end', () => {
  const named = (name: string): ConfigPresetBundleItem => ({ type: 'roles', id: roleStandardId(name), path: `security_access/roles/${name}.json`, configuration: { name } });

  it('stops at the item that refuses the bundle, and fails the next ones with the same reason without reading them', async () => {
    withBundle([named('Analyst'), named('Hunter'), named('Responder')]);
    vi.mocked(importRole).mockImplementation(async (_context, _user, configuration) => {
      if ((configuration as { name: string }).name === 'Hunter') {
        throw bundleRefused('The configuration bundle is too large once extracted');
      }
      return { status: 'created', exists: false, grantsSensitiveRights: false };
    });
    const { results } = await configPresetImport(context, user, FILE_ID, [{ type: 'roles' }], false);
    expect(results.map(({ status, reason }) => [status, reason])).toEqual([
      ['CREATED', null],
      ['FAILED', 'The configuration bundle is too large once extracted'],
      ['FAILED', 'The configuration bundle is too large once extracted'],
    ]);
    expect(vi.mocked(importRole).mock.calls.some(([, , configuration]) => (configuration as { name: string }).name === 'Responder')).toBe(false);
  });
});
