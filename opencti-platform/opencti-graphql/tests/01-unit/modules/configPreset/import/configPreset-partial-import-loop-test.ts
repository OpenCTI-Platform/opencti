import { Readable } from 'node:stream';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const enterpriseEdition = vi.hoisted(() => ({ enabled: true }));
vi.mock('../../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/enterprise-edition/ee')>()),
  isEnterpriseEditionUpToDate: vi.fn(async () => enterpriseEdition.enabled),
}));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-lock', () => ({ withConfigPresetImportLock: vi.fn() }));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/configPreset/import/configPreset-import-engine')>()),
  importConfigPresetItem: vi.fn(),
}));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/configPreset/import/configPreset-import-utils')>()),
  reloadConfigPresetImportUser: vi.fn(),
}));
vi.mock('../../../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../../../src/modules/configPreset/import/configPreset-import-running', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/configPreset/import/configPreset-import-running')>()),
  startConfigPresetImportRunning: vi.fn(),
  updateConfigPresetImportRunning: vi.fn(),
  endConfigPresetImportRunning: vi.fn(),
}));
vi.mock('../../../../../src/modules/theme/theme-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/theme/theme-domain')>()),
  findById: vi.fn(),
  checkExistingTheme: vi.fn(),
  addTheme: vi.fn(),
  fieldPatchTheme: vi.fn(),
}));

import { publishUserAction } from '../../../../../src/listener/UserActionListener';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import * as engine from '../../../../../src/modules/configPreset/import/configPreset-import-engine';
import { importConfigPresetItem } from '../../../../../src/modules/configPreset/import/configPreset-import-engine';
import { withConfigPresetImportLock } from '../../../../../src/modules/configPreset/import/configPreset-import-lock';
import {
  endConfigPresetImportRunning,
  startConfigPresetImportRunning,
  updateConfigPresetImportRunning,
} from '../../../../../src/modules/configPreset/import/configPreset-import-running';
import type { ConfigPresetImportItemResult } from '../../../../../src/modules/configPreset/import/configPreset-import-session';
import { CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import { reloadConfigPresetImportUser } from '../../../../../src/modules/configPreset/import/configPreset-import-utils';
import { configPresetPartialImport, configPresetPartialImportPreview } from '../../../../../src/modules/configPreset/import/configPreset-partial-import';
import { addTheme, checkExistingTheme, fieldPatchTheme, findById } from '../../../../../src/modules/theme/theme-domain';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { BYPASS } from '../../../../../src/utils/access';
import { buildZip, CUSTOM_THEME_ID, itemFile, metadataFile, OTHER_THEME_ID, themeConfiguration } from '../../../../utils/configPresetBundle';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id', capabilities: [{ name: BYPASS }] } as unknown as AuthUser;

// A bundle with two themes and the whitemark, a setting of the Enterprise Edition
const bundleFiles = () => ({
  'metadata.json': metadataFile(),
  [`platform_settings/branding/${CUSTOM_THEME_ID}.json`]: itemFile('platformSettings.branding', CUSTOM_THEME_ID, themeConfiguration()),
  [`platform_settings/branding/${OTHER_THEME_ID}.json`]: itemFile('platformSettings.branding', OTHER_THEME_ID, themeConfiguration({ standard_id: OTHER_THEME_ID, name: 'Second theme' })),
  'platform_settings/whitemark.json': itemFile('platformSettings.whitemark', 'whitemark', { platform_whitemark: true }),
});
const upload = async () => {
  const zip = await buildZip(bundleFiles());
  return Promise.resolve({ createReadStream: () => Readable.from([zip]), filename: 'bundle.zip' });
};
const result = (key: string, status: ConfigPresetImportItemResult['status'], reason: string | null = null): ConfigPresetImportItemResult => ({
  type: 'branding',
  key,
  status,
  reason,
  label: key,
  translatable: false,
});
const importThemes = async (ids: string[] = [CUSTOM_THEME_ID, OTHER_THEME_ID]) => configPresetPartialImport(context, user, upload(), 'branding', ids, []);

let lockController: AbortController;

beforeEach(() => {
  vi.resetAllMocks();
  enterpriseEdition.enabled = true;
  lockController = new AbortController();
  vi.mocked(withConfigPresetImportLock).mockImplementation(async (_context, fn) => fn({ signal: lockController.signal } as never));
  vi.mocked(reloadConfigPresetImportUser).mockResolvedValue(user);
  vi.mocked(findById).mockResolvedValue(undefined as never);
  vi.mocked(checkExistingTheme).mockResolvedValue(false);
});

describe('Config preset partial import: the loop', () => {
  it('refuses an empty selection, before any item is imported or audited', async () => {
    await expect(importThemes([])).rejects.toThrow('Select at least one configuration item to import');
    expect(importConfigPresetItem).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
  });

  it('fails the remaining items when the lock is lost, the item in progress keeps its result', async () => {
    vi.mocked(importConfigPresetItem).mockImplementationOnce(async () => {
      lockController.abort();
      return result(CUSTOM_THEME_ID, 'CREATED');
    });
    const output = await importThemes();
    expect(output.results).toEqual([
      result(CUSTOM_THEME_ID, 'CREATED'),
      { type: 'branding', key: OTHER_THEME_ID, status: 'FAILED', reason: 'Import stopped: lock lost', label: OTHER_THEME_ID, translatable: false },
    ]);
    expect(importConfigPresetItem).toHaveBeenCalledTimes(1);
    expect(output.counts).toEqual({ created: 1, overwritten: 0, skipped: 0, failed: 1 });
  });

  it('goes on after a failed item', async () => {
    vi.mocked(importConfigPresetItem)
      .mockResolvedValueOnce(result(CUSTOM_THEME_ID, 'FAILED', 'Theme name already exists'))
      .mockResolvedValueOnce(result(OTHER_THEME_ID, 'CREATED'));
    const output = await importThemes();
    expect(importConfigPresetItem).toHaveBeenCalledTimes(2);
    expect(output.results.map(({ key, status }) => `${key}:${status}`)).toEqual([`${CUSTOM_THEME_ID}:FAILED`, `${OTHER_THEME_ID}:CREATED`]);
    expect(output.counts).toEqual({ created: 1, overwritten: 0, skipped: 0, failed: 1 });
  });

  it('audits a successful import with the type, the uploaded file and the counts', async () => {
    vi.mocked(importConfigPresetItem)
      .mockResolvedValueOnce(result(CUSTOM_THEME_ID, 'CREATED'))
      .mockResolvedValueOnce(result(OTHER_THEME_ID, 'CREATED'));
    const output = await importThemes();
    expect(output.counts).toEqual({ created: 2, overwritten: 0, skipped: 0, failed: 0 });
    expect(publishUserAction).toHaveBeenCalledTimes(1);
    expect(publishUserAction).toHaveBeenCalledWith({
      user,
      event_type: 'command',
      event_access: 'administration',
      event_scope: 'import',
      context_data: { file_id: null, path: '', file_name: 'bundle.zip', input: { type: 'branding', counts: output.counts } },
    });
  });

  it('does not fail the import when the audit event cannot be published', async () => {
    vi.mocked(importConfigPresetItem).mockResolvedValue(result(CUSTOM_THEME_ID, 'CREATED'));
    vi.mocked(publishUserAction).mockRejectedValue(new Error('listener down'));
    const output = await importThemes([CUSTOM_THEME_ID]);
    expect(output.results).toEqual([result(CUSTOM_THEME_ID, 'CREATED')]);
  });
});

describe('Config preset partial import: the running record', () => {
  it('writes the running record before the first item, updates it after each one and deletes it at the end', async () => {
    const calls: string[] = [];
    vi.mocked(startConfigPresetImportRunning).mockImplementation(async (_context, _user, _startedAt, total) => {
      calls.push(`start:${total}`);
    });
    vi.mocked(importConfigPresetItem).mockImplementation(async (_context, _user, item) => {
      calls.push(`item:${item.id}`);
      return result(item.id, 'CREATED');
    });
    vi.mocked(updateConfigPresetImportRunning).mockImplementation(async (_user, _startedAt, processed) => {
      calls.push(`update:${processed}`);
    });
    vi.mocked(endConfigPresetImportRunning).mockImplementation(async (_user, _startedAt, hasFinished) => {
      calls.push(`end:${hasFinished}`);
    });
    await importThemes();
    expect(calls).toEqual(['start:2', `item:${CUSTOM_THEME_ID}`, 'update:1', `item:${OTHER_THEME_ID}`, 'update:2', 'end:true']);
    // The same run all along: the record of another run is never touched
    const startedAt = vi.mocked(startConfigPresetImportRunning).mock.calls[0][2];
    expect(vi.mocked(startConfigPresetImportRunning).mock.calls[0][1]).toBe(user);
    expect(vi.mocked(endConfigPresetImportRunning)).toHaveBeenCalledWith(user, startedAt, true);
    expect(vi.mocked(updateConfigPresetImportRunning).mock.calls.every(([, at]) => at === startedAt)).toBe(true);
  });

  it('deletes the running record of a stopped import too', async () => {
    vi.mocked(importConfigPresetItem).mockImplementationOnce(async () => {
      lockController.abort();
      return result(CUSTOM_THEME_ID, 'CREATED');
    });
    await importThemes();
    expect(endConfigPresetImportRunning).toHaveBeenCalledWith(user, expect.any(String), true);
  });

  it('writes no running record, and nothing at all, when the lock was lost while the zip was read', async () => {
    // The lock is lost while the upload is read: another import may hold it and own the running record by now
    vi.mocked(withConfigPresetImportLock).mockImplementation(async (_context, fn) => {
      lockController.abort();
      return fn({ signal: lockController.signal } as never);
    });
    await expect(importThemes()).rejects.toThrow('Import stopped: lock lost');
    expect(startConfigPresetImportRunning).not.toHaveBeenCalled();
    expect(endConfigPresetImportRunning).not.toHaveBeenCalled();
    expect(importConfigPresetItem).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
  });

  it('imports nothing when the running record cannot be written', async () => {
    vi.mocked(startConfigPresetImportRunning).mockRejectedValue(new Error('redis down'));
    await expect(importThemes()).rejects.toThrow('redis down');
    expect(importConfigPresetItem).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
  });

  it('writes no running record for an empty selection, nor for a preview', async () => {
    await expect(importThemes([])).rejects.toThrow('Select at least one configuration item to import');
    await configPresetPartialImportPreview(context, user, upload(), 'branding');
    expect(startConfigPresetImportRunning).not.toHaveBeenCalled();
    expect(endConfigPresetImportRunning).not.toHaveBeenCalled();
  });
});

describe('Config preset partial import: the preview', () => {
  it('writes nothing, publishes no audit event and takes no lock', async () => {
    const preview = await configPresetPartialImportPreview(context, user, upload(), 'branding');
    expect(preview.type?.items.map(({ key }) => key).sort()).toEqual([CUSTOM_THEME_ID, OTHER_THEME_ID].sort());
    expect(addTheme).not.toHaveBeenCalled();
    expect(fieldPatchTheme).not.toHaveBeenCalled();
    expect(importConfigPresetItem).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
    expect(withConfigPresetImportLock).not.toHaveBeenCalled();
  });
});

describe('Config preset partial import: the preview of a theme whose name only is taken', () => {
  it('shows it in conflict, so that the dialog marks it and offers the choice of the mode', async () => {
    // No theme has its standard id, another one has its name: COPY, the default of a partial import, would add it as "Import test theme (1)"
    vi.mocked(checkExistingTheme).mockImplementation(async (_context, _user, name) => name === 'Import test theme');
    const preview = await configPresetPartialImportPreview(context, user, upload(), 'branding');
    expect(preview.default_mode).toBe('COPY');
    expect(preview.type?.items.find(({ key }) => key === CUSTOM_THEME_ID)).toMatchObject({ exists: false, conflict: true });
    expect(preview.type?.items.find(({ key }) => key === OTHER_THEME_ID)).toMatchObject({ exists: false, conflict: false });
  });
});

describe('Config preset partial import: Enterprise Edition', () => {
  const whitemark = () => CONFIG_PRESET_FAMILIES.find((family) => family.id === 'whitemark')!;

  it('previews a family locked by the Enterprise Edition as locked, without its items', async () => {
    enterpriseEdition.enabled = false;
    const compute = vi.spyOn(whitemark().importer!, 'compute');
    const preview = await configPresetPartialImportPreview(context, user, upload(), 'whitemark');
    expect(preview.type).toMatchObject({ key: 'whitemark', lockedByEnterpriseEdition: true, items: [] });
    expect(compute).not.toHaveBeenCalled();
  });

  it('skips an item of a family locked by the Enterprise Edition, without calling its importer', async () => {
    enterpriseEdition.enabled = false;
    // The real step of an item, as the import runs it
    const actualEngine = await vi.importActual<typeof engine>('../../../../../src/modules/configPreset/import/configPreset-import-engine');
    vi.mocked(importConfigPresetItem).mockImplementation(actualEngine.importConfigPresetItem);
    const compute = vi.spyOn(whitemark().importer!, 'compute');
    const apply = vi.spyOn(whitemark().importer!, 'apply');
    const output = await configPresetPartialImport(context, user, upload(), 'whitemark', ['whitemark'], []);
    expect(output.results).toHaveLength(1);
    expect(output.results[0]).toMatchObject({ type: 'whitemark', key: 'whitemark', status: 'SKIPPED', reason: CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED });
    expect(compute).not.toHaveBeenCalled();
    expect(apply).not.toHaveBeenCalled();
  });
});
