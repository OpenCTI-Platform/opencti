import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, CUSTOM_THEME_ID, itemFile, OTHER_THEME_ID, themeConfiguration, validBundleFiles } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase, lockResource } from '../../../../../src/database/redis';
import * as masterLock from '../../../../../src/lock/master-lock';
import * as settingsDomain from '../../../../../src/domain/settings';
import { getSettings, setPlatformBootstrapStatus, settingsEditField } from '../../../../../src/domain/settings';
import { addTheme, deleteTheme, findAllThemes } from '../../../../../src/modules/theme/theme-domain';
import * as fileStorage from '../../../../../src/database/file-storage';
import * as userDomain from '../../../../../src/modules/user/user-domain';
import * as userActionListener from '../../../../../src/listener/UserActionListener';
import * as sessionDomain from '../../../../../src/modules/configPreset/import/configPreset-import-session-domain';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import { CONFIG_PRESET_IMPORT_LOCK_KEY, isConfigPresetImportLocked } from '../../../../../src/modules/configPreset/import/configPreset-import-lock';

const UPLOAD_MUTATION = gql`mutation ConfigPresetLockUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetLockImport($file_id: String!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { key status reason } report_id }
  }
`;
const SESSION_QUERY = gql`query ConfigPresetLockSession { configPresetImportSession { status file_id outcome counts { failed } selections { type items } results { key status reason } } }`;
const PREVIEW_QUERY = gql`query ConfigPresetLockPreview($file_id: ID!) { configPresetImportPreview(file_id: $file_id) { openCTI_version } }`;
const SETTINGS_QUERY = gql`query ConfigPresetLockSettings { settings { id platform_title platform_bootstrap_status platform_banner_text platform_banner_level platform_language platform_favicon platform_theme { id } } }`;

const upload = async (files: Record<string, string> = validBundleFiles()) => {
  const content = await buildZip(files);
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const runImport = (fileId: string, selections: unknown[], dryRun = false) => queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections, dry_run: dryRun } });
const readSettings = async () => (await queryAsAdminWithSuccess({ query: SETTINGS_QUERY })).data?.settings;
const readSession = async () => (await queryAsAdminWithSuccess({ query: SESSION_QUERY })).data?.configPresetImportSession;
const zipExists = async (fileId: string) => (await queryAsAdmin({ query: PREVIEW_QUERY, variables: { file_id: fileId } })).errors === undefined;
const messagesImporter = () => CONFIG_PRESET_FAMILIES.find((family) => family.id === 'messages')!.importer!;
const platformImporter = () => CONFIG_PRESET_FAMILIES.find((family) => family.id === 'platform')!.importer!;
const brandingImporter = () => CONFIG_PRESET_FAMILIES.find((family) => family.id === 'branding')!.importer!;
// Fails the writes of the session that the predicate selects, and lets the others through
const failRunEvents = (shouldFail: (event: string, payload: unknown) => boolean) => {
  const realRunEvent = sessionDomain.applyConfigPresetImportRunEvent;
  return vi.spyOn(sessionDomain, 'applyConfigPresetImportRunEvent').mockImplementation(async (...args: Parameters<typeof realRunEvent>) => {
    if (shouldFail(args[3], args[4])) {
      throw new Error('redis down');
    }
    return realRunEvent(...args);
  });
};

describe('Config preset import lock', () => {
  let before: Awaited<ReturnType<typeof readSettings>>;

  beforeEach(async () => {
    before = await readSettings();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    const settings = await getSettings(testContext);
    await settingsEditField(testContext, ADMIN_USER, settings.id, [
      { key: 'platform_title', value: [before.platform_title] },
      { key: 'platform_favicon', value: [before.platform_favicon ?? ''] },
      { key: 'platform_language', value: [before.platform_language] },
      { key: 'platform_theme', value: [before.platform_theme.id] },
      { key: 'platform_banner_text', value: [before.platform_banner_text ?? ''] },
      { key: 'platform_banner_level', value: [before.platform_banner_level ?? ''] },
    ]);
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    const themes = (await findAllThemes(testContext, ADMIN_USER)).filter((theme) => !theme.built_in);
    for (let i = 0; i < themes.length; i += 1) {
      await deleteTheme(testContext, ADMIN_USER, themes[i].id);
    }
    await queryAsAdmin({ query: gql`mutation ConfigPresetLockClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const files = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history', 'config_preset/import']);
    for (let i = 0; i < files.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, files[i].id, { forceDelete: true });
    }
  });

  it('refuses a real import at once while another one runs, without writing anything, and keeps the session and the zip', async () => {
    const fileId = await upload();
    const lock = await lockResource([CONFIG_PRESET_IMPORT_LOCK_KEY]);
    try {
      expect(await isConfigPresetImportLocked()).toBe(true);
      const startedAt = Date.now();
      const { errors } = await runImport(fileId, [{ type: 'platform' }, { type: 'messages' }]);
      expect(Date.now() - startedAt).toBeLessThan(5000);
      expect(errors?.[0].extensions?.data).toMatchObject({ reason: 'import_running' });
      expect(errors?.[0].message).toEqual('An import is already running');
      const settings = await readSettings();
      expect(settings.platform_title).toEqual(before.platform_title);
      expect(settings.platform_bootstrap_status).toEqual('pending');
      expect(await zipExists(fileId)).toBe(true);
      expect(await readSession()).toMatchObject({ status: 'DRAFT', file_id: fileId });
      // A dry run and the preview take no lock
      expect((await runImport(fileId, [{ type: 'messages' }], true)).errors).toBeUndefined();
    } finally {
      await lock.unlock();
    }
    expect(await isConfigPresetImportLocked()).toBe(false);
  });

  it('accepts a new import once the previous one is over, whatever its failures', async () => {
    const first = await runImport(await upload(), [{ type: 'messages', items: ['banner'] }]);
    expect(first.errors).toBeUndefined();
    expect(await isConfigPresetImportLocked()).toBe(false);
    expect((await runImport(await upload(), [{ type: 'messages' }])).errors).toBeUndefined();
  });

  it('releases the lock and keeps the draft on an error before the transition', async () => {
    const fileId = await upload();
    expect((await runImport(fileId, [{ type: 'messages', items: ['nope'] }])).errors?.[0].message).toContain('Unknown configuration preset item');
    expect(await isConfigPresetImportLocked()).toBe(false);
    expect(await readSession()).toMatchObject({ status: 'DRAFT' });
    expect((await runImport(fileId, [{ type: 'messages' }])).errors).toBeUndefined();
  });

  it('refuses a second attempt of the same user while the first one really runs, without touching its session', async () => {
    const fileId = await upload();
    let release: () => void = () => undefined;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const original = messagesImporter().apply;
    vi.spyOn(messagesImporter(), 'apply').mockImplementationOnce(async (...args) => {
      await blocked;
      return original(...args);
    });
    const first = runImport(fileId, [{ type: 'messages' }]);
    await vi.waitFor(async () => expect((await readSession())?.status).toEqual('APPLYING'));
    const second = await runImport(fileId, [{ type: 'messages' }]);
    expect(second.errors?.[0].extensions?.data).toMatchObject({ reason: 'import_running' });
    expect((await readSession()).status).toEqual('APPLYING');
    release();
    expect((await first).errors).toBeUndefined();
    expect(await readSession()).toMatchObject({ status: 'FINISHED', outcome: 'COMPLETED' });
  });

  it('puts the session back to the draft and returns the error when it fails before the first item', async () => {
    const fileId = await upload();
    vi.spyOn(messagesImporter(), 'compute').mockRejectedValueOnce(new Error('elastic down'));
    const { errors } = await runImport(fileId, [{ type: 'messages' }]);
    expect(errors?.[0].message).toContain('elastic down');
    expect(await readSession()).toMatchObject({ status: 'DRAFT', file_id: fileId });
    expect(await isConfigPresetImportLocked()).toBe(false);
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
    expect((await runImport(fileId, [{ type: 'messages' }])).errors).toBeUndefined();
  });

  it('stops on an unexpected error between two items: the rest fails with the message, the status stays pending, the zip is kept', async () => {
    const fileId = await upload();
    vi.spyOn(messagesImporter(), 'compute').mockRejectedValueOnce(new Error('elastic down'));
    const { data, errors } = await runImport(fileId, [{ type: 'platform', items: ['platform'] }, { type: 'messages' }]);
    expect(errors).toBeUndefined();
    const results = data?.configPresetImport.results;
    expect(results.map((result: { key: string; status: string }) => `${result.key}:${result.status}`)).toEqual(['theme--11111111-2222-4333-8444-555555555555:CREATED', 'platform:OVERWRITTEN', 'banner:FAILED']);
    expect(results[2].reason).toEqual('elastic down');
    expect(await readSession()).toMatchObject({ status: 'FINISHED', outcome: 'STOPPED' });
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
    expect(await zipExists(fileId)).toBe(true);
    expect(data?.configPresetImport.report_id).toMatch(/^config_preset\/history\//);
    expect(await isConfigPresetImportLocked()).toBe(false);
  });

  it('stops when the lock is lost: the item in progress finishes, the remaining items fail', async () => {
    const fileId = await upload();
    const controller = new AbortController();
    const realLockResources = masterLock.lockResources;
    vi.spyOn(masterLock, 'lockResources').mockImplementation(async (...args: Parameters<typeof realLockResources>) => {
      return { ...(await realLockResources(...args)), signal: controller.signal };
    });
    const original = platformImporter().apply;
    vi.spyOn(platformImporter(), 'apply').mockImplementationOnce(async (...args) => {
      const applied = await original(...args);
      controller.abort({ name: 'ExecutionError' });
      return applied;
    });
    const { data, errors } = await runImport(fileId, [{ type: 'platform', items: ['platform'] }, { type: 'messages' }]);
    expect(errors).toBeUndefined();
    const results = data?.configPresetImport.results as { key: string; status: string; reason: string | null }[];
    expect(results.find((result) => result.key === 'platform')?.status).toEqual('OVERWRITTEN');
    expect(results.find((result) => result.key === 'banner')).toMatchObject({ status: 'FAILED', reason: 'Import stopped: lock lost' });
    expect(await readSession()).toMatchObject({ status: 'FINISHED', outcome: 'STOPPED' });
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
    expect(await zipExists(fileId)).toBe(true);
  });

  it('refuses a real import of a file that is no longer the one of the session', async () => {
    const fileId = await upload();
    await queryAsAdminWithSuccess({ query: gql`mutation ConfigPresetLockForget { configPresetImportSessionClear(delete_file: false) }` });
    const { errors } = await runImport(fileId, [{ type: 'messages' }]);
    expect(errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
    expect(await isConfigPresetImportLocked()).toBe(false);
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
  });

  it('records the required dependencies in the selection of their type, next to the items already selected', async () => {
    const files = {
      ...validBundleFiles(),
      [`platform_settings/branding/${OTHER_THEME_ID}.json`]: itemFile('platformSettings.branding', OTHER_THEME_ID, themeConfiguration({ standard_id: OTHER_THEME_ID, name: 'Other import theme' })),
    };
    const { data, errors } = await runImport(await upload(files), [{ type: 'platform' }, { type: 'branding', items: [OTHER_THEME_ID] }]);
    expect(errors).toBeUndefined();
    expect(data?.configPresetImport.results.map((result: { key: string }) => result.key).sort()).toEqual([CUSTOM_THEME_ID, OTHER_THEME_ID, 'platform'].sort());
    const branding = (await readSession()).selections.find((selection: { type: string }) => selection.type === 'branding');
    expect(branding.items.sort()).toEqual([CUSTOM_THEME_ID, OTHER_THEME_ID].sort());
  });

  it('releases the lock and keeps the draft when the session cannot start applying', async () => {
    const fileId = await upload();
    vi.spyOn(sessionDomain, 'applyConfigPresetImportEvent').mockRejectedValueOnce(new Error('redis down'));
    const { errors } = await runImport(fileId, [{ type: 'messages' }]);
    expect(errors?.[0].message).toContain('redis down');
    expect(await isConfigPresetImportLocked()).toBe(false);
    expect(await readSession()).toMatchObject({ status: 'DRAFT', file_id: fileId });
    expect((await runImport(fileId, [{ type: 'messages' }])).errors).toBeUndefined();
  });

  it('goes back to the draft with the error when the user who started the import no longer exists', async () => {
    const fileId = await upload();
    vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockResolvedValueOnce(undefined as never);
    const { errors } = await runImport(fileId, [{ type: 'messages' }]);
    expect(errors?.[0].message).toContain('The user who started the import no longer exists');
    expect(await readSession()).toMatchObject({ status: 'DRAFT', file_id: fileId });
    expect(await isConfigPresetImportLocked()).toBe(false);
  });

  it('returns the error of an import that fails before the first item even when the session cannot go back to the draft', async () => {
    const fileId = await upload();
    vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockResolvedValueOnce(undefined as never);
    failRunEvents((event) => event === 'ABORT');
    const { errors } = await runImport(fileId, [{ type: 'messages' }]);
    expect(errors?.[0].message).toContain('The user who started the import no longer exists');
    expect(await isConfigPresetImportLocked()).toBe(false);
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
  });

  it('reports the status an item really got when it is not the one of the preview', async () => {
    const original = brandingImporter().apply;
    // The theme is created between the preview of the item and its write: the import overwrites it, never duplicates it
    vi.spyOn(brandingImporter(), 'apply').mockImplementationOnce(async (...args) => {
      await addTheme(testContext, ADMIN_USER, { ...themeConfiguration(), standard_id: CUSTOM_THEME_ID } as never);
      return original(...args);
    });
    const { data, errors } = await runImport(await upload(), [{ type: 'platform' }]);
    expect(errors).toBeUndefined();
    const results = data?.configPresetImport.results as { key: string; status: string }[];
    expect(results.find((result) => result.key === CUSTOM_THEME_ID)?.status).toEqual('OVERWRITTEN');
    expect(results.find((result) => result.key === 'platform')?.status).toEqual('OVERWRITTEN');
    expect((await findAllThemes(testContext, ADMIN_USER)).filter((theme) => !theme.built_in)).toHaveLength(1);
  });

  it('fails an item whose write throws, and the items that depend on it, without stopping the import', async () => {
    vi.spyOn(brandingImporter(), 'apply').mockRejectedValueOnce(new Error('theme write failed'));
    const { data, errors } = await runImport(await upload(), [{ type: 'platform' }, { type: 'messages' }]);
    expect(errors).toBeUndefined();
    const results = data?.configPresetImport.results as { key: string; status: string; reason: string | null }[];
    expect(results.find((result) => result.key === CUSTOM_THEME_ID)).toMatchObject({ status: 'FAILED', reason: 'theme write failed' });
    expect(results.find((result) => result.key === 'platform')?.status).toEqual('FAILED');
    expect(results.find((result) => result.key === 'banner')?.status).toEqual('OVERWRITTEN');
    expect(await readSession()).toMatchObject({ status: 'FINISHED', outcome: 'COMPLETED' });
  });

  it('still stops the import when the results of the remaining items cannot be written in the session', async () => {
    const fileId = await upload();
    vi.spyOn(messagesImporter(), 'compute').mockRejectedValueOnce(new Error('elastic down'));
    failRunEvents((event, payload) => event === 'ITEM_PROCESSED' && (payload as { result: { reason: string } }).result.reason === 'elastic down');
    const { data, errors } = await runImport(fileId, [{ type: 'platform', items: ['platform'] }, { type: 'messages' }]);
    expect(errors).toBeUndefined();
    expect(data?.configPresetImport.results.map((result: { key: string; status: string }) => `${result.key}:${result.status}`)).toEqual([
      `${CUSTOM_THEME_ID}:CREATED`, 'platform:OVERWRITTEN', 'banner:FAILED',
    ]);
    expect(await isConfigPresetImportLocked()).toBe(false);
  });

  it('completes the import when the platform status cannot be set to completed, and keeps it pending', async () => {
    vi.spyOn(settingsDomain, 'setPlatformBootstrapStatus').mockRejectedValueOnce(new Error('elastic down'));
    const { data, errors } = await runImport(await upload(), [{ type: 'messages' }]);
    expect(errors).toBeUndefined();
    expect(data?.configPresetImport.results).toMatchObject([{ key: 'banner', status: 'OVERWRITTEN' }]);
    expect(await readSession()).toMatchObject({ status: 'FINISHED', outcome: 'COMPLETED' });
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
  });

  it('returns the result and releases the lock when the end of the import cannot be written in the session', async () => {
    failRunEvents((event) => event === 'FINISH');
    const { data, errors } = await runImport(await upload(), [{ type: 'messages' }]);
    expect(errors).toBeUndefined();
    expect(data?.configPresetImport.report_id).toMatch(/^config_preset\/history\//);
    expect(await isConfigPresetImportLocked()).toBe(false);
  });

  it('writes the report and keeps the pending zip when the zip cannot be copied next to it', async () => {
    const fileId = await upload();
    vi.spyOn(fileStorage, 'copyFile').mockResolvedValueOnce(null as never);
    const { data, errors } = await runImport(fileId, [{ type: 'messages' }]);
    expect(errors).toBeUndefined();
    expect(data?.configPresetImport.report_id).toMatch(/^config_preset\/history\//);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    expect(history.map((file) => file.name)).toEqual(['import-report.json']);
    expect(await zipExists(fileId)).toBe(true);
    expect(await readSession()).toMatchObject({ status: 'FINISHED', outcome: 'COMPLETED' });
  });

  it('returns the result when the activity event of the import cannot be published', async () => {
    const realPublish = userActionListener.publishUserAction;
    vi.spyOn(userActionListener, 'publishUserAction').mockImplementation(async (action) => {
      if (action.event_scope === 'import') {
        throw new Error('listener down');
      }
      return realPublish(action);
    });
    const { data, errors } = await runImport(await upload(), [{ type: 'messages' }]);
    expect(errors).toBeUndefined();
    expect(data?.configPresetImport.report_id).toMatch(/^config_preset\/history\//);
    expect(await readSession()).toMatchObject({ status: 'FINISHED', outcome: 'COMPLETED' });
  });
});
