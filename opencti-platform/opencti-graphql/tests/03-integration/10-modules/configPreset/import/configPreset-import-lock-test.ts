import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, validBundleFiles } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase, lockResource } from '../../../../../src/database/redis';
import * as masterLock from '../../../../../src/lock/master-lock';
import { getSettings, setPlatformBootstrapStatus, settingsEditField } from '../../../../../src/domain/settings';
import { deleteTheme, findAllThemes } from '../../../../../src/modules/theme/theme-domain';
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
const SESSION_QUERY = gql`query ConfigPresetLockSession { configPresetImportSession { status file_id outcome counts { failed } results { key status reason } } }`;
const PREVIEW_QUERY = gql`query ConfigPresetLockPreview($file_id: ID!) { configPresetImportPreview(file_id: $file_id) { openCTI_version } }`;
const SETTINGS_QUERY = gql`query ConfigPresetLockSettings { settings { id platform_title platform_bootstrap_status platform_banner_text platform_banner_level platform_language platform_favicon platform_theme { id } } }`;

const upload = async () => {
  const content = await buildZip(validBundleFiles());
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const runImport = (fileId: string, selections: unknown[], dryRun = false) => queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections, dry_run: dryRun } });
const readSettings = async () => (await queryAsAdminWithSuccess({ query: SETTINGS_QUERY })).data?.settings;
const readSession = async () => (await queryAsAdminWithSuccess({ query: SESSION_QUERY })).data?.configPresetImportSession;
const zipExists = async (fileId: string) => (await queryAsAdmin({ query: PREVIEW_QUERY, variables: { file_id: fileId } })).errors === undefined;
const messagesImporter = () => CONFIG_PRESET_FAMILIES.find((family) => family.id === 'messages')!.importer!;
const platformImporter = () => CONFIG_PRESET_FAMILIES.find((family) => family.id === 'platform')!.importer!;

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
});
