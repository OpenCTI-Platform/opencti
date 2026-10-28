import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, CUSTOM_THEME_ID, itemFile, metadataFile, themeConfiguration, validBundleFiles } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { getSettings, setPlatformBootstrapStatus, settingsEditField } from '../../../../../src/domain/settings';
import { addTheme, deleteTheme, findAllThemes, findById as findThemeById } from '../../../../../src/modules/theme/theme-domain';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';
import { configPresetImport } from '../../../../../src/modules/configPreset/import/configPreset-import-engine';
import { applyConfigPresetImportRunEvent } from '../../../../../src/modules/configPreset/import/configPreset-import-session-domain';

const UPLOAD_MUTATION = gql`mutation ConfigPresetApplyUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetApplyImport($file_id: String!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) {
      results { type key status reason }
      report_id
      settings { id platform_title platform_bootstrap_status platform_theme { id name } }
    }
  }
`;
const SESSION_QUERY = gql`
  query ConfigPresetApplySession {
    configPresetImportSession { status file_id outcome report_id counts { created overwritten skipped failed } results { key status } total }
  }
`;
const SETTINGS_QUERY = gql`
  query ConfigPresetApplySettings {
    settings {
      id
      platform_title
      platform_favicon
      platform_language
      platform_banner_text
      platform_banner_level
      platform_bootstrap_status
      platform_theme { id name standard_id }
    }
  }
`;

const readSettings = async () => (await queryAsAdminWithSuccess({ query: SETTINGS_QUERY })).data?.settings;
const upload = async (files: Record<string, string>) => {
  const content = await buildZip(files);
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const runImport = (fileId: string, selections: unknown[], dryRun = false) => queryAsAdmin({
  query: IMPORT_MUTATION,
  variables: { file_id: fileId, selections, dry_run: dryRun },
});
const importData = async (fileId: string, selections: unknown[], dryRun = false) => {
  const { data, errors } = await runImport(fileId, selections, dryRun);
  expect(errors).toBeUndefined();
  return data?.configPresetImport;
};
const resultOf = (output: { results: { type: string; key: string; status: string; reason: string | null }[] }, key: string) => output.results.find((result) => result.key === key);
const ALL = [{ type: 'platform' }, { type: 'branding' }, { type: 'messages' }];

const customThemes = async () => (await findAllThemes(testContext, ADMIN_USER)).filter((theme) => !theme.built_in);

describe('Config preset import: apply', () => {
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
    const themes = await customThemes();
    for (let i = 0; i < themes.length; i += 1) {
      await deleteTheme(testContext, ADMIN_USER, themes[i].id);
    }
    await queryAsAdmin({ query: gql`mutation ConfigPresetApplyClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    for (let i = 0; i < history.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, history[i].id, { forceDelete: true });
    }
  });

  it('writes nothing on a dry run, and the results match the real import', async () => {
    const fileId = await upload(validBundleFiles());
    const dry = await importData(fileId, ALL, true);
    expect(dry.settings).toBeNull();
    expect(dry.report_id).toBeNull();
    // Required dependencies first, the platform item is expected overwritten with a new custom default theme
    expect(dry.results.map((result: { key: string }) => result.key)).toEqual([CUSTOM_THEME_ID, 'platform', 'banner']);
    expect(dry.results.map((result: { status: string }) => result.status)).toEqual(['CREATED', 'OVERWRITTEN', 'OVERWRITTEN']);
    expect(await readSettings()).toEqual(before);
    expect(await customThemes()).toHaveLength(0);
    expect((await queryAsAdminWithSuccess({ query: SESSION_QUERY })).data?.configPresetImportSession).toMatchObject({ status: 'DRAFT', file_id: fileId });
    expect(before.platform_bootstrap_status).toEqual('pending');

    const real = await importData(fileId, ALL);
    expect(real.results).toEqual(dry.results);
  });

  it('imports a blank platform: the theme is created with the bundle standard id and becomes the default', async () => {
    const fileId = await upload(validBundleFiles());
    const output = await importData(fileId, ALL);
    expect(output.results).toEqual([
      { type: 'branding', key: CUSTOM_THEME_ID, status: 'CREATED', reason: null },
      { type: 'platform', key: 'platform', status: 'OVERWRITTEN', reason: null },
      { type: 'messages', key: 'banner', status: 'OVERWRITTEN', reason: null },
    ]);
    const theme = await findThemeById(testContext, ADMIN_USER, CUSTOM_THEME_ID);
    expect(theme).toMatchObject({ name: 'Import test theme', built_in: false, standard_id: CUSTOM_THEME_ID, theme_primary: '#ff0000' });
    const settings = await readSettings();
    expect(settings).toMatchObject({ platform_title: 'Imported title', platform_language: 'fr-fr', platform_banner_text: 'Hello', platform_banner_level: 'GREEN' });
    expect(settings.platform_theme.id).toEqual(theme!.id);
    // The mutation returns the settings so that the front store learns the new values
    expect(output.settings).toMatchObject({ platform_title: 'Imported title', platform_bootstrap_status: 'completed', platform_theme: { name: 'Import test theme' } });
    expect(settings.platform_bootstrap_status).toEqual('completed');
  });

  it('overwrites on a second import of the same bundle, without duplicating the theme', async () => {
    await importData(await upload(validBundleFiles()), ALL);
    const output = await importData(await upload(validBundleFiles()), ALL);
    expect(resultOf(output, CUSTOM_THEME_ID)?.status).toEqual('OVERWRITTEN');
    expect(await customThemes()).toHaveLength(1);
  });

  describe('modes', () => {
    const OTHER_THEME_ID = 'theme--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    // The bundle theme is imported with this mode, the other items with the default one
    const BRANDING = (mode: string) => [{ type: 'platform' }, { type: 'branding', item_modes: [{ key: CUSTOM_THEME_ID, mode }] }, { type: 'messages' }];
    const twoThemes = () => ({
      ...validBundleFiles(),
      [`platform_settings/branding/${OTHER_THEME_ID}.json`]: itemFile('platformSettings.branding', OTHER_THEME_ID, themeConfiguration({ standard_id: OTHER_THEME_ID, name: 'Other import theme' })),
    });

    it('adds the themes that exist as copies under a free name with COPY, and leaves the existing theme and the default theme alone', async () => {
      await importData(await upload(validBundleFiles()), ALL);
      const output = await importData(await upload(validBundleFiles()), BRANDING('COPY'));
      expect(resultOf(output, CUSTOM_THEME_ID)).toMatchObject({ status: 'CREATED', reason: 'Added as "Import test theme (1)"' });
      // The mode of a theme does not change what the other items do
      expect(resultOf(output, 'banner')).toMatchObject({ status: 'OVERWRITTEN' });
      const themes = await customThemes();
      expect(themes.map((theme) => theme.name).sort()).toEqual(['Import test theme', 'Import test theme (1)']);
      // The original keeps the standard id of the bundle: the default theme is still the one of the bundle
      expect((await findThemeById(testContext, ADMIN_USER, CUSTOM_THEME_ID))?.name).toEqual('Import test theme');
      expect((await readSettings()).platform_theme.standard_id).toEqual(CUSTOM_THEME_ID);
    });

    it('keeps the standard id of the bundle for a theme whose name only is taken with COPY, so that the default theme resolves', async () => {
      await addTheme(testContext, ADMIN_USER, { ...themeConfiguration({ name: 'Import test theme' }), standard_id: 'theme--99999999-9999-4999-8999-999999999999' } as never);
      const output = await importData(await upload(validBundleFiles()), BRANDING('COPY'));
      expect(resultOf(output, CUSTOM_THEME_ID)).toMatchObject({ status: 'CREATED', reason: 'Added as "Import test theme (1)"' });
      expect(resultOf(output, 'platform')?.status).toEqual('OVERWRITTEN');
      expect((await findThemeById(testContext, ADMIN_USER, CUSTOM_THEME_ID))?.name).toEqual('Import test theme (1)');
      expect((await readSettings()).platform_theme.standard_id).toEqual(CUSTOM_THEME_ID);
    });

    it('expects on a dry run what the real import does', async () => {
      await importData(await upload(validBundleFiles()), ALL);
      const fileId = await upload(validBundleFiles());
      const dry = await importData(fileId, BRANDING('COPY'), true);
      expect(await customThemes()).toHaveLength(1);
      const real = await importData(fileId, BRANDING('COPY'));
      expect(real.results).toEqual(dry.results);
    });

    it('applies the mode of each item: a copy of one theme that exists, an overwrite of the other', async () => {
      await importData(await upload(twoThemes()), ALL);
      const fileId = await upload(twoThemes());
      const dry = await importData(fileId, BRANDING('COPY'), true);
      const real = await importData(fileId, BRANDING('COPY'));
      expect(real.results).toEqual(dry.results);
      expect(resultOf(real, CUSTOM_THEME_ID)).toMatchObject({ status: 'CREATED', reason: 'Added as "Import test theme (1)"' });
      expect(resultOf(real, OTHER_THEME_ID)).toMatchObject({ status: 'OVERWRITTEN', reason: null });
      expect((await customThemes()).map((theme) => theme.name).sort()).toEqual(['Import test theme', 'Import test theme (1)', 'Other import theme']);
    });

    it('refuses a mode the type does not support', async () => {
      const fileId = await upload(validBundleFiles());
      const { errors } = await runImport(fileId, [{ type: 'messages', item_modes: [{ key: 'banner', mode: 'COPY' }] }], true);
      expect(errors?.[0].message).toContain('Unsupported import mode');
    });
  });

  it('imports a required dependency left out of the selection, and leaves the unselected items untouched', async () => {
    const fileId = await upload(validBundleFiles());
    const output = await importData(fileId, [{ type: 'platform', items: ['platform'] }]);
    expect(output.results.map((result: { key: string }) => result.key)).toEqual([CUSTOM_THEME_ID, 'platform']);
    const settings = await readSettings();
    expect(settings.platform_title).toEqual('Imported title');
    expect(settings.platform_banner_text).toEqual(before.platform_banner_text);
  });

  it('fails the theme on a name clash, and the platform item with it, without stopping the other items', async () => {
    await addTheme(testContext, ADMIN_USER, { ...themeConfiguration({ name: 'Import test theme' }), standard_id: 'theme--99999999-9999-4999-8999-999999999999' } as never);
    const fileId = await upload(validBundleFiles());
    const output = await importData(fileId, ALL);
    expect(resultOf(output, CUSTOM_THEME_ID)).toMatchObject({ status: 'FAILED', reason: 'Theme name already exists' });
    expect(resultOf(output, 'platform')).toMatchObject({ status: 'FAILED', reason: 'Default theme Import test theme could not be imported' });
    expect(resultOf(output, 'banner')?.status).toEqual('OVERWRITTEN');
    const settings = await readSettings();
    expect(settings.platform_title).toEqual(before.platform_title);
    expect(settings.platform_banner_text).toEqual('Hello');
    // completed is set whatever the failures
    expect(settings.platform_bootstrap_status).toEqual('completed');
  });

  it('resolves a built-in default theme on the platform, skips the built-in theme and does not need dependencies.json', async () => {
    const [builtIn] = (await findAllThemes(testContext, ADMIN_USER)).filter((theme) => theme.built_in);
    const files = {
      'metadata.json': metadataFile(),
      'platform.json': itemFile('platformSettings.platform', 'platform', { platform_title: 'Built-in default', default_theme: { standard_id: builtIn.standard_id, name: builtIn.name } }),
      [`${builtIn.standard_id}.json`]: itemFile('platformSettings.branding', builtIn.standard_id, { standard_id: builtIn.standard_id, name: builtIn.name }),
    };
    const output = await importData(await upload(files), ALL);
    expect(resultOf(output, 'platform')?.status).toEqual('OVERWRITTEN');
    expect(resultOf(output, builtIn.standard_id)).toMatchObject({ status: 'SKIPPED' });
    const settings = await readSettings();
    expect(settings).toMatchObject({ platform_title: 'Built-in default' });
    expect(settings.platform_theme.id).toEqual(builtIn.id);
  });

  it('skips an item with only null values and fails an invalid one without touching the others', async () => {
    const files = {
      ...validBundleFiles(),
      'platform_settings/messages/login.json': itemFile('platformSettings.messages', 'login', { platform_login_message: null }),
      'platform_settings/messages/consent.json': itemFile('platformSettings.messages', 'consent', { platform_consent_message: 'x', unknown_key: true }),
    };
    const output = await importData(await upload(files), [{ type: 'messages' }]);
    expect(resultOf(output, 'login')).toMatchObject({ status: 'SKIPPED', reason: 'Nothing to import' });
    expect(resultOf(output, 'consent')?.status).toEqual('FAILED');
    expect(resultOf(output, 'banner')?.status).toEqual('OVERWRITTEN');
  });

  it('keeps the status when it is not pending (an upgraded platform)', async () => {
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'completed');
    const output = await importData(await upload(validBundleFiles()), [{ type: 'messages' }]);
    expect(output.settings.platform_bootstrap_status).toEqual('completed');
  });

  it('writes the report next to a copy of the zip, moves the session to finished, and deletes the pending zip', async () => {
    const fileId = await upload(validBundleFiles());
    const output = await importData(fileId, ALL);
    expect(output.report_id).toMatch(/^config_preset\/history\/[0-9a-f-]{36}\/import-report\.json$/);
    const history = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history']);
    expect(history.map((file) => file.name).sort()).toEqual(['bundle.zip', 'import-report.json']);
    // The pending zip is gone
    expect((await runImport(fileId, ALL, true)).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
    const session = (await queryAsAdminWithSuccess({ query: SESSION_QUERY })).data?.configPresetImportSession;
    expect(session).toMatchObject({ status: 'FINISHED', outcome: 'COMPLETED', report_id: output.report_id, total: 4, counts: { created: 1, overwritten: 3, skipped: 0, failed: 0 } });
    expect(session.results).toHaveLength(4);
  });

  it('refuses another file, a second import on the finished zip, and a user without BYPASS', async () => {
    expect((await runImport('config_preset/import/unknown/x.zip', ALL)).errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
    const fileId = await upload(validBundleFiles());
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: IMPORT_MUTATION, variables: { file_id: fileId, selections: ALL, dry_run: true } });
    expect((await runImport(fileId, [])).errors?.[0].message).toContain('Select at least one');
    expect((await runImport(fileId, [{ type: 'unknown' }])).errors?.[0].message).toContain('Unknown configuration preset type');
    expect((await runImport(fileId, [{ type: 'messages', items: ['nope'] }])).errors?.[0].message).toContain('Unknown configuration preset item');
  });

  it('refuses a bundle from a more recent platform, without touching the session or the status', async () => {
    const fileId = await upload({ ...validBundleFiles(), 'metadata.json': metadataFile('999.0.0') });
    expect((await runImport(fileId, ALL)).errors?.[0].extensions?.data).toMatchObject({ reason: 'bundle_refused' });
    expect((await queryAsAdminWithSuccess({ query: SESSION_QUERY })).data?.configPresetImportSession).toMatchObject({ status: 'DRAFT', file_id: fileId });
    expect((await readSettings()).platform_bootstrap_status).toEqual('pending');
  });

  it('goes on when the request is aborted, as the calling user', async () => {
    const fileId = await upload(validBundleFiles());
    const controller = new AbortController();
    controller.abort();
    const output = await configPresetImport({ ...testContext, requestAbortSignal: controller.signal }, ADMIN_USER, fileId, [{ type: 'messages' }], false);
    expect(output.results).toEqual([{ type: 'messages', key: 'banner', status: 'OVERWRITTEN', reason: null }]);
    expect((await readSettings()).platform_banner_text).toEqual('Hello');
  });

  it('skips the writes of a run that no longer owns the session', async () => {
    const fileId = await upload(validBundleFiles());
    await importData(fileId, [{ type: 'messages' }]);
    const stale = await applyConfigPresetImportRunEvent(testContext, ADMIN_USER, '2020-01-01T00:00:00.000Z', 'ITEM_PROCESSED', { result: { type: 'messages', key: 'x', status: 'CREATED', reason: null } });
    expect(stale).toBe(false);
    expect((await queryAsAdminWithSuccess({ query: SESSION_QUERY })).data?.configPresetImportSession.results).toHaveLength(1);
  });
});
