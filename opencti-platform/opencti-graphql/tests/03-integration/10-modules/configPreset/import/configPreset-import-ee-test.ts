import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, itemFile, metadataFile, validBundleFiles } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import * as ee from '../../../../../src/enterprise-edition/ee';
import { getSettings, setPlatformBootstrapStatus, settingsEditField } from '../../../../../src/domain/settings';
import { deleteTheme, findAllThemes } from '../../../../../src/modules/theme/theme-domain';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';

const UPLOAD_MUTATION = gql`mutation ConfigPresetEeUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetEeImport($file_id: String!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { key status reason } }
  }
`;
const PREVIEW_QUERY = gql`
  query ConfigPresetEePreview($file_id: ID!) {
    configPresetImportPreview(file_id: $file_id) { types { key items { key requiresEnterpriseEdition } } }
  }
`;
const SETTINGS_QUERY = gql`query ConfigPresetEeSettings { settings { platform_title platform_whitemark platform_bootstrap_status platform_theme { id } platform_language platform_favicon platform_banner_text platform_banner_level } }`;

const upload = async (files: Record<string, string> = validBundleFiles()) => {
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(await buildZip(files), 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const runImport = async (fileId: string, selections: unknown[], dryRun = false) => {
  const { data, errors } = await queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections, dry_run: dryRun } });
  expect(errors).toBeUndefined();
  return data?.configPresetImport.results as { key: string; status: string; reason: string | null }[];
};
const readSettings = async () => (await queryAsAdminWithSuccess({ query: SETTINGS_QUERY })).data?.settings;

describe('Config preset import: Enterprise Edition items', () => {
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
      { key: 'platform_whitemark', value: [before.platform_whitemark ?? false] },
    ]);
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    const themes = (await findAllThemes(testContext, ADMIN_USER)).filter((theme) => !theme.built_in);
    for (let i = 0; i < themes.length; i += 1) {
      await deleteTheme(testContext, ADMIN_USER, themes[i].id);
    }
    await queryAsAdmin({ query: gql`mutation ConfigPresetEeClear { configPresetImportSessionClear(delete_file: true) }` });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
    const files = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history', 'config_preset/import']);
    for (let i = 0; i < files.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, files[i].id, { forceDelete: true });
    }
  });

  it('skips the whitemark on a Community platform and goes on with the other items', async () => {
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(false);
    const results = await runImport(await upload(), [{ type: 'platform' }, { type: 'branding' }]);
    expect(results.find((result) => result.key === 'whitemark')).toMatchObject({ status: 'SKIPPED', reason: 'Enterprise Edition required' });
    expect(results.find((result) => result.key === 'platform')?.status).toEqual('OVERWRITTEN');
    const settings = await readSettings();
    expect(settings.platform_title).toEqual('Imported title');
    expect(settings.platform_whitemark).toEqual(before.platform_whitemark);
    expect(settings.platform_bootstrap_status).toEqual('completed');
  });

  it('skips the whitemark whatever its value, a null value included', async () => {
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(false);
    const files = {
      'metadata.json': metadataFile(),
      'whitemark.json': itemFile('platformSettings.branding', 'whitemark', { platform_whitemark: null }),
    };
    const results = await runImport(await upload(files), [{ type: 'branding' }]);
    expect(results).toEqual([{ key: 'whitemark', status: 'SKIPPED', reason: 'Enterprise Edition required' }]);
  });

  it('skips it in a dry run too, and writes nothing', async () => {
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(false);
    const results = await runImport(await upload(), [{ type: 'branding', items: ['whitemark'] }], true);
    expect(results).toEqual([{ key: 'whitemark', status: 'SKIPPED', reason: 'Enterprise Edition required' }]);
    expect(await readSettings()).toEqual(before);
  });

  it('writes the whitemark on an Enterprise Edition platform', async () => {
    vi.spyOn(ee, 'isEnterpriseEdition').mockResolvedValue(true);
    const results = await runImport(await upload(), [{ type: 'branding', items: ['whitemark'] }]);
    expect(results).toEqual([{ key: 'whitemark', status: 'OVERWRITTEN', reason: null }]);
    expect((await readSettings()).platform_whitemark).toBe(true);
  });

  it('exposes the requirement in the preview, true for the whitemark only and never null', async () => {
    const fileId = await upload();
    const { data, errors } = await queryAsAdmin({ query: PREVIEW_QUERY, variables: { file_id: fileId } });
    expect(errors).toBeUndefined();
    const flags = (data?.configPresetImportPreview.types as { items: { key: string; requiresEnterpriseEdition: boolean }[] }[])
      .flatMap((type) => type.items)
      .map((item) => [item.key, item.requiresEnterpriseEdition]);
    expect(flags.filter(([, required]) => required)).toEqual([['whitemark', true]]);
    expect(flags.every(([, required]) => typeof required === 'boolean')).toBe(true);
  });
});
