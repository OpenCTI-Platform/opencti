import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, CUSTOM_THEME_ID, itemFile, OTHER_THEME_ID, themeConfiguration, validBundleFiles } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsUserIsExpectedForbidden } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../../../utils/testQuery';
import { getClientBase } from '../../../../../src/database/redis';
import { getSettings } from '../../../../../src/domain/settings';
import { addTheme, deleteTheme, findAllThemes, findById as findThemeById } from '../../../../../src/modules/theme/theme-domain';

const PREVIEW_MUTATION = gql`
  mutation ConfigPresetPartialPreview($file: Upload!, $type: ID!) {
    configPresetPartialImportPreview(file: $file, type: $type) {
      bundle_name
      default_mode
      type { key modes items { key label exists conflict } }
    }
  }
`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetPartialImport($file: Upload!, $type: ID!, $items: [ID!]!, $item_modes: [ConfigPresetItemModeInput!]) {
    configPresetPartialImport(file: $file, type: $type, items: $items, item_modes: $item_modes) {
      results { type key status reason label }
      counts { created overwritten skipped failed }
    }
  }
`;

const SECOND_THEME = `platform_settings/branding/${OTHER_THEME_ID}.json`;
const bundleWithTwoThemes = () => ({
  ...validBundleFiles(),
  [SECOND_THEME]: itemFile('platformSettings.branding', OTHER_THEME_ID, themeConfiguration({ standard_id: OTHER_THEME_ID, name: 'Second partial theme' })),
});
const zipUpload = async (files: Record<string, string>) => createUploadFromBuffer(await buildZip(files), 'bundle.zip');
const preview = async (files: Record<string, string>, type = 'branding') => {
  return queryAsAdmin({ query: PREVIEW_MUTATION, variables: { file: await zipUpload(files), type } });
};
const partialImport = async (files: Record<string, string>, items: string[], itemModes?: unknown[], type = 'branding') => {
  return queryAsAdmin({ query: IMPORT_MUTATION, variables: { file: await zipUpload(files), type, items, item_modes: itemModes } });
};
const customThemes = async () => (await findAllThemes(testContext, ADMIN_USER)).filter((theme) => !theme.built_in);

describe('Config preset partial import', () => {
  let existingThemeIds: Set<string>;
  let platformTitle: string;

  beforeEach(async () => {
    existingThemeIds = new Set((await customThemes()).map(({ id }) => id));
    platformTitle = (await getSettings(testContext)).platform_title;
  });

  afterEach(async () => {
    const themes = (await customThemes()).filter(({ id }) => !existingThemeIds.has(id));
    for (let i = 0; i < themes.length; i += 1) {
      await deleteTheme(testContext, ADMIN_USER, themes[i].id);
    }
  });

  it('previews only the items of the type, with COPY as the default mode', async () => {
    const { data, errors } = await preview(bundleWithTwoThemes());
    expect(errors).toBeUndefined();
    const result = data?.configPresetPartialImportPreview;
    expect(result.bundle_name).toEqual('Test bundle');
    expect(result.default_mode).toEqual('COPY');
    expect(result.type.key).toEqual('branding');
    expect(result.type.modes).toEqual(['OVERWRITE', 'COPY']);
    expect(result.type.items.map(({ key }: { key: string }) => key).sort()).toEqual([CUSTOM_THEME_ID, OTHER_THEME_ID].sort());
    expect(result.type.items.every(({ exists }: { exists: boolean }) => !exists)).toBe(true);
  });

  it('answers a null type for a bundle without item of the type', async () => {
    const { [`platform_settings/branding/${CUSTOM_THEME_ID}.json`]: _theme, ...withoutTheme } = validBundleFiles();
    const { data, errors } = await preview(withoutTheme);
    expect(errors).toBeUndefined();
    expect(data?.configPresetPartialImportPreview.type).toBeNull();
  });

  it('imports only the selected themes and nothing of the other types, without touching the wizard session', async () => {
    const { data, errors } = await partialImport(bundleWithTwoThemes(), [OTHER_THEME_ID]);
    expect(errors).toBeUndefined();
    const output = data?.configPresetPartialImport;
    expect(output.results).toEqual([{ type: 'branding', key: OTHER_THEME_ID, status: 'CREATED', reason: null, label: 'Second partial theme' }]);
    expect(output.counts).toEqual({ created: 1, overwritten: 0, skipped: 0, failed: 0 });
    expect((await findThemeById(testContext, ADMIN_USER, OTHER_THEME_ID))?.name).toEqual('Second partial theme');
    expect(await findThemeById(testContext, ADMIN_USER, CUSTOM_THEME_ID)).toBeUndefined();
    // The platform item of the bundle is not imported
    expect((await getSettings(testContext)).platform_title).toEqual(platformTitle);
    expect(await getClientBase().get(`config_preset_import_session_${ADMIN_USER.id}`)).toBeNull();
  });

  it('adds a theme that exists as a copy by default, and overwrites it when asked', async () => {
    await addTheme(testContext, ADMIN_USER, themeConfiguration() as never);
    const conflict = await preview(validBundleFiles());
    expect(conflict.data?.configPresetPartialImportPreview.type.items[0]).toMatchObject({ key: CUSTOM_THEME_ID, exists: true, conflict: true });

    const copied = await partialImport(validBundleFiles(), [CUSTOM_THEME_ID]);
    expect(copied.errors).toBeUndefined();
    expect(copied.data?.configPresetPartialImport.results[0]).toMatchObject({ status: 'CREATED', reason: 'Added as "Import test theme (1)"' });
    expect((await customThemes()).map(({ name }) => name)).toEqual(expect.arrayContaining(['Import test theme', 'Import test theme (1)']));

    const overwritten = await partialImport(validBundleFiles(), [CUSTOM_THEME_ID], [{ key: CUSTOM_THEME_ID, mode: 'OVERWRITE' }]);
    expect(overwritten.errors).toBeUndefined();
    expect(overwritten.data?.configPresetPartialImport.counts).toEqual({ created: 0, overwritten: 1, skipped: 0, failed: 0 });
  });

  it('refuses an unknown item, an unsupported mode, a type without importer and an invalid bundle', async () => {
    expect((await partialImport(validBundleFiles(), [OTHER_THEME_ID])).errors?.[0].message).toEqual('Unknown configuration preset item');
    const addMode = await partialImport(validBundleFiles(), [CUSTOM_THEME_ID], [{ key: CUSTOM_THEME_ID, mode: 'ADD' }]);
    expect(addMode.errors?.[0].message).toEqual('Unsupported import mode for this configuration preset type');
    expect((await preview(validBundleFiles(), 'unknown')).errors?.[0].message).toEqual('This configuration type cannot be imported');
    const notAZip = await queryAsAdmin({ query: PREVIEW_MUTATION, variables: { file: createUploadFromBuffer(Buffer.from('not a zip'), 'x.zip'), type: 'branding' } });
    expect(notAZip.errors?.[0].extensions?.data).toMatchObject({ reason: 'bundle_refused' });
  });

  it('is reserved to BYPASS users', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: PREVIEW_MUTATION,
      variables: { file: await zipUpload(validBundleFiles()), type: 'branding' },
    });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, {
      query: IMPORT_MUTATION,
      variables: { file: await zipUpload(validBundleFiles()), type: 'branding', items: [CUSTOM_THEME_ID] },
    });
  });
});
