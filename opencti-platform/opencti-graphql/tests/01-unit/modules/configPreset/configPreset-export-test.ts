import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';
// @ts-expect-error unzipper ships no type declarations
import unzipper from 'unzipper';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  topEntitiesList: vi.fn(),
  fullEntitiesList: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/database/file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/file-storage')>()),
  uploadToStorage: vi.fn(),
}));
vi.mock('../../../../src/listener/UserActionListener', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/listener/UserActionListener')>()),
  publishUserAction: vi.fn(),
}));
vi.mock('../../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/manager/telemetryManager')>()),
  addConfigPresetExportCount: vi.fn(),
}));

import { fullEntitiesList, topEntitiesList } from '../../../../src/database/middleware-loader';
import { uploadToStorage } from '../../../../src/database/file-storage';
import { publishUserAction, type UserConfigPresetExportActionContextData } from '../../../../src/listener/UserActionListener';
import { addConfigPresetExportCount } from '../../../../src/manager/telemetryManager';
import { PLATFORM_VERSION } from '../../../../src/config/conf';
import '../../../../src/modules/attributes/internalObject-registrationAttributes';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_ACTIVITY } from '../../../../src/schema/internalObject';
import type { ObjectAttribute } from '../../../../src/schema/attribute-definition';
import {
  addConfigPresetDependencies,
  buildConfigPresetDependencies,
  configPresetExport,
  resolveConfigPresetSelections,
} from '../../../../src/modules/configPreset/configPreset-domain';
import { CONFIG_PRESET_FAMILIES } from '../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetItemDefinition } from '../../../../src/modules/configPreset/configPreset-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { builtInTheme, customTheme, mockThemeLoaders, otherCustomTheme } from './configPreset-themes-fixtures';

const context = { source: 'test' } as AuthContext;
const draftContext = { source: 'test', draft_context: 'draft-id' } as AuthContext;
const bypassUser = { id: 'admin-id', capabilities: [{ name: 'BYPASS' }] } as AuthUser;
const settingsUser = { id: 'settings-id', capabilities: [{ name: 'SETTINGS_SETPARAMETERS' }, { name: 'KNOWLEDGE' }] } as AuthUser;

const MESSAGE_IDS = ['banner', 'login', 'consent', 'noAccess'];
const ALL_CATEGORIES = [
  { type: 'platform', items: ['platform'] },
  { type: 'messages', items: MESSAGE_IDS },
  { type: 'hiddenEntityTypes', items: ['hiddenEntityTypes'] },
];
const ALL_FILES = [
  'data_model/hidden_entity_types.json',
  'dependencies.json',
  'metadata.json',
  'platform_settings/messages/banner.json',
  'platform_settings/messages/consent.json',
  'platform_settings/messages/login.json',
  'platform_settings/messages/noAccess.json',
  'platform_settings/platform.json',
];
const ALL_ITEMS = { platform: ['platform'], messages: MESSAGE_IDS, hiddenEntityTypes: ['hiddenEntityTypes'] };
const ALL_COUNTS = { platform: 1, messages: 4, hiddenEntityTypes: 1 };
const NOW = new Date('2026-10-14T09:05:07.123Z');
const EXPECTED_FILE_NAME = `opencti-config-20261014-090507-${PLATFORM_VERSION}.zip`;
const EXPORT_FOLDER = /^config_preset\/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TMP_ZIP_MARKER = 'opencti-config-preset-';

const storedSettings = {
  id: 'settings-id',
  platform_title: 'My platform',
  platform_favicon: null,
  platform_language: 'en-us',
  platform_banner_text: 'Banner',
  platform_banner_level: 'GREEN',
  platform_login_message: 'Hello',
  platform_consent_message: 'Consent',
  platform_consent_confirm_text: 'I agree',
  platform_no_access_message: 'No access',
  platform_theme: builtInTheme.id,
  platform_whitemark: true,
  enterprise_license: 'secret-license',
};
const withDefaultTheme = (themeId: string) => vi.mocked(topEntitiesList).mockResolvedValue([{ ...storedSettings, platform_theme: themeId }] as never);

// The temporary zip paths, from the write streams the export opened
const realCreateWriteStream = fs.createWriteStream;
let createWriteStreamSpy: MockInstance<typeof fs.createWriteStream>;
const tmpZipPaths = () => createWriteStreamSpy.mock.calls.map(([p]) => String(p)).filter((p) => p.includes(TMP_ZIP_MARKER));

// Reads the uploaded stream like the storage would, and keeps the zip to inspect it
let uploadedZip: Buffer | undefined;
let tmpFileModeDuringUpload: number | undefined;
const mockUploadReadingTheZip = () => {
  vi.mocked(uploadToStorage).mockImplementation(async (_ctx, _user, filePath, fileUpload) => {
    const [tmpZipPath] = tmpZipPaths();
    tmpFileModeDuringUpload = fs.existsSync(tmpZipPath) ? fs.statSync(tmpZipPath).mode & 0o777 : undefined;
    const chunks: Buffer[] = [];
    for await (const chunk of fileUpload.createReadStream()) {
      chunks.push(chunk as Buffer);
    }
    uploadedZip = Buffer.concat(chunks);
    const id = `${filePath}/${fileUpload.filename}`;
    return { upload: { id, name: fileUpload.filename } as never, untouched: false };
  });
};

const readZip = async (zip: Buffer) => {
  const directory = await unzipper.Open.buffer(zip);
  const entries: Record<string, any> = {};
  for (let i = 0; i < directory.files.length; i += 1) {
    const file: { path: string; buffer: () => Promise<Buffer> } = directory.files[i];
    entries[file.path] = JSON.parse((await file.buffer()).toString('utf8'));
  }
  return entries;
};

// What the last export reported to the activity log
const publishedSummary = () => (vi.mocked(publishUserAction).mock.calls.at(-1)![0].context_data as UserConfigPresetExportActionContextData).input;

const expectNothingWritten = () => {
  expect(tmpZipPaths()).toEqual([]);
  expect(uploadToStorage).not.toHaveBeenCalled();
  expect(publishUserAction).not.toHaveBeenCalled();
};

describe('Config preset export', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    createWriteStreamSpy = vi.spyOn(fs, 'createWriteStream');
    uploadedZip = undefined;
    tmpFileModeDuringUpload = undefined;
    vi.mocked(topEntitiesList).mockResolvedValue([storedSettings] as never);
    mockThemeLoaders([{ target_type: 'Channel', platform_hidden_type: true }]);
    mockUploadReadingTheZip();
  });

  afterEach(() => {
    const paths = tmpZipPaths();
    vi.useRealTimers();
    vi.restoreAllMocks();
    paths.forEach((p) => fs.rmSync(p, { force: true }));
  });

  it('builds a zip with one JSON file per selected item and its metadata', async () => {
    await configPresetExport(context, bypassUser, ALL_CATEGORIES, '  My\u0007 bundle / v1 ');
    const entries = await readZip(uploadedZip!);
    expect(Object.keys(entries).sort()).toEqual(ALL_FILES);
    // Only what the bundle needs to be identified, the content is the files
    expect(entries['metadata.json']).toEqual({
      openCTI_version: PLATFORM_VERSION,
      generated_at: NOW.toISOString(),
      bundle_name: 'My bundle v1',
    });
    expect(entries['platform_settings/platform.json']).toEqual({
      openCTI_version: PLATFORM_VERSION,
      type: 'platformSettings.platform',
      id: 'platform',
      // A built-in default theme is named, without dependency
      configuration: { platform_title: 'My platform', platform_favicon: null, platform_language: 'en-us', default_theme: { standard_id: builtInTheme.standard_id, name: 'Filigran Dark' } },
    });
    expect(entries['platform_settings/messages/banner.json']).toEqual({
      openCTI_version: PLATFORM_VERSION,
      type: 'platformSettings.messages',
      id: 'banner',
      configuration: { platform_banner_text: 'Banner', platform_banner_level: 'GREEN' },
    });
    expect(entries['data_model/hidden_entity_types.json']).toMatchObject({
      type: 'dataModel.hiddenEntityTypes',
      id: 'hiddenEntityTypes',
      configuration: { hidden_entity_types: ['Channel'] },
    });
    // No item has dependencies
    expect(entries['dependencies.json']).toEqual({});
    expect(JSON.stringify(entries)).not.toContain('secret-license');
  });

  it('only writes the selected items and merges duplicated selections', async () => {
    await configPresetExport(context, bypassUser, [
      { type: 'messages', items: ['banner'] },
      { type: 'messages', items: ['banner'] },
      { type: 'platform', items: ['platform'] },
    ]);
    const entries = await readZip(uploadedZip!);
    expect(Object.keys(entries).sort()).toEqual(['dependencies.json', 'metadata.json', 'platform_settings/messages/banner.json', 'platform_settings/platform.json']);
    expect(entries['metadata.json'].bundle_name).toBeNull();
    // Registry order, not selection order
    expect(publishedSummary()).toMatchObject({ entity_types: ['platform', 'messages'], counts: { platform: 1, messages: 1 }, items: { platform: ['platform'], messages: ['banner'] } });
  });

  it('keeps the exported items out of the metadata, for a partial selection too', async () => {
    await configPresetExport(context, bypassUser, [{ type: 'messages', items: ['login', 'noAccess'] }]);
    const entries = await readZip(uploadedZip!);
    expect(Object.keys(entries).sort()).toEqual(['dependencies.json', 'metadata.json', 'platform_settings/messages/login.json', 'platform_settings/messages/noAccess.json']);
    expect(entries['metadata.json']).toEqual({
      openCTI_version: PLATFORM_VERSION,
      generated_at: NOW.toISOString(),
      bundle_name: null,
    });
    expect(publishedSummary()).toMatchObject({ entity_types: ['messages'], counts: { messages: 2 }, items: { messages: ['login', 'noAccess'] } });
  });

  it('exports every item of the type when items is omitted', async () => {
    await configPresetExport(context, bypassUser, [{ type: 'platform' }, { type: 'messages' }, { type: 'hiddenEntityTypes' }]);
    const entries = await readZip(uploadedZip!);
    expect(Object.keys(entries).sort()).toEqual(ALL_FILES);
    expect(publishedSummary().items).toEqual(ALL_ITEMS);
  });

  it('stores each export in its own random folder under config_preset, with a dated and versioned name', async () => {
    const first = await configPresetExport(context, bypassUser, ALL_CATEGORIES);
    const second = await configPresetExport(context, bypassUser, ALL_CATEGORIES);
    const firstFolder = path.posix.dirname(first.id);
    const secondFolder = path.posix.dirname(second.id);
    expect(firstFolder).toMatch(EXPORT_FOLDER);
    expect(secondFolder).toMatch(EXPORT_FOLDER);
    // Same second, same name, no collision
    expect(secondFolder).not.toBe(firstFolder);
    expect(path.posix.basename(first.id)).toBe(EXPECTED_FILE_NAME);
    expect(path.posix.basename(second.id)).toBe(EXPECTED_FILE_NAME);
    expect(uploadToStorage).toHaveBeenNthCalledWith(
      1,
      context,
      bypassUser,
      firstFolder,
      expect.objectContaining({ filename: EXPECTED_FILE_NAME }),
      expect.objectContaining({ noTriggerImport: true }),
    );
  });

  it('publishes an export command user action and counts the export in telemetry', async () => {
    const file = await configPresetExport(context, bypassUser, ALL_CATEGORIES);
    expect(publishUserAction).toHaveBeenCalledTimes(1);
    const action = vi.mocked(publishUserAction).mock.calls[0][0];
    expect(action).toMatchObject({ user: bypassUser, event_type: 'command', event_scope: 'export', event_access: 'administration' });
    // The activity log maps the context data field by field: the summary is in the free-form input
    expect(action.context_data).toEqual({
      path: path.posix.dirname(file.id),
      file_name: EXPECTED_FILE_NAME,
      input: {
        entity_types: ['platform', 'messages', 'hiddenEntityTypes'],
        counts: ALL_COUNTS,
        items: ALL_ITEMS,
      },
    });
    expect(addConfigPresetExportCount).toHaveBeenCalledTimes(1);
  });

  it('only publishes context data fields that the activity index maps', async () => {
    // The mapping of the context data is strict: an unknown field makes the indexing of the event fail
    await configPresetExport(context, bypassUser, ALL_CATEGORIES);
    const contextData = vi.mocked(publishUserAction).mock.calls[0][0].context_data as object;
    const contextDataAttribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_ACTIVITY, 'context_data') as ObjectAttribute;
    const mappedFields = contextDataAttribute.mappings.map(({ name }) => name);
    expect(mappedFields).toContain('input');
    Object.keys(contextData).forEach((field) => expect(mappedFields).toContain(field));
  });

  it('writes the temporary zip readable by its owner only and removes it once uploaded', async () => {
    await configPresetExport(context, bypassUser, ALL_CATEGORIES);
    expect(createWriteStreamSpy).toHaveBeenCalledWith(expect.stringContaining(TMP_ZIP_MARKER), { mode: 0o600 });
    expect(tmpFileModeDuringUpload).toBe(0o600);
    expect(tmpZipPaths()).toHaveLength(1);
    expect(fs.existsSync(tmpZipPaths()[0])).toBe(false);
  });

  it('removes the temporary zip and stores nothing when an exporter fails', async () => {
    vi.mocked(topEntitiesList).mockRejectedValue(new Error('engine down'));
    await expect(configPresetExport(context, bypassUser, ALL_CATEGORIES)).rejects.toThrow('engine down');
    expect(fs.existsSync(tmpZipPaths()[0])).toBe(false);
    expect(uploadToStorage).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
    expect(addConfigPresetExportCount).not.toHaveBeenCalled();
  });

  it('removes the temporary zip when the upload fails', async () => {
    vi.mocked(uploadToStorage).mockRejectedValue(new Error('storage down'));
    await expect(configPresetExport(context, bypassUser, ALL_CATEGORIES)).rejects.toThrow('storage down');
    expect(fs.existsSync(tmpZipPaths()[0])).toBe(false);
    expect(publishUserAction).not.toHaveBeenCalled();
  });

  it('reports an output stream error raised while items are exported, without an unhandled rejection', async () => {
    const unhandledRejection = vi.fn();
    process.on('unhandledRejection', unhandledRejection);
    try {
      // The reads of a complete export (settings and entity settings), to check that a failed one stops earlier
      const reads = () => vi.mocked(topEntitiesList).mock.calls.length + vi.mocked(fullEntitiesList).mock.calls.length;
      await configPresetExport(context, bypassUser, ALL_CATEGORIES);
      const completeExportReads = reads();
      vi.clearAllMocks();
      // The temporary file cannot be opened, and the exporters answer only after the stream failed,
      // with an incompressible content larger than the stream buffers so that the archive cannot be drained
      const largeSettings = { ...storedSettings, platform_title: crypto.randomBytes(3 * 1024 * 1024).toString('base64') };
      const missingFolder = path.join(os.tmpdir(), `${TMP_ZIP_MARKER}missing-${process.pid}-${Date.now()}`);
      createWriteStreamSpy.mockImplementation(((p: fs.PathLike, options?: Parameters<typeof fs.createWriteStream>[1]) => {
        const target = String(p).includes(TMP_ZIP_MARKER) ? path.join(missingFolder, path.basename(String(p))) : p;
        return realCreateWriteStream(target, options);
      }) as typeof fs.createWriteStream);
      vi.mocked(topEntitiesList).mockImplementation(() => new Promise((resolve) => {
        setTimeout(() => resolve([largeSettings] as never), 50);
      }));
      await expect(configPresetExport(context, bypassUser, ALL_CATEGORIES)).rejects.toThrow(/ENOENT/);
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
      expect(unhandledRejection).not.toHaveBeenCalled();
      expect(uploadToStorage).not.toHaveBeenCalled();
      expect(publishUserAction).not.toHaveBeenCalled();
      // The export stops at the first item that ends after the stream error: the next ones are not read
      expect(reads()).toBeLessThan(completeExportReads);
    } finally {
      process.off('unhandledRejection', unhandledRejection);
    }
  });

  it('does not hang when the output fails while the archive is written, and removes the temporary zip', async () => {
    // Incompressible content larger than the stream buffers: once the output fails, the archive is no longer drained
    const largeSettings = { ...storedSettings, platform_title: crypto.randomBytes(4 * 1024 * 1024).toString('base64') };
    vi.mocked(topEntitiesList).mockResolvedValue([largeSettings] as never);
    createWriteStreamSpy.mockImplementation(((p: fs.PathLike, options?: Parameters<typeof fs.createWriteStream>[1]) => {
      if (!String(p).includes(TMP_ZIP_MARKER)) {
        return realCreateWriteStream(p, options);
      }
      return new Writable({
        write(_chunk, _encoding, callback) {
          callback(Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' }));
        },
      }) as unknown as fs.WriteStream;
    }) as typeof fs.createWriteStream);
    const removeSpy = vi.spyOn(fs.promises, 'rm');
    await expect(configPresetExport(context, bypassUser, ALL_CATEGORIES)).rejects.toThrow(/ENOSPC/);
    expect(removeSpy).toHaveBeenCalledWith(expect.stringContaining(TMP_ZIP_MARKER), { force: true });
    expect(uploadToStorage).not.toHaveBeenCalled();
    expect(publishUserAction).not.toHaveBeenCalled();
    expect(addConfigPresetExportCount).not.toHaveBeenCalled();
  });

  it('exports the platform configuration with the custom default theme it depends on, even when excluded from the branding', async () => {
    withDefaultTheme(customTheme.id);
    await configPresetExport(context, bypassUser, [{ type: 'platform' }, { type: 'branding', excluded_items: [customTheme.id, builtInTheme.id] }]);
    const entries = await readZip(uploadedZip!);
    const customThemeFile = `platform_settings/branding/${customTheme.standard_id}.json`;
    const otherThemeFile = `platform_settings/branding/${otherCustomTheme.standard_id}.json`;
    expect(Object.keys(entries).sort()).toEqual([
      'dependencies.json',
      'metadata.json',
      'platform_settings/branding/whitemark.json',
      'platform_settings/platform.json',
      customThemeFile,
      otherThemeFile,
    ].sort());
    expect(entries['platform_settings/platform.json'].configuration.default_theme).toEqual({ standard_id: customTheme.standard_id, name: 'SOC night' });
    expect(entries['platform_settings/branding/whitemark.json']).toMatchObject({ type: 'platformSettings.branding', id: 'whitemark', configuration: { platform_whitemark: true } });
    expect(entries[customThemeFile]).toMatchObject({ type: 'platformSettings.branding', id: customTheme.standard_id });
    expect(entries[customThemeFile].configuration).toMatchObject({ standard_id: customTheme.standard_id, name: 'SOC night' });
    // Only the owners of dependencies, by item
    expect(entries['dependencies.json']).toEqual({
      'platformSettings.platform': { platform: { [customTheme.standard_id]: customThemeFile } },
    });
    expect(publishedSummary()).toMatchObject({
      entity_types: ['platform', 'branding'],
      // The forced dependency is counted as exported
      counts: { platform: 1, branding: 3 },
      items: { platform: ['platform'], branding: ['whitemark', otherCustomTheme.standard_id, customTheme.standard_id] },
    });
    // Internal ids never leave the platform
    expect(JSON.stringify(entries)).not.toContain(customTheme.id);
  });

  it('exports a custom default theme with the platform configuration when no branding is selected, not with whitemark alone', async () => {
    withDefaultTheme(customTheme.id);
    await configPresetExport(context, bypassUser, [{ type: 'platform', items: ['platform'] }]);
    expect(publishedSummary()).toMatchObject({
      entity_types: ['platform', 'branding'],
      counts: { platform: 1, branding: 1 },
      items: { platform: ['platform'], branding: [customTheme.standard_id] },
    });
    await configPresetExport(context, bypassUser, [{ type: 'branding', items: ['whitemark'] }]);
    const entries = await readZip(uploadedZip!);
    expect(publishedSummary().items).toEqual({ branding: ['whitemark'] });
    expect(entries['dependencies.json']).toEqual({});
  });

  it('exports a selected built-in theme, and references a built-in default theme without depending on it', async () => {
    await configPresetExport(context, bypassUser, [{ type: 'platform' }, { type: 'branding', items: [builtInTheme.id] }]);
    const entries = await readZip(uploadedZip!);
    expect(entries['platform_settings/platform.json'].configuration.default_theme).toEqual({ standard_id: builtInTheme.standard_id, name: 'Filigran Dark' });
    const builtInThemeFile = entries[`platform_settings/branding/${builtInTheme.standard_id}.json`];
    expect(builtInThemeFile).toMatchObject({ type: 'platformSettings.branding', id: builtInTheme.standard_id, configuration: { standard_id: builtInTheme.standard_id, name: 'Filigran Dark' } });
    // Not part of the theme import format
    expect(builtInThemeFile.configuration).not.toHaveProperty('built_in');
    expect(entries['dependencies.json']).toEqual({});
    // Without the theme selected, only the reference
    await configPresetExport(context, bypassUser, [{ type: 'platform' }]);
    expect(publishedSummary().items).toEqual({ platform: ['platform'] });
  });

  it('fails the export, before any write, when a dependency cannot be exported', async () => {
    withDefaultTheme(customTheme.id);
    // The default theme is found by id, but the theme listing no longer returns it
    vi.mocked(fullEntitiesList).mockResolvedValue([] as never);
    await expect(configPresetExport(context, bypassUser, [{ type: 'platform' }])).rejects.toThrow('A configuration preset dependency cannot be exported');
    expectNothingWritten();
  });

  it('refuses a user without BYPASS', async () => {
    await expect(configPresetExport(context, settingsUser, ALL_CATEGORIES)).rejects.toThrow('You are not allowed to do this.');
    expectNothingWritten();
  });

  it('refuses an export in a draft, before any write', async () => {
    await expect(configPresetExport(draftContext, bypassUser, ALL_CATEGORIES)).rejects.toThrow('Cannot export configuration presets in draft');
    expectNothingWritten();
  });
});

describe('Config preset selections', () => {
  beforeEach(() => {
    vi.mocked(topEntitiesList).mockResolvedValue([storedSettings] as never);
    mockThemeLoaders();
  });

  const resolveIds = async (selections: Parameters<typeof resolveConfigPresetSelections>[2]) => {
    const families = await resolveConfigPresetSelections(context, bypassUser, selections);
    return families.map((family) => [family.id, family.items.map((item) => item.id)]);
  };

  it('rejects unknown types, unknown items and empty selections', async () => {
    await expect(resolveConfigPresetSelections(context, bypassUser, [{ type: 'theme', items: ['platform'] }])).rejects.toThrow('Unknown configuration preset type');
    await expect(resolveConfigPresetSelections(context, bypassUser, [{ type: 'theme' }])).rejects.toThrow('Unknown configuration preset type');
    await expect(resolveConfigPresetSelections(context, bypassUser, [{ type: 'platform', items: ['branding'] }])).rejects.toThrow('Unknown configuration preset item');
    await expect(resolveConfigPresetSelections(context, bypassUser, [])).rejects.toThrow('Select at least one configuration item to export');
    await expect(resolveConfigPresetSelections(context, bypassUser, [{ type: 'platform', items: [] }])).rejects.toThrow('Select at least one configuration item to export');
  });

  it('keeps the registry order of the explicitly selected types and items', async () => {
    expect(await resolveIds([{ type: 'hiddenEntityTypes', items: ['hiddenEntityTypes'] }, { type: 'platform', items: ['platform'] }])).toEqual([
      ['platform', ['platform']],
      ['hiddenEntityTypes', ['hiddenEntityTypes']],
    ]);
  });

  it('takes every item of the type when items is null or omitted', async () => {
    const all = [['messages', MESSAGE_IDS]];
    expect(await resolveIds([{ type: 'messages', items: null }])).toEqual(all);
    expect(await resolveIds([{ type: 'messages' }])).toEqual(all);
    expect(await resolveIds([{ type: 'messages', items: [] }, { type: 'messages', items: null }])).toEqual(all);
  });

  it('takes every item but the excluded ones, and refuses excluded items with an explicit list', async () => {
    expect(await resolveIds([{ type: 'branding', excluded_items: [customTheme.id] }])).toEqual([['branding', ['whitemark', otherCustomTheme.id, builtInTheme.id]]]);
    expect(await resolveIds([{ type: 'branding', items: null, excluded_items: [] }])).toEqual([['branding', ['whitemark', otherCustomTheme.id, builtInTheme.id, customTheme.id]]]);
    expect(await resolveIds([{ type: 'messages', excluded_items: MESSAGE_IDS }, { type: 'platform' }])).toEqual([['platform', ['platform']]]);
    await expect(resolveConfigPresetSelections(context, bypassUser, [{ type: 'branding', items: [customTheme.id], excluded_items: [otherCustomTheme.id] }]))
      .rejects.toThrow('Excluded items require a selection of every item of the type');
    await expect(resolveConfigPresetSelections(context, bypassUser, [{ type: 'branding', items: [], excluded_items: [customTheme.id] }]))
      .rejects.toThrow('Excluded items require a selection of every item of the type');
    // Excluding everything leaves nothing to export
    await expect(resolveConfigPresetSelections(context, bypassUser, [{ type: 'branding', excluded_items: ['whitemark', customTheme.id, otherCustomTheme.id, builtInTheme.id] }]))
      .rejects.toThrow('Select at least one configuration item to export');
  });

  it('adds up selections of the same type: an item stays excluded only when no selection takes it', async () => {
    expect(await resolveIds([
      { type: 'branding', excluded_items: [customTheme.id, otherCustomTheme.id] },
      { type: 'branding', excluded_items: [customTheme.id] },
    ])).toEqual([['branding', ['whitemark', otherCustomTheme.id, builtInTheme.id]]]);
    expect(await resolveIds([
      { type: 'branding', excluded_items: [customTheme.id] },
      { type: 'branding', items: [customTheme.id] },
    ])).toEqual([['branding', ['whitemark', otherCustomTheme.id, builtInTheme.id, customTheme.id]]]);
  });

  it('takes a built-in theme like any other', async () => {
    expect(await resolveIds([{ type: 'branding', items: [builtInTheme.id] }])).toEqual([['branding', [builtInTheme.id]]]);
  });

  it('still rejects an unknown item merged with a null selection', async () => {
    await expect(resolveConfigPresetSelections(context, bypassUser, [
      { type: 'platform', items: null },
      { type: 'platform', items: ['branding'] },
    ])).rejects.toThrow('Unknown configuration preset item');
  });
});

describe('Config preset dependencies', () => {
  const family = (id: string) => CONFIG_PRESET_FAMILIES.find((current) => current.id === id)!;
  const item = (id: string, dependsOn: ConfigPresetItemDefinition['dependsOn']): ConfigPresetItemDefinition => ({
    id,
    label: id,
    translatable: true,
    dependsOn,
    exporter: async () => ({}),
  });
  // Static items for the singleton families, with the given dependencies
  const withItems = (items: ConfigPresetItemDefinition[]) => {
    ['platform', 'messages', 'hiddenEntityTypes'].forEach((familyId) => {
      vi.spyOn(family(familyId), 'resolveItems').mockImplementation(async (_ctx, _user, ids) => items.filter((current) => current.id === familyId && (!ids || ids.includes(current.id))));
    });
  };
  const closureIds = async (selected: ConfigPresetItemDefinition[]) => {
    const families = selected.map((current) => ({ ...family(current.id), items: [current] }));
    return (await addConfigPresetDependencies(context, bypassUser, families)).map(({ id, items }) => [id, items.map(({ id: itemId }) => itemId)]);
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('adds a chain of dependencies depth first, in registry order', async () => {
    const platform = item('platform', [{ type: 'messages', id: 'messages' }]);
    const messages = item('messages', [{ type: 'hiddenEntityTypes', id: 'hiddenEntityTypes' }]);
    withItems([platform, messages, item('hiddenEntityTypes', [])]);
    expect(await closureIds([platform])).toEqual([['platform', ['platform']], ['messages', ['messages']], ['hiddenEntityTypes', ['hiddenEntityTypes']]]);
  });

  it('lists every owner of a transitive chain under its own type, with the bundle id and path of each dependency', async () => {
    const platform = item('platform', [{ type: 'messages', id: 'messages' }]);
    const messages = item('messages', [{ type: 'hiddenEntityTypes', id: 'hiddenEntityTypes' }]);
    withItems([platform, messages, item('hiddenEntityTypes', [])]);
    const families = await addConfigPresetDependencies(context, bypassUser, [{ ...family('platform'), items: [platform] }]);
    const dependencies = buildConfigPresetDependencies(families);
    expect(dependencies).toEqual({
      'platformSettings.platform': { platform: { messages: 'platform_settings/messages/messages.json' } },
      // The test items have no file name: `<id>.json`
      'platformSettings.messages': { messages: { hiddenEntityTypes: 'data_model/hiddenEntityTypes.json' } },
    });
    // Registry order
    expect(Object.keys(dependencies)).toEqual(['platformSettings.platform', 'platformSettings.messages']);
  });

  it('stops on a cycle', async () => {
    const platform = item('platform', [{ type: 'messages', id: 'messages' }]);
    const messages = item('messages', [{ type: 'platform', id: 'platform' }]);
    withItems([platform, messages]);
    expect(await closureIds([platform])).toEqual([['platform', ['platform']], ['messages', ['messages']]]);
    expect(family('messages').resolveItems).toHaveBeenCalledTimes(1);
    expect(family('platform').resolveItems).not.toHaveBeenCalled();
  });

  it('fails on a dependency of an unknown type or item', async () => {
    withItems([]);
    await expect(closureIds([item('platform', [{ type: 'dashboards', id: 'dashboard-id' }])])).rejects.toThrow('A configuration preset dependency cannot be exported');
    await expect(closureIds([item('platform', [{ type: 'messages', id: 'messages' }])])).rejects.toThrow('A configuration preset dependency cannot be exported');
  });
});
