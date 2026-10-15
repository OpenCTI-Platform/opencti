import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';
// @ts-expect-error unzipper ships no type declarations
import unzipper from 'unzipper';

const flags = vi.hoisted(() => ({ enabled: true }));
vi.mock('../../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => flags.enabled),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  topEntitiesList: vi.fn(),
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/database/file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/file-storage')>()),
  uploadToStorage: vi.fn(),
  deleteFile: vi.fn(),
}));
vi.mock('../../../../src/modules/internal/document/document-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/internal/document/document-domain')>()),
  allFilesForPaths: vi.fn(),
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
import { deleteFile, uploadToStorage } from '../../../../src/database/file-storage';
import { allFilesForPaths } from '../../../../src/modules/internal/document/document-domain';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { addConfigPresetExportCount } from '../../../../src/manager/telemetryManager';
import { PLATFORM_VERSION } from '../../../../src/config/conf';
import { buildConfigPresetFileName, configPresetExport, resolveConfigPresetSelections, sanitizeBundleName } from '../../../../src/modules/configPreset/configPreset-domain';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const draftContext = { source: 'test', draft_context: 'draft-id' } as AuthContext;
const bypassUser = { id: 'admin-id', capabilities: [{ name: 'BYPASS' }] } as AuthUser;
const settingsUser = { id: 'settings-id', capabilities: [{ name: 'SETTINGS_SETPARAMETERS' }, { name: 'KNOWLEDGE' }] } as AuthUser;

const ALL_CATEGORIES = [
  { type: 'platform', items: ['platform'] },
  { type: 'messages', items: ['messages'] },
  { type: 'hiddenEntityTypes', items: ['hiddenEntityTypes'] },
];
const ALL_FILES = ['data_model/hidden_entity_types.json', 'metadata.json', 'platform_settings/messages.json', 'platform_settings/platform.json'];
const ALL_ITEMS = { platform: ['platform'], messages: ['messages'], hiddenEntityTypes: ['hiddenEntityTypes'] };
const ONE_PER_CATEGORY = { platform: 1, messages: 1, hiddenEntityTypes: 1 };
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
  platform_consent_message: null,
  platform_consent_confirm_text: null,
  platform_theme: 'theme-id',
  enterprise_license: 'secret-license',
};

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

const expectNothingWritten = () => {
  expect(allFilesForPaths).not.toHaveBeenCalled();
  expect(deleteFile).not.toHaveBeenCalled();
  expect(tmpZipPaths()).toEqual([]);
  expect(uploadToStorage).not.toHaveBeenCalled();
  expect(publishUserAction).not.toHaveBeenCalled();
};

describe('Config preset export', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    flags.enabled = true;
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    createWriteStreamSpy = vi.spyOn(fs, 'createWriteStream');
    uploadedZip = undefined;
    tmpFileModeDuringUpload = undefined;
    vi.mocked(topEntitiesList).mockResolvedValue([storedSettings] as never);
    vi.mocked(fullEntitiesList).mockResolvedValue([{ target_type: 'Channel', platform_hidden_type: true }] as never);
    vi.mocked(allFilesForPaths).mockResolvedValue([]);
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
    expect(entries['metadata.json']).toEqual({
      openCTI_version: PLATFORM_VERSION,
      generated_at: NOW.toISOString(),
      generated_by: 'admin-id',
      entity_types: ['platform', 'messages', 'hiddenEntityTypes'],
      counts: ONE_PER_CATEGORY,
      requested_counts: ONE_PER_CATEGORY,
      items: ALL_ITEMS,
      bundle_name: 'My bundle v1',
    });
    expect(entries['platform_settings/platform.json']).toEqual({
      openCTI_version: PLATFORM_VERSION,
      type: 'platform.platform',
      configuration: { platform_title: 'My platform', platform_favicon: null, platform_language: 'en-us' },
    });
    expect(entries['data_model/hidden_entity_types.json'].configuration).toEqual({ hidden_entity_types: ['Channel'] });
    const serialized = JSON.stringify(entries);
    expect(serialized).not.toMatch(/theme|branding|secret-license/i);
  });

  it('only writes the selected items and merges duplicated selections', async () => {
    await configPresetExport(context, bypassUser, [
      { type: 'messages', items: ['messages'] },
      { type: 'messages', items: ['messages'] },
      { type: 'platform', items: ['platform'] },
    ]);
    const entries = await readZip(uploadedZip!);
    expect(Object.keys(entries).sort()).toEqual(['metadata.json', 'platform_settings/messages.json', 'platform_settings/platform.json']);
    // Registry order, not selection order
    expect(entries['metadata.json'].entity_types).toEqual(['platform', 'messages']);
    expect(entries['metadata.json'].counts).toEqual({ platform: 1, messages: 1 });
    expect(entries['metadata.json'].requested_counts).toEqual({ platform: 1, messages: 1 });
    expect(entries['metadata.json'].items).toEqual({ platform: ['platform'], messages: ['messages'] });
    expect(entries['metadata.json'].bundle_name).toBeNull();
  });

  it('lists only the exported items in the metadata of a partial selection', async () => {
    await configPresetExport(context, bypassUser, [{ type: 'messages', items: ['messages'] }]);
    const entries = await readZip(uploadedZip!);
    expect(Object.keys(entries).sort()).toEqual(['metadata.json', 'platform_settings/messages.json']);
    expect(entries['metadata.json']).toEqual({
      openCTI_version: PLATFORM_VERSION,
      generated_at: NOW.toISOString(),
      generated_by: 'admin-id',
      entity_types: ['messages'],
      counts: { messages: 1 },
      requested_counts: { messages: 1 },
      items: { messages: ['messages'] },
      bundle_name: null,
    });
  });

  it('exports every item of the type when items is omitted', async () => {
    await configPresetExport(context, bypassUser, [{ type: 'platform' }, { type: 'messages' }, { type: 'hiddenEntityTypes' }]);
    const entries = await readZip(uploadedZip!);
    expect(Object.keys(entries).sort()).toEqual(ALL_FILES);
    expect(entries['metadata.json'].items).toEqual(ALL_ITEMS);
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
      expect.objectContaining({ filename: EXPECTED_FILE_NAME, mimeType: 'application/zip' }),
      expect.objectContaining({ noTriggerImport: true }),
    );
  });

  it('publishes a file creation user action and counts the export in telemetry', async () => {
    const file = await configPresetExport(context, bypassUser, ALL_CATEGORIES);
    expect(publishUserAction).toHaveBeenCalledTimes(1);
    const action = vi.mocked(publishUserAction).mock.calls[0][0];
    expect(action).toMatchObject({ user: bypassUser, event_type: 'file', event_scope: 'create', event_access: 'administration' });
    expect(action.context_data).toMatchObject({
      path: path.posix.dirname(file.id),
      file_name: EXPECTED_FILE_NAME,
      entity_type: 'global',
      input: {
        entity_types: ['platform', 'messages', 'hiddenEntityTypes'],
        counts: ONE_PER_CATEGORY,
        items: ALL_ITEMS,
      },
    });
    expect(addConfigPresetExportCount).toHaveBeenCalledTimes(1);
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
    } finally {
      process.off('unhandledRejection', unhandledRejection);
    }
  });

  it('deletes the exports older than one hour, in every export folder', async () => {
    vi.mocked(allFilesForPaths).mockResolvedValue([{ id: 'config_preset/old-folder/old.zip' }] as never);
    await configPresetExport(context, bypassUser, ALL_CATEGORIES);
    expect(allFilesForPaths).toHaveBeenCalledWith(context, bypassUser, ['config_preset'], { notModifiedSince: '2026-10-14T08:05:07.123Z' });
    expect(deleteFile).toHaveBeenCalledWith(context, bypassUser, 'config_preset/old-folder/old.zip');
  });

  it('keeps deleting the other expired exports when one deletion fails', async () => {
    vi.mocked(allFilesForPaths).mockResolvedValue([
      { id: 'config_preset/a/old.zip' },
      { id: 'config_preset/b/old.zip' },
      { id: 'config_preset/c/old.zip' },
    ] as never);
    vi.mocked(deleteFile).mockImplementation(async (_ctx, _user, id) => {
      if (id === 'config_preset/b/old.zip') {
        throw new Error('storage down');
      }
      return undefined;
    });
    const file = await configPresetExport(context, bypassUser, ALL_CATEGORIES);
    expect(vi.mocked(deleteFile).mock.calls.map(([, , id]) => id)).toEqual(['config_preset/a/old.zip', 'config_preset/b/old.zip', 'config_preset/c/old.zip']);
    expect(file.id).toMatch(/^config_preset\//);
  });

  it('still exports when the cleanup of expired exports fails', async () => {
    vi.mocked(allFilesForPaths).mockRejectedValue(new Error('index down'));
    const file = await configPresetExport(context, bypassUser, ALL_CATEGORIES);
    expect(file.id).toMatch(/^config_preset\//);
  });

  it('refuses a user without BYPASS', async () => {
    await expect(configPresetExport(context, settingsUser, ALL_CATEGORIES)).rejects.toThrow('You are not allowed to do this.');
    expectNothingWritten();
  });

  it('refuses an export in a draft, before any cleanup or write', async () => {
    await expect(configPresetExport(draftContext, bypassUser, ALL_CATEGORIES)).rejects.toThrow('Cannot export configuration presets in draft');
    expectNothingWritten();
  });

  it('refuses an export when the feature flag is disabled', async () => {
    flags.enabled = false;
    await expect(configPresetExport(context, bypassUser, ALL_CATEGORIES)).rejects.toThrow(/Feature is disabled/i);
    expectNothingWritten();
  });
});

describe('Config preset selections', () => {
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
    const all = [['messages', ['messages']]];
    expect(await resolveIds([{ type: 'messages', items: null }])).toEqual(all);
    expect(await resolveIds([{ type: 'messages' }])).toEqual(all);
    expect(await resolveIds([{ type: 'messages', items: [] }, { type: 'messages', items: null }])).toEqual(all);
  });

  it('still rejects an unknown item merged with a null selection', async () => {
    await expect(resolveConfigPresetSelections(context, bypassUser, [
      { type: 'platform', items: null },
      { type: 'platform', items: ['branding'] },
    ])).rejects.toThrow('Unknown configuration preset item');
  });
});

describe('Config preset naming', () => {
  it('sanitizes the bundle name', () => {
    expect(sanitizeBundleName(undefined)).toBeNull();
    expect(sanitizeBundleName('   ')).toBeNull();
    expect(sanitizeBundleName('<script>alert(1)</script>')).toBe('scriptalert(1)script');
    expect(sanitizeBundleName('Prod\n\tbundle‮  2026')).toBe('Prodbundle 2026');
    expect(sanitizeBundleName('Préréglage SOC_v1.2-(EU)')).toBe('Préréglage SOC_v1.2-(EU)');
    expect(sanitizeBundleName('a'.repeat(100))).toHaveLength(80);
  });

  it('keeps the combining marks and joiners of non-Latin scripts', () => {
    // Hindi: virama and vowel signs are combining marks
    expect(sanitizeBundleName('नमस्ते दुनिया')).toBe('नमस्ते दुनिया');
    // Persian: the zero-width non-joiner is part of the word
    expect(sanitizeBundleName('می‌خواهم')).toBe('می‌خواهم');
    // A decomposed accent is composed
    expect(sanitizeBundleName('Préréglage')).toBe('Préréglage');
  });

  it('cuts the bundle name at 80 characters without splitting a character or leaving a space', () => {
    const astral = '\u{1D49C}';
    expect(sanitizeBundleName(`${'a'.repeat(79)}${astral}bc`)).toBe(`${'a'.repeat(79)}${astral}`);
    expect(sanitizeBundleName(`${'a'.repeat(79)} bc`)).toBe('a'.repeat(79));
  });

  it('puts the UTC date, time and platform version in the zip name', () => {
    expect(buildConfigPresetFileName(new Date('2026-01-02T23:59:58.999Z'))).toBe(`opencti-config-20260102-235958-${PLATFORM_VERSION}.zip`);
  });

  it('keeps the zip name in UTC whatever the time zone of the platform', () => {
    const previousTimeZone = process.env.TZ;
    process.env.TZ = 'Pacific/Kiritimati';
    try {
      const date = new Date('2026-01-02T23:59:58.999Z');
      // UTC+14: the local day is already the next one
      expect(date.getDate()).toBe(3);
      expect(buildConfigPresetFileName(date)).toBe(`opencti-config-20260102-235958-${PLATFORM_VERSION}.zip`);
    } finally {
      if (previousTimeZone === undefined) {
        delete process.env.TZ;
      } else {
        process.env.TZ = previousTimeZone;
      }
    }
  });
});
