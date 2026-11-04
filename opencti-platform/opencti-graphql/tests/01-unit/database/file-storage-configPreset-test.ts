import { beforeEach, describe, expect, it, vi } from 'vitest';

// The stored document of a file is read through storeLoadById
vi.mock('../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));

import { storeLoadById } from '../../../src/database/middleware-loader';
import { loadFile } from '../../../src/database/file-storage';
import { CONFIG_PRESET_STORAGE_PATH } from '../../../src/modules/internal/document/document-types';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const bypassUser = { id: 'admin-id', capabilities: [{ name: 'BYPASS' }] } as AuthUser;
const knowledgeUser = { id: 'analyst-id', capabilities: [{ name: 'KNOWLEDGE' }] } as AuthUser;
const noCapabilityUser = { id: 'viewer-id', capabilities: [] as { name: string }[] } as AuthUser;

const RESTRICTED = 'File not found or restricted';
const presetFileId = `${CONFIG_PRESET_STORAGE_PATH}/0b5c1e9e-4b0a-4f37-9a43-1f1c2b7c9d10/opencti-config-20261014-090507-7.0.0.zip`;
const draftPresetFileId = `draft/draft-id/${presetFileId}`;
const knowledgeExportId = 'export/Report/report-id/report.json';
const storedFileIds = [presetFileId, draftPresetFileId, knowledgeExportId];

// Like the internal_id lookup of the engine (string_normalizer: lowercase + asciifolding)
const normalize = (value: string) => value.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();

describe('loadFile on configuration preset bundles', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => {
      const storedId = storedFileIds.find((fileId) => normalize(fileId) === normalize(id as string));
      return (storedId ? { id: storedId, internal_id: storedId, metaData: {} } : undefined) as never;
    });
  });

  it('refuses the exact path to a user without BYPASS, even with the knowledge capability', async () => {
    await expect(loadFile(context, knowledgeUser, presetFileId)).rejects.toThrow(RESTRICTED);
    await expect(loadFile(context, knowledgeUser, presetFileId, { dontThrow: true })).resolves.toBeUndefined();
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('returns the bundle to a BYPASS user', async () => {
    const file = await loadFile(context, bypassUser, presetFileId);
    expect(file?.id).toBe(presetFileId);
  });

  it.each([
    `Config_preset/${presetFileId.slice(CONFIG_PRESET_STORAGE_PATH.length + 1)}`,
    presetFileId.toUpperCase(),
    `cönfig_preset/${presetFileId.slice(CONFIG_PRESET_STORAGE_PATH.length + 1)}`,
  ])('refuses the case or accent variant %s to a user without BYPASS once the document is found', async (variant) => {
    await expect(loadFile(context, knowledgeUser, variant)).rejects.toThrow(RESTRICTED);
    await expect(loadFile(context, knowledgeUser, variant, { dontThrow: true })).resolves.toBeUndefined();
    // The path itself passes the first check, the refusal comes from the document actually found
    expect(storeLoadById).toHaveBeenCalledWith(context, knowledgeUser, variant, expect.anything(), expect.anything());
  });

  it('returns the bundle to a BYPASS user through a case variant', async () => {
    const file = await loadFile(context, bypassUser, presetFileId.toUpperCase());
    expect(file?.id).toBe(presetFileId);
  });

  it('refuses a user without BYPASS on the draft copy of a bundle, also through a case variant', async () => {
    await expect(loadFile(context, knowledgeUser, draftPresetFileId)).rejects.toThrow(RESTRICTED);
    await expect(loadFile(context, knowledgeUser, draftPresetFileId.toUpperCase())).rejects.toThrow(RESTRICTED);
    const file = await loadFile(context, bypassUser, draftPresetFileId);
    expect(file?.id).toBe(draftPresetFileId);
  });

  it('keeps the knowledge rule for the other export files', async () => {
    const file = await loadFile(context, knowledgeUser, knowledgeExportId);
    expect(file?.id).toBe(knowledgeExportId);
    await expect(loadFile(context, noCapabilityUser, knowledgeExportId)).rejects.toThrow(RESTRICTED);
    await expect(loadFile(context, noCapabilityUser, knowledgeExportId, { dontThrow: true })).resolves.toBeUndefined();
  });
});
