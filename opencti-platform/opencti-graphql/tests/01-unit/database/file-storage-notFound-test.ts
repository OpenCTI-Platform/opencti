import { beforeEach, describe, expect, it, vi } from 'vitest';

// The stored document of a file is read through storeLoadById, the entity it is attached to through internalLoadById
vi.mock('../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
  internalLoadById: vi.fn(),
}));

import { internalLoadById, storeLoadById } from '../../../src/database/middleware-loader';
import { loadFile } from '../../../src/database/file-storage';
import { RESOURCE_NOT_FOUND_ERROR } from '../../../src/config/errors';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const noCapabilityUser = { id: 'viewer-id', capabilities: [] as { name: string }[] } as AuthUser;
// KNOWLEDGE through KNOWLEDGE_KNUPDATE, without KNOWLEDGE_KNASKIMPORT
const knowledgeUser = { id: 'analyst-id', capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }] } as AuthUser;

const RESTRICTED = 'File not found or restricted';
// A restricted file and a missing one give the same error: a 404 that does not reveal whether the file exists
const expectNotFound = async (promise: Promise<unknown>, filename?: string) => {
  const error = await promise.then(() => undefined, (e) => e);
  expect(error?.message).toBe(RESTRICTED);
  expect(error?.extensions?.code).toBe(RESOURCE_NOT_FOUND_ERROR);
  expect(error?.extensions?.data?.filename).toBe(filename);
};

describe('loadFile: file not found or restricted', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it.each([
    ['support package without SETTINGS_SUPPORT', noCapabilityUser, 'support/package/file.zip'],
    ['import file without KNOWLEDGE', noCapabilityUser, 'import/Report/report-id/report.pdf'],
    ['export file without KNOWLEDGE', noCapabilityUser, 'export/Report/report-id/report.json'],
    ['import/global file without KNOWLEDGE_KNASKIMPORT', knowledgeUser, 'import/global/file.csv'],
  ])('refuses %s before reading the storage', async (_name, user, fileId) => {
    await expectNotFound(loadFile(context, user, fileId), fileId);
    await expect(loadFile(context, user, fileId, { dontThrow: true })).resolves.toBeUndefined();
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('refuses a file that does not exist', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(undefined as never);
    await expectNotFound(loadFile(context, knowledgeUser, 'import/Report/report-id/missing.pdf'), 'import/Report/report-id/missing.pdf');
  });

  it('refuses a file attached to an entity to a user without KNOWLEDGE', async () => {
    // a path outside the folders checked up front, so the refusal comes from the entity the file is attached to
    const fileId = 'other/Report/report-id/report.pdf';
    vi.mocked(storeLoadById).mockResolvedValue({ id: fileId, internal_id: fileId, metaData: { entity_id: 'report-id' } } as never);
    await expectNotFound(loadFile(context, noCapabilityUser, fileId), fileId);
  });

  it('refuses a file attached to an entity the user cannot see', async () => {
    const fileId = 'import/Report/report-id/report.pdf';
    vi.mocked(storeLoadById).mockResolvedValue({ id: fileId, internal_id: fileId, metaData: { entity_id: 'report-id' } } as never);
    vi.mocked(internalLoadById).mockResolvedValue(undefined as never);
    await expectNotFound(loadFile(context, knowledgeUser, fileId), fileId);
    expect(internalLoadById).toHaveBeenCalled();
  });
});
