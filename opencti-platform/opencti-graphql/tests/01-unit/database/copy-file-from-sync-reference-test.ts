import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/database/raw-file-storage', () => ({
  rawCopyFile: vi.fn(),
  downloadFileWithoutLogging: vi.fn(),
  getFileSize: vi.fn(),
  deleteFileFromStorage: vi.fn(),
  rawListObjects: vi.fn(),
  rawUpload: vi.fn(),
}));
vi.mock('../../../src/modules/internal/document/document-domain', () => ({
  indexFileToDocument: vi.fn(),
  allFilesForPaths: vi.fn(),
  deleteDocumentIndex: vi.fn(),
  findById: vi.fn(),
}));
vi.mock('../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/cache')>()),
  getEntitiesMapFromCache: vi.fn(),
}));
vi.mock('../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/middleware-loader')>()),
  internalLoadById: vi.fn(),
}));
vi.mock('../../../src/lock/master-lock', () => ({
  lockResources: vi.fn(),
}));
// No eligible connector short-circuits uploadJobImport, so only the trigger decision is observed
vi.mock('../../../src/modules/connector/connector-domain', () => ({
  connectorsForImport: vi.fn(),
}));
// The real confidence control needs the schema attributes registry, which unit tests do not load
vi.mock('../../../src/utils/confidence-level', () => ({
  controlUserConfidenceAgainstElement: () => true,
}));

import { deleteFileFromStorage, downloadFileWithoutLogging, getFileSize, rawCopyFile } from '../../../src/database/raw-file-storage';
import { findById as documentFindById, indexFileToDocument } from '../../../src/modules/internal/document/document-domain';
import { getEntitiesMapFromCache } from '../../../src/database/cache';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { lockResources } from '../../../src/lock/master-lock';
import { connectorsForImport } from '../../../src/modules/connector/connector-domain';
import { copyFileFromSyncReference, upload, type LoadedFile, type SyncFileReferenceCopyProps } from '../../../src/database/file-storage';
import { logApp } from '../../../src/config/conf';
import { TYPE_LOCK_ERROR } from '../../../src/config/errors';
import { OPENCTI_SYSTEM_UUID } from '../../../src/schema/general';
import { ENTITY_TYPE_SYNC } from '../../../src/schema/internalObject';
import { SYSTEM_USER } from '../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { BasicStoreEntity, BasicStoreObject, StoreMarkingDefinition } from '../../../src/types/store';
import type { BasicStoreEntityDocument } from '../../../src/modules/internal/document/document-types';

const SYNC_ID = 'sync-id-1';
const STAGED_KEY = 'sync/inflight/sync-id-1/remote-file-1/content';
const STAGED_CONTENT = 'staged sync file content';
const STAGED_SHA256 = crypto.createHash('sha256').update(STAGED_CONTENT).digest('hex');
const TLP_AMBER = { internal_id: 'marking-internal-amber', standard_id: 'marking-definition--amber' } as unknown as StoreMarkingDefinition;
// Both lookups resolve undefined when nothing is found, although their return types do not say so
const MISSING_FILE = undefined as unknown as BasicStoreEntityDocument;
const UNKNOWN_SYNC = undefined as unknown as BasicStoreObject;

const context = { source: 'test' } as AuthContext;
const buildUser = (id: string, allowedMarkings: StoreMarkingDefinition[]): AuthUser => ({
  ...SYSTEM_USER,
  id,
  internal_id: id,
  capabilities: [],
  allowed_marking: allowedMarkings,
});
const user = buildUser('user-1', [TLP_AMBER]);

const buildCopyProps = (overrides: Partial<SyncFileReferenceCopyProps>): SyncFileReferenceCopyProps => ({
  syncId: SYNC_ID,
  filePath: 'import/Report/entity-1',
  storageKey: STAGED_KEY,
  name: 'report.pdf',
  entityId: 'entity-1',
  importContextEntities: [],
  ...overrides,
});
const buildStoredFile = (internalId: string, metaData: LoadedFile['metaData']) => ({ internal_id: internalId, metaData } as BasicStoreEntityDocument);
const buildLockError = () => Object.assign(new Error('The operation was unable to achieve a quorum during its retry window.'), { name: TYPE_LOCK_ERROR });
const indexedFile = (callIndex: number) => vi.mocked(indexFileToDocument).mock.calls[callIndex][1] as LoadedFile;

describe('copyFileFromSyncReference', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(downloadFileWithoutLogging).mockImplementation(async () => Readable.from([Buffer.from(STAGED_CONTENT)]));
    vi.mocked(getFileSize).mockResolvedValue(1234);
    vi.mocked(documentFindById).mockResolvedValue(MISSING_FILE);
    vi.mocked(lockResources).mockResolvedValue({ unlock: vi.fn() });
    vi.mocked(connectorsForImport).mockResolvedValue([]);
    vi.mocked(internalLoadById).mockResolvedValue({ internal_id: SYNC_ID, user_id: 'user-1' } as BasicStoreObject);
    const markings = new Map<string, BasicStoreObject>([[TLP_AMBER.internal_id, TLP_AMBER], [TLP_AMBER.standard_id, TLP_AMBER]]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(markings);
  });

  it('rejects a caller who is not the user the sync runs as, without touching S3', async () => {
    vi.mocked(internalLoadById).mockResolvedValue({ internal_id: SYNC_ID, user_id: 'sync-user' } as BasicStoreObject);

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({}));

    expect(result).toBeNull();
    expect(internalLoadById).toHaveBeenCalledWith(context, expect.objectContaining({ id: OPENCTI_SYSTEM_UUID }), SYNC_ID, { type: ENTITY_TYPE_SYNC });
    expect(lockResources).not.toHaveBeenCalled();
    expect(rawCopyFile).not.toHaveBeenCalled();
  });

  it('rejects a sync_id that does not match any synchronizer, without touching S3', async () => {
    vi.mocked(internalLoadById).mockResolvedValue(UNKNOWN_SYNC);

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({}));

    expect(result).toBeNull();
    expect(rawCopyFile).not.toHaveBeenCalled();
  });

  it('accepts the system user for a sync without a user, as the sync manager sends its bundles as system', async () => {
    vi.mocked(internalLoadById).mockResolvedValue({ internal_id: SYNC_ID } as BasicStoreObject);

    const result = await copyFileFromSyncReference(context, SYSTEM_USER, buildCopyProps({}));

    expect(result).not.toBeNull();
  });

  it('rejects a storage_key that does not belong to the calling sync, without touching S3', async () => {
    const result = await copyFileFromSyncReference(context, user, buildCopyProps({ storageKey: 'sync/inflight/some-other-sync/remote-file-1/content' }));

    expect(result).toBeNull();
    expect(lockResources).not.toHaveBeenCalled();
    expect(rawCopyFile).not.toHaveBeenCalled();
    expect(indexFileToDocument).not.toHaveBeenCalled();
    expect(deleteFileFromStorage).not.toHaveBeenCalled();
  });

  it('copies a validated storage_key to its final path, indexes it, and deletes the staged source', async () => {
    const unlock = vi.fn();
    vi.mocked(lockResources).mockResolvedValue({ unlock });

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({
      mimeType: 'application/pdf',
      version: '2024-01-01T00:00:00.000Z',
      fileMarkings: [TLP_AMBER.standard_id],
    }));

    expect(rawCopyFile).toHaveBeenCalledWith(STAGED_KEY, 'import/Report/entity-1/report.pdf');
    expect(indexFileToDocument).toHaveBeenCalledWith(context, expect.objectContaining({
      id: 'import/Report/entity-1/report.pdf',
      name: 'report.pdf',
      size: 1234,
      metaData: {
        version: '2024-01-01T00:00:00.000Z',
        mimetype: 'application/pdf',
        entity_id: 'entity-1',
        file_markings: [TLP_AMBER.internal_id],
        filename: 'report.pdf',
        encoding: '7bit',
        creator_id: 'user-1',
        sha256: STAGED_SHA256,
        messages: [],
        errors: [],
      },
    }));
    expect(deleteFileFromStorage).toHaveBeenCalledWith(STAGED_KEY);
    expect(result?.upload.id).toEqual('import/Report/entity-1/report.pdf');
    expect(result?.untouched).toEqual(false);
    expect(unlock).toHaveBeenCalledTimes(1);
  });

  it('locks on a hash of the staged key, as lock names are logged when an extension fails', async () => {
    await copyFileFromSyncReference(context, user, buildCopyProps({}));

    const lockName = `sync-inflight-copy:${crypto.createHash('sha256').update(STAGED_KEY).digest('hex')}`;
    expect(lockResources).toHaveBeenCalledWith([lockName], { retryCount: 0 });
  });

  it('rejects a marking the user does not hold before anything is copied, same as a direct upload', async () => {
    const copy = copyFileFromSyncReference(context, buildUser('user-1', []), buildCopyProps({ fileMarkings: [TLP_AMBER.standard_id] }));

    await expect(copy).rejects.toThrow('User trying to create the data has missing markings');
    expect(rawCopyFile).not.toHaveBeenCalled();
    expect(indexFileToDocument).not.toHaveBeenCalled();
  });

  it('skips the copy and marks the result untouched when the target already has this version', async () => {
    vi.mocked(documentFindById).mockResolvedValue(buildStoredFile('import/Report/entity-1/report.pdf', { version: '2024-01-01T00:00:00.000Z', mimetype: 'application/pdf' }));

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({ mimeType: 'application/pdf', version: '2024-01-01T00:00:00.000Z' }));

    expect(result?.untouched).toEqual(true);
    expect(rawCopyFile).not.toHaveBeenCalled();
    expect(indexFileToDocument).not.toHaveBeenCalled();
    // The redundant staged source is still consumed, so it does not wait for the cleanup TTL
    expect(deleteFileFromStorage).toHaveBeenCalledWith(STAGED_KEY);
  });

  it('still copies when the target exists but at an older version', async () => {
    vi.mocked(documentFindById).mockResolvedValue(buildStoredFile('import/Report/entity-1/report.pdf', { version: '2023-01-01T00:00:00.000Z', mimetype: 'application/pdf' }));

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({ mimeType: 'application/pdf', version: '2024-01-01T00:00:00.000Z' }));

    expect(result?.untouched).toEqual(false);
    expect(rawCopyFile).toHaveBeenCalled();
    expect(indexFileToDocument).toHaveBeenCalled();
  });

  it('overwrites an older existing file under its own id and keeps its creator, same as a direct upload', async () => {
    vi.mocked(documentFindById).mockResolvedValue(buildStoredFile('import/Report/entity-1/Report.PDF', {
      version: '2023-01-01T00:00:00.000Z',
      mimetype: 'application/pdf',
      creator_id: 'original-creator',
    }));

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({ name: 'Report.PDF', version: '2024-01-01T00:00:00.000Z' }));

    expect(rawCopyFile).toHaveBeenCalledWith(STAGED_KEY, 'import/Report/entity-1/Report.PDF');
    expect(result?.upload.id).toEqual('import/Report/entity-1/Report.PDF');
    expect(result?.upload.metaData.creator_id).toEqual('original-creator');
  });

  it('does not delete the staged source when the copy itself fails', async () => {
    vi.mocked(rawCopyFile).mockRejectedValue(new Error('S3 unavailable'));

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({}));

    expect(result).toBeNull();
    expect(indexFileToDocument).not.toHaveBeenCalled();
    expect(deleteFileFromStorage).not.toHaveBeenCalled();
  });

  it('never lets a remote-controlled file name escape filePath via traversal or nested segments', async () => {
    const result = await copyFileFromSyncReference(context, user, buildCopyProps({ name: '../../../etc/passwd' }));

    expect(rawCopyFile).toHaveBeenCalledWith(STAGED_KEY, 'import/Report/entity-1/passwd');
    expect(result?.upload.id).toEqual('import/Report/entity-1/passwd');
  });

  it('cannot be replayed onto another entity: a consumed storage_key is gone from S3, so a second attempt fails', async () => {
    const firstAttempt = await copyFileFromSyncReference(context, user, buildCopyProps({}));
    expect(firstAttempt).not.toBeNull();
    expect(deleteFileFromStorage).toHaveBeenCalledWith(STAGED_KEY);

    vi.mocked(downloadFileWithoutLogging).mockResolvedValue(null);
    const replayAttempt = await copyFileFromSyncReference(context, user, buildCopyProps({ filePath: 'import/Report/entity-attacker-controlled', entityId: 'entity-attacker-controlled' }));

    expect(replayAttempt).toBeNull();
    expect(rawCopyFile).toHaveBeenCalledTimes(1);
  });

  it('rejects a second concurrent call racing on the same storage_key while the first is still in flight', async () => {
    vi.mocked(lockResources).mockResolvedValueOnce({ unlock: vi.fn() }).mockRejectedValueOnce(buildLockError());

    const [first, second] = await Promise.all([
      copyFileFromSyncReference(context, user, buildCopyProps({})),
      copyFileFromSyncReference(context, user, buildCopyProps({})),
    ]);

    expect([first, second].filter((result) => result !== null)).toHaveLength(1);
    expect(rawCopyFile).toHaveBeenCalledTimes(1);
    expect(deleteFileFromStorage).toHaveBeenCalledTimes(1);
  });

  it('returns null on a lock timeout and keeps the lock error as the cause in the log', async () => {
    const lockError = buildLockError();
    vi.mocked(lockResources).mockRejectedValue(lockError);
    const warn = vi.spyOn(logApp, 'warn');

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({}));

    expect(result).toBeNull();
    expect(rawCopyFile).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ cause: lockError, syncId: SYNC_ID }));
  });

  it('propagates a lock failure that is not a lock timeout, without touching S3', async () => {
    const redisError = new Error('Connection is closed.');
    vi.mocked(lockResources).mockRejectedValue(redisError);

    await expect(copyFileFromSyncReference(context, user, buildCopyProps({}))).rejects.toBe(redisError);
    expect(downloadFileWithoutLogging).not.toHaveBeenCalled();
    expect(rawCopyFile).not.toHaveBeenCalled();
    expect(deleteFileFromStorage).not.toHaveBeenCalled();
  });

  it('treats a repeated call with the same key and no version as a no-op once the staged object is consumed', async () => {
    const first = await copyFileFromSyncReference(context, user, buildCopyProps({}));
    // An older stored version keeps the version check out of the way, whatever the clock does between both calls
    const targetFile = buildStoredFile(first?.upload.id as string, { ...first?.upload.metaData, version: '2023-01-01T00:00:00.000Z' });
    vi.mocked(documentFindById).mockResolvedValue(targetFile);
    vi.mocked(downloadFileWithoutLogging).mockResolvedValue(null);
    const error = vi.spyOn(logApp, 'error');

    const repeated = await copyFileFromSyncReference(context, user, buildCopyProps({}));

    expect(repeated).toEqual({ upload: { ...targetFile, information: '', uploadStatus: 'complete' }, untouched: true });
    expect(rawCopyFile).toHaveBeenCalledTimes(1);
    expect(indexFileToDocument).toHaveBeenCalledTimes(1);
    expect(error).not.toHaveBeenCalled();
  });

  it('fails when the staged object is gone and the call carries a newer version than the target', async () => {
    vi.mocked(documentFindById).mockResolvedValue(buildStoredFile('import/Report/entity-1/report.pdf', { version: '2023-01-01T00:00:00.000Z' }));
    vi.mocked(downloadFileWithoutLogging).mockResolvedValue(null);

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({ version: '2024-01-01T00:00:00.000Z' }));

    expect(result).toBeNull();
    expect(rawCopyFile).not.toHaveBeenCalled();
  });

  it('fails when the staged object is gone and the target does not exist', async () => {
    vi.mocked(downloadFileWithoutLogging).mockResolvedValue(null);

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({}));

    expect(result).toBeNull();
    expect(rawCopyFile).not.toHaveBeenCalled();
    expect(indexFileToDocument).not.toHaveBeenCalled();
  });

  it('indexes the same file document as upload() for the same file, markings and entity', async () => {
    const version = '2024-01-01T00:00:00.000Z';
    const entity = { internal_id: 'entity-1' } as BasicStoreEntity;
    const fileUpload = { filename: 'Report.pdf', createReadStream: () => Readable.from([Buffer.from(STAGED_CONTENT)]) };
    await upload(context, user, 'import/Report/entity-1', fileUpload, {
      entity,
      meta: { version, mimetype: 'application/pdf' },
      file_markings: [TLP_AMBER.standard_id],
      noTriggerImport: true,
    });

    await copyFileFromSyncReference(context, user, buildCopyProps({
      name: 'Report.pdf',
      mimeType: 'application/pdf',
      version,
      fileMarkings: [TLP_AMBER.standard_id],
      noTriggerImport: true,
    }));

    const uploaded = indexedFile(0);
    const copied = indexedFile(1);
    expect(copied.metaData).toEqual(uploaded.metaData);
    const comparedFields = (file: LoadedFile) => [file.id, file.name, file.size, file.information, file.uploadStatus];
    expect(comparedFields(copied)).toEqual(comparedFields(uploaded));
  });

  it('never writes the staged key into a log, on success or failure', async () => {
    const logCalls = [vi.spyOn(logApp, 'info'), vi.spyOn(logApp, 'warn'), vi.spyOn(logApp, 'error')];
    await copyFileFromSyncReference(context, user, buildCopyProps({}));
    vi.mocked(deleteFileFromStorage).mockRejectedValueOnce(new Error('S3 unavailable'));
    await copyFileFromSyncReference(context, user, buildCopyProps({}));
    vi.mocked(rawCopyFile).mockRejectedValueOnce(new Error('S3 unavailable'));
    await copyFileFromSyncReference(context, user, buildCopyProps({}));
    vi.mocked(downloadFileWithoutLogging).mockResolvedValueOnce(null);
    await copyFileFromSyncReference(context, user, buildCopyProps({}));
    vi.mocked(lockResources).mockRejectedValueOnce(buildLockError());
    await copyFileFromSyncReference(context, user, buildCopyProps({}));

    const logged = JSON.stringify(logCalls.flatMap((logCall) => logCall.mock.calls));
    expect(logged).not.toContain('remote-file-1');
    expect(logCalls.flatMap((logCall) => logCall.mock.calls).length).toBeGreaterThan(0);
  });

  it('still returns the file as successful when copy and index succeed but deleting the staged source fails', async () => {
    const unlock = vi.fn();
    vi.mocked(lockResources).mockResolvedValue({ unlock });
    vi.mocked(deleteFileFromStorage).mockRejectedValueOnce(new Error('S3 unavailable'));

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({}));

    expect(result?.upload.id).toEqual('import/Report/entity-1/report.pdf');
    expect(indexFileToDocument).toHaveBeenCalled();
    expect(deleteFileFromStorage).toHaveBeenCalledWith(STAGED_KEY);
    expect(unlock).toHaveBeenCalledTimes(1);
  });

  it('triggers the import enrichment job for an import-eligible path, same as a direct upload', async () => {
    const result = await copyFileFromSyncReference(context, user, buildCopyProps({
      noTriggerImport: false,
      importContextEntities: [{ internal_id: 'entity-1', entity_type: 'Report' } as BasicStoreEntity],
    }));

    expect(result).not.toBeNull();
    expect(connectorsForImport).toHaveBeenCalled();
  });

  it('does not trigger the import enrichment job when no_trigger_import is set', async () => {
    const result = await copyFileFromSyncReference(context, user, buildCopyProps({
      noTriggerImport: true,
      importContextEntities: [{ internal_id: 'entity-1' } as BasicStoreEntity],
    }));

    expect(result).not.toBeNull();
    expect(connectorsForImport).not.toHaveBeenCalled();
  });

  it('does not trigger the import enrichment job outside an import-eligible path (e.g. embedded/)', async () => {
    const result = await copyFileFromSyncReference(context, user, buildCopyProps({
      filePath: 'embedded/Report/entity-1',
      noTriggerImport: false,
      importContextEntities: [{ internal_id: 'entity-1' } as BasicStoreEntity],
    }));

    expect(result).not.toBeNull();
    expect(connectorsForImport).not.toHaveBeenCalled();
  });

  it('still returns the file as successful when the import trigger step itself fails', async () => {
    vi.mocked(connectorsForImport).mockRejectedValueOnce(new Error('ES unavailable'));

    const result = await copyFileFromSyncReference(context, user, buildCopyProps({ noTriggerImport: false, importContextEntities: [] }));

    expect(result).not.toBeNull();
    expect(deleteFileFromStorage).toHaveBeenCalled();
  });
});
