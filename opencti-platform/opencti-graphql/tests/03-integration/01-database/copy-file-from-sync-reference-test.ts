import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from 'vitest';
import { createEntity, deleteElementById } from '../../../src/database/middleware';
import { copyFileFromSyncReference, deleteFile, type SyncFileReferenceCopyProps } from '../../../src/database/file-storage';
import { deleteFileFromStorage, downloadFileWithoutLogging, rawUpload, streamToString } from '../../../src/database/raw-file-storage';
import { findById as findDocumentById } from '../../../src/modules/internal/document/document-domain';
import { SYNC_INFLIGHT_STORAGE_PATH } from '../../../src/modules/internal/document/document-types';
import { ENTITY_TYPE_SYNC } from '../../../src/schema/internalObject';
import { logApp } from '../../../src/config/conf';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

const TARGET_PATH = 'import/Report/sync-reference-copy-test';
const STAGED_CONTENT = 'staged sync file content';

const readObject = async (key: string): Promise<string | null> => {
  const stream = await downloadFileWithoutLogging(key);
  return stream ? streamToString(stream) : null;
};
const isRejectedByValidator = (logWarn: MockInstance<typeof logApp.warn>): boolean => {
  return logWarn.mock.calls.some((args) => args[0] === '[FILE STORAGE] Rejected sync file reference copy: invalid or unauthorized storage_key');
};

describe('copyFileFromSyncReference against the object storage', () => {
  let syncId: string;
  const stagedKeys: string[] = [];
  const targetIds: string[] = [];

  const stage = async (fileName: string, content: string): Promise<string> => {
    const storageKey = `${SYNC_INFLIGHT_STORAGE_PATH}/${syncId}/${crypto.randomBytes(16).toString('hex')}/${fileName}`;
    await rawUpload(storageKey, content);
    stagedKeys.push(storageKey);
    return storageKey;
  };
  const buildCopyProps = (storageKey: string, name: string): SyncFileReferenceCopyProps => ({
    syncId,
    filePath: TARGET_PATH,
    storageKey,
    name,
    entityId: 'sync-reference-copy-test',
    noTriggerImport: true,
    importContextEntities: [],
  });

  beforeAll(async () => {
    const creationResult = await createEntity(testContext, ADMIN_USER, {
      name: 'sync-reference-copy-test',
      uri: 'http://localhost:4242',
      token: 'token',
      stream_id: 'stream--sync-reference-copy-test',
      running: false,
      listen_deletion: true,
      no_dependencies: false,
      ssl_verify: false,
      synchronized: false,
      user_id: ADMIN_USER.id,
    }, ENTITY_TYPE_SYNC, { complete: true });
    const sync = 'element' in creationResult ? creationResult.element : creationResult;
    syncId = sync.internal_id;
  });

  afterAll(async () => {
    for (let index = 0; index < targetIds.length; index += 1) {
      await deleteFile(testContext, ADMIN_USER, targetIds[index], { forceDelete: true });
    }
    for (let index = 0; index < stagedKeys.length; index += 1) {
      await deleteFileFromStorage(stagedKeys[index]);
    }
    await deleteElementById(testContext, ADMIN_USER, syncId, ENTITY_TYPE_SYNC);
  });

  it('copies a key in the stager format, indexes its hash and deletes the staged object', async () => {
    const storageKey = await stage('content', STAGED_CONTENT);
    const result = await copyFileFromSyncReference(testContext, ADMIN_USER, buildCopyProps(storageKey, 'report.txt'));
    targetIds.push(`${TARGET_PATH}/report.txt`);

    expect(result?.untouched).toBe(false);
    expect(await readObject(`${TARGET_PATH}/report.txt`)).toBe(STAGED_CONTENT);
    expect(await readObject(storageKey)).toBeNull();
    const document = await findDocumentById(testContext, ADMIN_USER, `${TARGET_PATH}/report.txt`);
    expect(document.metaData.sha256).toBe(crypto.createHash('sha256').update(STAGED_CONTENT).digest('hex'));
  });

  it('never copies a neighbour object that a percent escape in the key decodes to', async () => {
    const remoteFileId = crypto.randomBytes(16).toString('hex');
    const literalKey = `${SYNC_INFLIGHT_STORAGE_PATH}/${syncId}/${remoteFileId}/report%20final.pdf`;
    const neighbourKey = `${SYNC_INFLIGHT_STORAGE_PATH}/${syncId}/${remoteFileId}/report final.pdf`;
    await rawUpload(literalKey, STAGED_CONTENT);
    await rawUpload(neighbourKey, 'neighbour content');
    stagedKeys.push(literalKey, neighbourKey);
    const logWarn = vi.spyOn(logApp, 'warn');
    const result = await copyFileFromSyncReference(testContext, ADMIN_USER, buildCopyProps(literalKey.replace('%20', '%2520'), 'neighbour.txt'));
    targetIds.push(`${TARGET_PATH}/neighbour.txt`);

    expect(result).toBeNull();
    expect(isRejectedByValidator(logWarn)).toBe(true);
    logWarn.mockRestore();
    expect(await readObject(literalKey)).toBe(STAGED_CONTENT);
    expect(await readObject(neighbourKey)).toBe('neighbour content');
    expect(await readObject(`${TARGET_PATH}/neighbour.txt`)).toBeNull();
    expect(await findDocumentById(testContext, ADMIN_USER, `${TARGET_PATH}/neighbour.txt`)).toBeUndefined();
  });

  it('rejects a key the HTTP layer cannot send as a copy source before it reaches the storage', async () => {
    const storageKey = await stage('report-😀.pdf', STAGED_CONTENT);
    const logWarn = vi.spyOn(logApp, 'warn');
    const result = await copyFileFromSyncReference(testContext, ADMIN_USER, buildCopyProps(storageKey, 'emoji.txt'));
    targetIds.push(`${TARGET_PATH}/emoji.txt`);

    expect(result).toBeNull();
    expect(isRejectedByValidator(logWarn)).toBe(true);
    logWarn.mockRestore();
    expect(await readObject(storageKey)).toBe(STAGED_CONTENT);
    expect(await readObject(`${TARGET_PATH}/emoji.txt`)).toBeNull();
    expect(await findDocumentById(testContext, ADMIN_USER, `${TARGET_PATH}/emoji.txt`)).toBeUndefined();
  });
});
