import crypto from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_CONNECTOR } from '../utils/testQuery';
import { createUploadFromTestDataFile, queryAsAdmin, queryAsUser } from '../utils/testQueryHelper';
import { createEntity, deleteElementById } from '../../src/database/middleware';
import { storeLoadById } from '../../src/database/middleware-loader';
import { deleteFile } from '../../src/database/file-storage';
import { deleteFileFromStorage, downloadFileWithoutLogging, rawUpload, streamToString } from '../../src/database/raw-file-storage';
import { findById as findDocumentById } from '../../src/modules/internal/document/document-domain';
import { SYNC_INFLIGHT_STORAGE_PATH } from '../../src/modules/internal/document/document-types';
import { ENTITY_TYPE_SYNC } from '../../src/schema/internalObject';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../src/schema/stixDomainObject';
import type { FileRefInput } from '../../src/generated/graphql';
import type { BasicStoreEntity } from '../../src/types/store';

interface ReportAddQueryData {
  reportAdd: ImportedEntity;
}

interface ImportedEntity {
  id: string;
}

interface ImportPushQueryData {
  stixDomainObjectEdit: ImportPushEdit;
}

interface ImportPushEdit {
  importPush: ImportedEntity | null;
}

interface ImportPushRefQueryData {
  stixDomainObjectEdit: ImportPushRefEdit;
}

interface ImportPushRefEdit {
  importPushRef: ImportedEntity | null;
}

interface StagedFileRef {
  syncId: string;
  storageKey: string;
  version: string;
}

type StoredFile = NonNullable<BasicStoreEntity['x_opencti_files']>[number];

const REPORT_ADD_QUERY = gql`
  mutation ReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
    }
  }
`;

const IMPORT_PUSH_QUERY = gql`
  mutation ImportPush($id: ID!, $file: Upload!, $version: DateTime) {
    stixDomainObjectEdit(id: $id) {
      importPush(file: $file, version: $version, noTriggerImport: true) {
        id
      }
    }
  }
`;

const IMPORT_PUSH_REF_QUERY = gql`
  mutation ImportPushRef($id: ID!, $fileRef: FileRefInput!) {
    stixDomainObjectEdit(id: $id) {
      importPushRef(fileRef: $fileRef) {
        id
      }
    }
  }
`;

const FILE_NAME = 'import-push-ref.txt';
const SYNC_CONTENT = 'content staged by the sync';

const createTestSync = async (name: string): Promise<string> => {
  const creationResult = await createEntity(testContext, ADMIN_USER, {
    name,
    uri: 'http://localhost:4242',
    token: 'token',
    stream_id: `stream--${name}`,
    running: false,
    listen_deletion: true,
    no_dependencies: false,
    ssl_verify: false,
    synchronized: false,
    user_id: ADMIN_USER.id,
  }, ENTITY_TYPE_SYNC, { complete: true });
  const sync = 'element' in creationResult ? creationResult.element : creationResult;
  return sync.internal_id;
};

const readObject = async (key: string): Promise<string | null> => {
  const stream = await downloadFileWithoutLogging(key);
  return stream ? streamToString(stream) : null;
};

const buildFileRef = (staged: StagedFileRef): FileRefInput => ({
  sync_id: staged.syncId,
  storage_key: staged.storageKey,
  name: FILE_NAME,
  mime_type: 'text/plain',
  version: staged.version,
  no_trigger_import: true,
});

describe('importPushRef resolver', () => {
  let syncId: string;
  let otherSyncId: string;
  let reportId: string;
  let fileId: string;
  const stagedKeys: string[] = [];

  const stage = async (stagingSyncId: string, content: string): Promise<string> => {
    const storageKey = `${SYNC_INFLIGHT_STORAGE_PATH}/${stagingSyncId}/${crypto.randomBytes(16).toString('hex')}/content`;
    await rawUpload(storageKey, content);
    stagedKeys.push(storageKey);
    return storageKey;
  };
  const loadReport = () => storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, reportId, ENTITY_TYPE_CONTAINER_REPORT);
  const attachedFile = (report: BasicStoreEntity): StoredFile | undefined => report.x_opencti_files?.find((file) => file.id === fileId);
  const pushRef = (staged: StagedFileRef) => queryAsAdmin<ImportPushRefQueryData>({ query: IMPORT_PUSH_REF_QUERY, variables: { id: reportId, fileRef: buildFileRef(staged) } });

  beforeAll(async () => {
    syncId = await createTestSync('import-push-ref-sync');
    otherSyncId = await createTestSync('import-push-ref-other-sync');
    const reportResult = await queryAsAdmin<ReportAddQueryData>({
      query: REPORT_ADD_QUERY,
      variables: { input: { name: 'import-push-ref-report', published: '2024-01-01T00:00:00.000Z' } },
    });
    reportId = reportResult.data?.reportAdd.id as string;
    fileId = `import/Report/${reportId}/${FILE_NAME}`;
  });

  afterAll(async () => {
    await deleteFile(testContext, ADMIN_USER, fileId, { forceDelete: true });
    await deleteElementById(testContext, ADMIN_USER, reportId, ENTITY_TYPE_CONTAINER_REPORT);
    for (let index = 0; index < stagedKeys.length; index += 1) {
      await deleteFileFromStorage(stagedKeys[index]);
    }
    await deleteElementById(testContext, ADMIN_USER, syncId, ENTITY_TYPE_SYNC);
    await deleteElementById(testContext, ADMIN_USER, otherSyncId, ENTITY_TYPE_SYNC);
  });

  it('attaches a staged file under the same entry and document importPush writes for the same name', async () => {
    const upload = await createUploadFromTestDataFile('test-file-to-index.txt', FILE_NAME, 'text/plain');
    const pushResult = await queryAsAdmin<ImportPushQueryData>({ query: IMPORT_PUSH_QUERY, variables: { id: reportId, file: upload, version: '2024-01-01T00:00:00.000Z' } });
    expect(pushResult.errors).toBeUndefined();
    const pushedEntry = attachedFile(await loadReport());
    const pushedDocument = await findDocumentById(testContext, ADMIN_USER, fileId);

    const storageKey = await stage(syncId, SYNC_CONTENT);
    const pushRefResult = await pushRef({ syncId, storageKey, version: '2024-02-01T00:00:00.000Z' });

    expect(pushRefResult.errors).toBeUndefined();
    expect(pushRefResult.data?.stixDomainObjectEdit.importPushRef?.id).toEqual(fileId);
    const copiedEntry = attachedFile(await loadReport());
    expect({ ...copiedEntry, version: undefined }).toEqual({ ...pushedEntry, version: undefined });
    expect(copiedEntry?.version).toEqual('2024-02-01T00:00:00.000Z');
    const copiedDocument = await findDocumentById(testContext, ADMIN_USER, fileId);
    expect({ ...copiedDocument.metaData, version: undefined, sha256: undefined }).toEqual({ ...pushedDocument.metaData, version: undefined, sha256: undefined });
    expect(await readObject(fileId)).toEqual(SYNC_CONTENT);
    expect(await readObject(storageKey)).toBeNull();
  });

  it('leaves the entity untouched when the staged bytes are already attached, even at a newer version', async () => {
    const before = await loadReport();
    const storageKey = await stage(syncId, SYNC_CONTENT);

    const pushRefResult = await pushRef({ syncId, storageKey, version: '2024-03-01T00:00:00.000Z' });

    expect(pushRefResult.errors).toBeUndefined();
    const after = await loadReport();
    expect(after.x_opencti_files).toEqual(before.x_opencti_files);
    expect(after.updated_at).toEqual(before.updated_at);
    expect(await readObject(storageKey)).toBeNull();
  });

  it('leaves the entity untouched when the attached file already has this version', async () => {
    const before = await loadReport();
    const storageKey = await stage(syncId, 'other content at the same version');

    const pushRefResult = await pushRef({ syncId, storageKey, version: '2024-02-01T00:00:00.000Z' });

    expect(pushRefResult.errors).toBeUndefined();
    const after = await loadReport();
    expect(after.x_opencti_files).toEqual(before.x_opencti_files);
    expect(after.updated_at).toEqual(before.updated_at);
    expect(await readObject(fileId)).toEqual(SYNC_CONTENT);
  });

  it('refuses a key staged by another sync with only the sync id in the error, and keeps it', async () => {
    const storageKey = await stage(otherSyncId, 'staged by another sync');

    const pushRefResult = await pushRef({ syncId, storageKey, version: '2024-04-01T00:00:00.000Z' });

    expect(pushRefResult.errors?.[0].message).toEqual('Cannot copy referenced sync file');
    expect(JSON.stringify(pushRefResult.errors)).not.toContain(storageKey);
    expect(await readObject(storageKey)).toEqual('staged by another sync');
    expect(await readObject(fileId)).toEqual(SYNC_CONTENT);
  });

  it('refuses a caller who is not the user the sync runs as, and keeps the staged file', async () => {
    const storageKey = await stage(syncId, 'staged for the sync user only');
    const fileRef = buildFileRef({ syncId, storageKey, version: '2024-04-01T00:00:00.000Z' });

    const pushRefResult = await queryAsUser(USER_CONNECTOR, { query: IMPORT_PUSH_REF_QUERY, variables: { id: reportId, fileRef } });

    expect(pushRefResult.errors?.[0].message).toEqual('Cannot copy referenced sync file');
    expect(JSON.stringify(pushRefResult.errors)).not.toContain(storageKey);
    expect(await readObject(storageKey)).toEqual('staged for the sync user only');
    expect(await readObject(fileId)).toEqual(SYNC_CONTENT);
  });
});
