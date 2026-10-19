import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, getUserIdByEmail, testContext, USER_CONNECTOR, USER_EDITOR } from '../../utils/testQuery';
import { queryAsAdmin, queryAsUser } from '../../utils/testQueryHelper';
import { downloadFile, rawUpload } from '../../../src/database/raw-file-storage';
import { createEntity, deleteElementById } from '../../../src/database/middleware';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_SYNC } from '../../../src/schema/internalObject';
import { MARKING_TLP_AMBER, MARKING_TLP_GREEN, MARKING_TLP_RED } from '../../../src/schema/identifier';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

// This test proves the real end-to-end pipeline for issue #17896 works against actual
// S3 (minio) and Elasticsearch - no mocks. It stages a file exactly the way syncManager.js
// does in ref mode (f5), then drives the real GraphQL mutation exactly like the worker will
// in f12 (f7/f10), and verifies the file is genuinely attached, byte-identical, and that the
// staged sync/inflight source was cleaned up (f6).
const REPORT_ADD_QUERY = gql`
  mutation ReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) {
      id
    }
  }
`;

const IMPORT_PUSH_REF_QUERY = gql`
  mutation ImportPushRef($id: ID!, $fileRef: FileRefInput!) {
    stixDomainObjectEdit(id: $id) {
      importPushRef(fileRef: $fileRef) {
        id
        name
        size
      }
    }
  }
`;

const REPORT_FILES_QUERY = gql`
  query report($id: String!) {
    report(id: $id) {
      id
      importFiles {
        edges {
          node {
            id
            name
          }
        }
      }
    }
  }
`;

const createTestSync = async (name: string, userId: string): Promise<string> => {
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
    user_id: userId,
  }, ENTITY_TYPE_SYNC, { complete: true });
  const synchronizer = 'element' in creationResult ? creationResult.element : creationResult;
  return synchronizer.internal_id;
};

// importPushRef only accepts the user a sync runs as, and queryAsAdmin calls as admin.
let adminSyncId: string;
let editorSyncId: string;

beforeAll(async () => {
  adminSyncId = await createTestSync('import-push-ref-admin-sync', ADMIN_USER.id);
  editorSyncId = await createTestSync('import-push-ref-editor-sync', USER_EDITOR.id);
});

afterAll(async () => {
  await deleteElementById(testContext, ADMIN_USER, adminSyncId, ENTITY_TYPE_SYNC);
  await deleteElementById(testContext, ADMIN_USER, editorSyncId, ENTITY_TYPE_SYNC);
});

describe('f10 - importPushRef end-to-end', () => {
  let reportId: string;

  afterAll(async () => {
    if (reportId) {
      await deleteElementById(testContext, ADMIN_USER, reportId, ENTITY_TYPE_CONTAINER_REPORT);
    }
  });

  it('copies a staged sync/inflight file into the entity via a real GraphQL importPushRef call', async () => {
    // 00. Create a throwaway report to attach the file to
    const reportResult = await queryAsAdmin({
      query: REPORT_ADD_QUERY,
      variables: { input: { name: 'f10-verify-report', published: '2020-02-26T00:51:35.000Z' } },
    });
    expect(reportResult.errors).toBeUndefined();
    reportId = reportResult.data?.reportAdd.id;

    // 01. Stage a file exactly the way syncManager.js does in ref mode (real S3 write, no mocks)
    const syncId = adminSyncId;
    const storageKey = `sync/inflight/${syncId}/f10-verify-file/content`;
    const content = Buffer.from('hello from the f10 end-to-end check');
    await rawUpload(storageKey, content);

    // 02. Call the real GraphQL mutation, exactly like the worker will call it once f12 lands
    const fileRef = {
      sync_id: syncId,
      storage_key: storageKey,
      name: 'f10-verify.txt',
      mime_type: 'text/plain',
    };
    const pushResult = await queryAsAdmin({
      query: IMPORT_PUSH_REF_QUERY,
      variables: { id: reportId, fileRef },
    });
    expect(pushResult.errors).toBeUndefined();
    const file = pushResult.data?.stixDomainObjectEdit.importPushRef;
    expect(file.name).toEqual('f10-verify.txt');

    // 03. The file is really attached to the entity (not just floating in storage)
    const reportData = await queryAsAdmin({ query: REPORT_FILES_QUERY, variables: { id: reportId } });
    const attachedFileIds = reportData.data?.report.importFiles.edges.map((e: { node: { id: string } }) => e.node.id);
    expect(attachedFileIds).toContain(file.id);

    // 04. The bytes at the final location match exactly what was staged (real S3 read)
    const downloadedStream = await downloadFile(file.id);
    expect(downloadedStream).not.toBeNull();
    const chunks: Buffer[] = [];
    for await (const chunk of downloadedStream!) {
      chunks.push(chunk as Buffer);
    }
    expect(Buffer.concat(chunks).toString()).toEqual(content.toString());

    // 05. The staged sync/inflight source was deleted after the copy (no orphaned data left behind)
    const stagedStillThere = await downloadFile(storageKey);
    expect(stagedStillThere).toBeNull();
  });
});

// f14 - closes out the roadmap with the failure-injection / adversarial scenarios that only
// make sense against real S3 + Elastic (not mocks): a cross-sync theft attempt, a redelivered
// message replaying an already-consumed key, and a larger payload proving the pipeline never
// buffers the whole file as base64 (the original motivation for #17896).
describe('f14 - importPushRef failure injection and adversarial scenarios', () => {
  // Each `it` below creates its own throwaway report, so a single shared `reportId` reassigned
  // per-test would only let afterAll clean up the last one, leaking the earlier reports into
  // the shared integration DB (this previously broke report-test.js's exact-count assertions).
  // Track every id created in this block instead, and delete them all at the end.
  const reportIds: string[] = [];

  afterAll(async () => {
    await Promise.all(reportIds.map((id) => deleteElementById(testContext, ADMIN_USER, id, ENTITY_TYPE_CONTAINER_REPORT)));
  });

  it('rejects a storage_key staged for a different sync, without leaking or consuming it', async () => {
    const reportResult = await queryAsAdmin({
      query: REPORT_ADD_QUERY,
      variables: { input: { name: 'f14-cross-sync-report', published: '2020-02-26T00:51:35.000Z' } },
    });
    expect(reportResult.errors).toBeUndefined();
    const reportId = reportResult.data?.reportAdd.id;
    reportIds.push(reportId);

    // Stage a file for sync A, then try to consume it while claiming to be sync B.
    const realSyncId = 'sync--f14-real-owner';
    const attackerClaimedSyncId = 'sync--f14-attacker';
    const storageKey = `sync/inflight/${realSyncId}/f14-real-file/content`;
    const content = Buffer.from('this file belongs to sync--f14-real-owner only');
    await rawUpload(storageKey, content);

    const pushResult = await queryAsAdmin({
      query: IMPORT_PUSH_REF_QUERY,
      variables: {
        id: reportId,
        fileRef: { sync_id: attackerClaimedSyncId, storage_key: storageKey, name: 'stolen.txt', mime_type: 'text/plain' },
      },
    });
    expect(pushResult.errors?.[0]?.message).toEqual('Cannot copy referenced sync file');
    expect(pushResult.data?.stixDomainObjectEdit.importPushRef).toBeNull();

    // Nothing was attached, and the real owner's staged file is untouched (still there, unconsumed)
    const reportData = await queryAsAdmin({ query: REPORT_FILES_QUERY, variables: { id: reportId } });
    expect(reportData.data?.report.importFiles.edges).toEqual([]);
    const stillStaged = await downloadFile(storageKey);
    expect(stillStaged).not.toBeNull();

    // Clean up the still-staged file ourselves since this test intentionally never consumes it
    const chunks: Buffer[] = [];
    for await (const chunk of stillStaged!) chunks.push(chunk as Buffer);
    expect(Buffer.concat(chunks).toString()).toEqual(content.toString());
  });

  it('rejects a caller who is not the user the sync runs as, without consuming the staged file', async () => {
    const reportResult = await queryAsAdmin({
      query: REPORT_ADD_QUERY,
      variables: { input: { name: 'f14-foreign-sync-report', published: '2020-02-26T00:51:35.000Z' } },
    });
    expect(reportResult.errors).toBeUndefined();
    const reportId = reportResult.data?.reportAdd.id;
    reportIds.push(reportId);

    const storageKey = `sync/inflight/${editorSyncId}/f14-foreign-sync-file/content`;
    await rawUpload(storageKey, Buffer.from('staged for a sync that runs as the editor'));

    const pushResult = await queryAsAdmin({
      query: IMPORT_PUSH_REF_QUERY,
      variables: {
        id: reportId,
        fileRef: { sync_id: editorSyncId, storage_key: storageKey, name: 'foreign.txt', mime_type: 'text/plain' },
      },
    });
    expect(pushResult.errors?.[0]?.message).toEqual('Cannot copy referenced sync file');
    const stillStaged = await downloadFile(storageKey);
    expect(stillStaged).not.toBeNull();
    stillStaged?.destroy();
  });

  it('fails cleanly on a redelivered message replaying an already-consumed storage_key (no duplicate file, no crash)', async () => {
    const reportResult = await queryAsAdmin({
      query: REPORT_ADD_QUERY,
      variables: { input: { name: 'f14-redelivery-report', published: '2020-02-26T00:51:35.000Z' } },
    });
    expect(reportResult.errors).toBeUndefined();
    const reportId = reportResult.data?.reportAdd.id;
    reportIds.push(reportId);

    const syncId = adminSyncId;
    const storageKey = `sync/inflight/${syncId}/f14-redelivery-file/content`;
    await rawUpload(storageKey, Buffer.from('delivered once, replayed once'));
    const fileRef = { sync_id: syncId, storage_key: storageKey, name: 'redelivered.txt', mime_type: 'text/plain' };

    // First delivery: the worker processes the message normally, file gets attached and the
    // staged source is consumed (deleted).
    const firstAttempt = await queryAsAdmin({ query: IMPORT_PUSH_REF_QUERY, variables: { id: reportId, fileRef } });
    expect(firstAttempt.errors).toBeUndefined();
    expect(firstAttempt.data?.stixDomainObjectEdit.importPushRef).not.toBeNull();

    // Simulate RabbitMQ redelivering the exact same message (e.g. worker crashed after the
    // mutation succeeded but before acking). The mutation must fail closed (thrown functional
    // error, not a crash), and must not create a second/duplicate file on the entity.
    const redelivery = await queryAsAdmin({ query: IMPORT_PUSH_REF_QUERY, variables: { id: reportId, fileRef } });
    expect(redelivery.errors?.[0]?.message).toEqual('Cannot copy referenced sync file');
    expect(redelivery.data?.stixDomainObjectEdit.importPushRef).toBeNull();

    const reportData = await queryAsAdmin({ query: REPORT_FILES_QUERY, variables: { id: reportId } });
    const attachedNames = reportData.data?.report.importFiles.edges.map((e: { node: { name: string } }) => e.node.name);
    expect(attachedNames.filter((n: string) => n === 'redelivered.txt')).toHaveLength(1);
  });

  it('round-trips a several-MB payload byte-for-byte without ever materializing it as base64 (the #17896 motivation)', async () => {
    const reportResult = await queryAsAdmin({
      query: REPORT_ADD_QUERY,
      variables: { input: { name: 'f14-large-file-report', published: '2020-02-26T00:51:35.000Z' } },
    });
    expect(reportResult.errors).toBeUndefined();
    const reportId = reportResult.data?.reportAdd.id;
    reportIds.push(reportId);

    // 8MB of pseudo-random bytes. Large enough to be representative of the real-world payloads
    // (scan reports, PCAPs, memory dumps) that used to risk ERR_STRING_TOO_LONG once base64
    // encoded and embedded in a single RabbitMQ JSON message; small enough to keep the test fast.
    const largeContent = Buffer.alloc(8 * 1024 * 1024);
    for (let i = 0; i < largeContent.length; i += 4) largeContent.writeUInt32LE((i * 2654435761) >>> 0, i);

    const syncId = adminSyncId;
    const storageKey = `sync/inflight/${syncId}/f14-large-file/content`;
    await rawUpload(storageKey, largeContent);

    const pushResult = await queryAsAdmin({
      query: IMPORT_PUSH_REF_QUERY,
      variables: {
        id: reportId,
        fileRef: { sync_id: syncId, storage_key: storageKey, name: 'large-payload.bin', mime_type: 'application/octet-stream' },
      },
    });
    expect(pushResult.errors).toBeUndefined();
    const file = pushResult.data?.stixDomainObjectEdit.importPushRef;
    expect(file.size).toEqual(largeContent.length);

    const downloadedStream = await downloadFile(file.id);
    expect(downloadedStream).not.toBeNull();
    const chunks: Buffer[] = [];
    for await (const chunk of downloadedStream!) chunks.push(chunk as Buffer);
    expect(Buffer.concat(chunks).equals(largeContent)).toBe(true);
  });
});

const IMPORT_PUSH_REF_MARKINGS_QUERY = gql`
  mutation ImportPushRefMarkings($id: ID!, $fileRef: FileRefInput!) {
    stixDomainObjectEdit(id: $id) {
      importPushRef(fileRef: $fileRef) {
        id
        metaData {
          file_markings
        }
        objectMarking {
          id
          standard_id
        }
      }
    }
  }
`;

const REPORT_STIX_QUERY = gql`
  query reportStix($id: String!) {
    report(id: $id) {
      toStix
    }
  }
`;

const MARKING_QUERY = gql`
  query markingDefinition($id: String!) {
    markingDefinition(id: $id) {
      id
    }
  }
`;

const MISSING_MARKINGS_ERROR = 'User trying to create the data has missing markings';

interface MarkedFileRef {
  sync_id: string;
  storage_key: string;
  name: string;
  mime_type: string;
  file_markings: (string | null)[];
}

interface PushedFileMarking {
  id: string;
  standard_id: string;
}

interface PushedFileMetaData {
  file_markings: string[];
}

interface PushedFile {
  id: string;
  metaData: PushedFileMetaData;
  objectMarking: PushedFileMarking[];
}

interface StixFile {
  name: string;
  object_marking_refs: string[];
}

interface StixOctiExtension {
  files: StixFile[];
}

interface StixEntity {
  extensions: Record<string, StixOctiExtension>;
}

const buildMarkedFileRef = (syncId: string, name: string, fileMarkings: (string | null)[]): MarkedFileRef => ({
  sync_id: syncId,
  storage_key: `sync/inflight/${syncId}/${name}/content`,
  name: `${name}.txt`,
  mime_type: 'text/plain',
  file_markings: fileMarkings,
});

const stageMarkedFile = async (fileRef: MarkedFileRef) => {
  await rawUpload(fileRef.storage_key, Buffer.from(`staged ${fileRef.name}`));
};

const isStillStaged = async (storageKey: string): Promise<boolean> => {
  const stream = await downloadFile(storageKey);
  stream?.destroy();
  return stream !== null;
};

const countAttachedFiles = async (reportId: string): Promise<number> => {
  const reportData = await queryAsAdmin({ query: REPORT_FILES_QUERY, variables: { id: reportId } });
  return reportData.data?.report.importFiles.edges.length;
};

// Markings come from the sending platform, so a sync user must not be able to stamp a file with a marking it does not hold.
describe('importPushRef file markings', () => {
  const reportIds: string[] = [];
  let connectorSyncId: string;

  beforeAll(async () => {
    const connectorUserId = await getUserIdByEmail(USER_CONNECTOR.email);
    connectorSyncId = await createTestSync('import-push-ref-connector-sync', connectorUserId);
  });

  afterAll(async () => {
    await Promise.all(reportIds.map((id) => deleteElementById(testContext, ADMIN_USER, id, ENTITY_TYPE_CONTAINER_REPORT)));
    await deleteElementById(testContext, ADMIN_USER, connectorSyncId, ENTITY_TYPE_SYNC);
  });

  const createMarkingsReport = async (name: string): Promise<string> => {
    const reportResult = await queryAsAdmin({
      query: REPORT_ADD_QUERY,
      variables: { input: { name, published: '2020-02-26T00:51:35.000Z' } },
    });
    expect(reportResult.errors).toBeUndefined();
    const reportId: string = reportResult.data?.reportAdd.id;
    reportIds.push(reportId);
    return reportId;
  };

  const pushAsConnector = (reportId: string, fileRef: MarkedFileRef) => {
    return queryAsUser(USER_CONNECTOR, { query: IMPORT_PUSH_REF_MARKINGS_QUERY, variables: { id: reportId, fileRef } });
  };

  it('stores a standard_id marking as its internal id and exports it in the entity STIX files', async () => {
    const reportId = await createMarkingsReport('markings-admin-amber-report');
    const fileRef = buildMarkedFileRef(adminSyncId, 'markings-admin-amber', [MARKING_TLP_AMBER]);
    await stageMarkedFile(fileRef);

    const pushResult = await queryAsAdmin({ query: IMPORT_PUSH_REF_MARKINGS_QUERY, variables: { id: reportId, fileRef } });
    expect(pushResult.errors).toBeUndefined();
    const file: PushedFile = pushResult.data?.stixDomainObjectEdit.importPushRef;
    expect(file.objectMarking.map((marking) => marking.standard_id)).toEqual([MARKING_TLP_AMBER]);
    expect(file.metaData.file_markings).toEqual(file.objectMarking.map((marking) => marking.id));

    const stixResult = await queryAsAdmin({ query: REPORT_STIX_QUERY, variables: { id: reportId } });
    const stixReport: StixEntity = JSON.parse(stixResult.data?.report.toStix);
    const stixFile = stixReport.extensions[STIX_EXT_OCTI].files.find((f) => f.name === fileRef.name);
    expect(stixFile?.object_marking_refs).toEqual([MARKING_TLP_AMBER]);
  });

  it('lets a non-bypass sync user attach a file with a marking it holds', async () => {
    const reportId = await createMarkingsReport('markings-connector-green-report');
    const fileRef = buildMarkedFileRef(connectorSyncId, 'markings-connector-green', [MARKING_TLP_GREEN]);
    await stageMarkedFile(fileRef);

    const pushResult = await pushAsConnector(reportId, fileRef);
    expect(pushResult.errors).toBeUndefined();
    const file: PushedFile = pushResult.data?.stixDomainObjectEdit.importPushRef;
    expect(file.objectMarking.map((marking) => marking.standard_id)).toEqual([MARKING_TLP_GREEN]);
    expect(await isStillStaged(fileRef.storage_key)).toBe(false);
  });

  it('rejects a marking the sync user does not hold without consuming the staged file, which stays retryable', async () => {
    const reportId = await createMarkingsReport('markings-connector-red-report');
    const rejectedRef = buildMarkedFileRef(connectorSyncId, 'markings-connector-red', [MARKING_TLP_RED]);
    await stageMarkedFile(rejectedRef);

    const rejected = await pushAsConnector(reportId, rejectedRef);
    expect(rejected.errors?.[0]?.message).toEqual(MISSING_MARKINGS_ERROR);
    expect(await countAttachedFiles(reportId)).toEqual(0);
    expect(await isStillStaged(rejectedRef.storage_key)).toBe(true);

    // A leaked lock or a consumed staged file would make this retry fail.
    const retriedRef: MarkedFileRef = { ...rejectedRef, file_markings: [MARKING_TLP_GREEN] };
    const retried = await pushAsConnector(reportId, retriedRef);
    expect(retried.errors).toBeUndefined();
    expect(await countAttachedFiles(reportId)).toEqual(1);
    expect(await isStillStaged(rejectedRef.storage_key)).toBe(false);
  });

  it('rejects the whole request when only one of several markings is not held', async () => {
    const reportId = await createMarkingsReport('markings-connector-mixed-report');
    const fileRef = buildMarkedFileRef(connectorSyncId, 'markings-connector-mixed', [MARKING_TLP_GREEN, MARKING_TLP_RED]);
    await stageMarkedFile(fileRef);

    const pushResult = await pushAsConnector(reportId, fileRef);
    expect(pushResult.errors?.[0]?.message).toEqual(MISSING_MARKINGS_ERROR);
    expect(await countAttachedFiles(reportId)).toEqual(0);
    expect(await isStillStaged(fileRef.storage_key)).toBe(true);
  });

  it('rejects a marking id that does not exist on the receiving platform', async () => {
    const reportId = await createMarkingsReport('markings-connector-unknown-report');
    const unknownMarking = 'marking-definition--00000000-0000-4000-8000-000000000000';
    const fileRef = buildMarkedFileRef(connectorSyncId, 'markings-connector-unknown', [unknownMarking]);
    await stageMarkedFile(fileRef);

    const pushResult = await pushAsConnector(reportId, fileRef);
    expect(pushResult.errors?.[0]?.message).toEqual(MISSING_MARKINGS_ERROR);
    expect(await countAttachedFiles(reportId)).toEqual(0);
    expect(await isStillStaged(fileRef.storage_key)).toBe(true);
  });

  it('keeps a marking already given as an internal id and drops null entries', async () => {
    const reportId = await createMarkingsReport('markings-connector-internal-id-report');
    const markingResult = await queryAsAdmin({ query: MARKING_QUERY, variables: { id: MARKING_TLP_GREEN } });
    const greenInternalId: string = markingResult.data?.markingDefinition.id;
    const fileRef = buildMarkedFileRef(connectorSyncId, 'markings-connector-internal-id', [null, greenInternalId]);
    await stageMarkedFile(fileRef);

    const pushResult = await pushAsConnector(reportId, fileRef);
    expect(pushResult.errors).toBeUndefined();
    const file: PushedFile = pushResult.data?.stixDomainObjectEdit.importPushRef;
    expect(file.metaData.file_markings).toEqual([greenInternalId]);
  });

  it('attaches the file without markings when the list is empty', async () => {
    const reportId = await createMarkingsReport('markings-connector-empty-report');
    const fileRef = buildMarkedFileRef(connectorSyncId, 'markings-connector-empty', []);
    await stageMarkedFile(fileRef);

    const pushResult = await pushAsConnector(reportId, fileRef);
    expect(pushResult.errors).toBeUndefined();
    const file: PushedFile = pushResult.data?.stixDomainObjectEdit.importPushRef;
    expect(file.metaData.file_markings).toEqual([]);
    expect(file.objectMarking).toEqual([]);
  });
});
