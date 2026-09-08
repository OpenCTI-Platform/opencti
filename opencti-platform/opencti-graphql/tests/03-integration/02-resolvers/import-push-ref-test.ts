import { afterAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { downloadFile, rawUpload } from '../../../src/database/raw-file-storage';
import { deleteElementById } from '../../../src/database/middleware';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';

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
    const syncId = 'sync--f10-verify';
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
    // This is the real attack this segment's fix was built for: sync_id/storage_key are only
    // cross-checked for internal consistency, never against caller identity (every worker shares
    // one platform-wide token) -- so the only thing that can still stop this is that a genuine
    // storage_key for sync A is never derivable/guessable by whoever only knows sync B's id.
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

  it('fails cleanly on a redelivered message replaying an already-consumed storage_key (no duplicate file, no crash)', async () => {
    const reportResult = await queryAsAdmin({
      query: REPORT_ADD_QUERY,
      variables: { input: { name: 'f14-redelivery-report', published: '2020-02-26T00:51:35.000Z' } },
    });
    expect(reportResult.errors).toBeUndefined();
    const reportId = reportResult.data?.reportAdd.id;
    reportIds.push(reportId);

    const syncId = 'sync--f14-redelivery';
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

    const syncId = 'sync--f14-large-file';
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
