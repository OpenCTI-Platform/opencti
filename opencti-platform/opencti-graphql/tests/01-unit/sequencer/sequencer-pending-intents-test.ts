import { describe, expect, it, vi } from 'vitest';
import {
  deferIntents,
  deferOperation,
  fireResubmit,
  matchLandedIntents,
  pendingIntentRecordKey,
  pendingRecordInput,
  registerPendingFileStaging,
  registerPendingIntentsEsOps,
  registerPendingOperationExecute,
} from '../../../src/database/sequencer/sequencer-pending-intents';
import { toUpload } from '../../../src/intake/file-values';
import { type FileStorage, rehydrateFiles, removeStagedFiles, stageFiles } from '../../../src/intake/intake-files';
import { UploadFile } from '../../../src/intake/stix-import/types';

describe('pending intent record key', () => {
  const input = {
    stix_id: 'relationship--4641638c-5bac-5f1f-9dcc-53d92cbf35bf',
    relationship_type: 'has',
    fromId: 'software--ef7e2974-325f-50dc-a747-3d66d4bdaf90',
    toId: 'vulnerability--050cffd8-8e54-55c9-8db3-b599debb7f6f',
    confidence: undefined,
    created: new Date('2026-07-21T09:01:43.414Z'),
    objectMarking: ['marking-definition--1'],
  };

  it('should be stable across the JSON round trip a re-submission reads back', () => {
    const roundTripped = JSON.parse(JSON.stringify(input));
    expect(pendingIntentRecordKey('relation', 'has', 'user1', roundTripped)).toBe(pendingIntentRecordKey('relation', 'has', 'user1', input));
  });

  it('should not depend on the key order of the input', () => {
    const reordered = { objectMarking: input.objectMarking, toId: input.toId, fromId: input.fromId, created: input.created, relationship_type: 'has', stix_id: input.stix_id };
    expect(pendingIntentRecordKey('relation', 'has', 'user1', reordered)).toBe(pendingIntentRecordKey('relation', 'has', 'user1', input));
  });

  it('should separate distinct creations, kinds and users', () => {
    const key = pendingIntentRecordKey('relation', 'has', 'user1', input);
    expect(pendingIntentRecordKey('relation', 'has', 'user1', { ...input, toId: 'vulnerability--other' })).not.toBe(key);
    expect(pendingIntentRecordKey('operation', 'has', 'user1', input)).not.toBe(key);
    expect(pendingIntentRecordKey('relation', 'has', 'user2', input)).not.toBe(key);
  });
});

describe('retained intent envelope', () => {
  it('should keep the intake envelope the intent was written under, to rebuild its context', async () => {
    const bulk = vi.fn().mockResolvedValue({ errors: false, items: [] });
    registerPendingIntentsEsOps({ indexExists: vi.fn(), createIndex: vi.fn(), bulk, search: vi.fn() });
    const user = { id: 'applicant-1', origin: { applicant_id: 'applicant-1', playbook_id: 'playbook-1', call_retry_number: '0' } } as any;
    const context = {
      workId: 'work-1',
      draft_context: 'draft-1',
      eventId: 'event-1',
      previousStandard: 'malware--previous',
      synchronizedUpsert: true,
      real_authentication_id: 'writer-1',
    } as any;
    const intent = { id: 'i', kind: 'entity', type: 'Malware', input: { name: 'M' }, user, context, opts: {}, arrivedAt: 0, source: 'test', sizeBytes: 1, candidateIds: [], referencedIds: [] } as any;
    expect(await deferIntents([{ intent, missing: ['malware--x'] }])).toBe(true);
    const record = bulk.mock.calls[0][0][1];
    expect(JSON.parse(record.envelope_json)).toEqual({
      user_id: 'writer-1',
      applicant_id: 'applicant-1',
      work_id: 'work-1',
      draft_id: 'draft-1',
      event_id: 'event-1',
      playbook_id: 'playbook-1',
      synchronized: true,
      previous_standard: 'malware--previous',
      retry_number: 0,
    });
  });
});

describe('retained operation files', () => {
  it('should stage the files of a retained operation, read them back to re-execute it, then delete them', async () => {
    const objects = new Map<string, Buffer>();
    const storage: FileStorage = {
      upload: async (key, data) => objects.set(key, data),
      download: async (key) => objects.get(key) as Buffer,
      remove: async (key) => objects.delete(key),
    };
    registerPendingFileStaging({
      stage: (value, prefix) => stageFiles(value, prefix, storage),
      rehydrate: (value) => rehydrateFiles(value, storage),
      remove: (keys) => removeStagedFiles(keys, storage),
    });
    const bulk = vi.fn().mockResolvedValue({ errors: false, items: [] });
    registerPendingIntentsEsOps({ indexExists: vi.fn(), createIndex: vi.fn(), bulk, search: vi.fn() });
    const file = new UploadFile('report.pdf', Buffer.from('%PDF-1.4 content'), 'application/pdf');
    const operation = { query: 'mutation ReportAdd', variables: { input: { name: 'R', files: [file] } }, object_id: 'report--1' };
    expect(await deferOperation({ operation, envelope: {}, user: { id: 'user-1' } as any, missing: ['malware--x'] })).toBe(true);
    const persisted = bulk.mock.calls[bulk.mock.calls.length - 1][0][1];
    const id = pendingIntentRecordKey('operation', 'report', 'user-1', operation);
    expect(persisted.staged_files).toEqual([`intake-staging/${id}/0`]);
    expect(persisted.input_json).not.toContain('%PDF');
    expect(objects.get(`intake-staging/${id}/0`)?.toString()).toEqual('%PDF-1.4 content');
    // re-executed with its file read back, then settled: the staged file is deleted
    const executed: any[] = [];
    registerPendingOperationExecute(async (record) => {
      executed.push(await pendingRecordInput(record));
      return 'applied';
    });
    fireResubmit([{ ...persisted, id }]);
    await vi.waitFor(() => expect(objects.size).toEqual(0));
    expect(executed[0].variables.input.files[0]).toBeInstanceOf(UploadFile);
    expect(pendingIntentRecordKey('operation', 'report', 'user-1', executed[0])).toEqual(id);
  });

  it('should stage the file of a retained intent, given as the Upload scalar gives it to the domain', async () => {
    const objects = new Map<string, Buffer>();
    const storage: FileStorage = {
      upload: async (key, data) => objects.set(key, data),
      download: async (key) => objects.get(key) as Buffer,
      remove: async (key) => objects.delete(key),
    };
    registerPendingFileStaging({
      stage: (value, prefix) => stageFiles(value, prefix, storage),
      rehydrate: (value) => rehydrateFiles(value, storage),
      remove: (keys) => removeStagedFiles(keys, storage),
    });
    const bulk = vi.fn().mockResolvedValue({ errors: false, items: [] });
    registerPendingIntentsEsOps({ indexExists: vi.fn(), createIndex: vi.fn(), bulk, search: vi.fn() });
    const file = new UploadFile('report.pdf', Buffer.from('%PDF-1.4 content'), 'application/pdf');
    const user = { id: 'user-1', origin: {} } as any;
    const input = { name: 'R', files: [(toUpload(file) as any).promise] };
    const intent = { id: 'i', kind: 'entity', type: 'Report', input, user, context: { workId: 'work-1' }, opts: {}, arrivedAt: 0, source: 'test', sizeBytes: 1, candidateIds: [], referencedIds: [] } as any;
    expect(await deferIntents([{ intent, missing: ['malware--x'] }])).toBe(true);
    const persisted = bulk.mock.calls[bulk.mock.calls.length - 1][0][1];
    expect(persisted.staged_files).toHaveLength(1);
    const reread: any = await pendingRecordInput({ ...persisted, id: 'record' });
    const { filename, createReadStream } = await reread.files[0];
    const chunks: Buffer[] = [];
    for await (const chunk of createReadStream()) chunks.push(chunk);
    expect({ filename, data: Buffer.concat(chunks).toString() }).toEqual({ filename: 'report.pdf', data: '%PDF-1.4 content' });
  });
});

describe('retained records re-submission', () => {
  const setup = () => {
    const bulk = vi.fn().mockResolvedValue({ errors: false, items: [] });
    registerPendingIntentsEsOps({ indexExists: vi.fn(), createIndex: vi.fn(), bulk, search: vi.fn() });
    return bulk;
  };
  const operation = (index: number) => ({ query: 'mutation IndicatorAdd', variables: { input: { name: `I${index}` } }, object_id: `indicator--${index}` });

  it('should re-submit several records at once, each once even if asked again', async () => {
    setup();
    let running = 0;
    let maxRunning = 0;
    const runs = new Map<string, number>();
    const releases: (() => void)[] = [];
    registerPendingOperationExecute(async (record) => {
      running += 1;
      maxRunning = Math.max(maxRunning, running);
      runs.set(record.id, (runs.get(record.id) ?? 0) + 1);
      await new Promise<void>((resolve) => {
        releases.push(resolve);
      });
      running -= 1;
      return 'applied';
    });
    const user = { id: 'user-1' } as any;
    for (let index = 0; index < 4; index += 1) {
      await deferOperation({ operation: operation(index), envelope: {}, user, missing: ['identity--author'] });
    }
    // the author lands: its 4 dependents re-submitted together; a second landing while they run
    const landed = matchLandedIntents({ internal_id: 'x', standard_id: 'identity--author', entity_type: 'Organization' });
    expect(landed).toHaveLength(4);
    fireResubmit(landed);
    fireResubmit(landed);
    await vi.waitFor(() => expect(running).toEqual(4));
    expect(maxRunning).toEqual(4);
    releases.splice(0).forEach((release) => release());
    await vi.waitFor(() => expect(running).toEqual(0));
    // asked again while running: run again only if still pending (applied here: settled)
    expect([...runs.values()]).toEqual([1, 1, 1, 1]);
  });

  it('should re-submit at once a record whose reference landed before it was retained', async () => {
    setup();
    const executed: string[] = [];
    registerPendingOperationExecute(async (record) => {
      executed.push(record.id);
      return 'applied';
    });
    // the author lands first (no record waits yet), the retention of its dependent comes after
    matchLandedIntents({ internal_id: 'y', standard_id: 'identity--early', entity_type: 'Organization' });
    await deferOperation({ operation: operation(9), envelope: {}, user: { id: 'user-1' } as any, missing: ['identity--early'] });
    await vi.waitFor(() => expect(executed).toHaveLength(1));
  });
});
