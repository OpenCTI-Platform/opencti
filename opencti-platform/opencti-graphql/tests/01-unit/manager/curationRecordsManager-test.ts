import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  curationRecordsManagerCronHandler,
  curationRecordsManagerStreamHandler,
  curationRecordsManagerStreamStartFrom,
  deletedEntityIds,
  reclassifiedEntityIds,
  retryQueuedRestrictionRefreshes,
} from '../../../src/manager/curationRecordsManager';
import type { AuthContext } from '../../../src/types/user';
import { redisGetManagerEventState, redisSetManagerEventState } from '../../../src/database/redis';
import { completePendingMergeRecords, expireMergeRecords, refreshMergeRecordRestrictions } from '../../../src/modules/curation/curation-merge-record';
import { refreshProposalRestrictions, retireProposalsOfDeletedSubjects } from '../../../src/modules/curation/curation-proposals';
import type { DataEvent, SseEvent } from '../../../src/types/event';

const retryQueue = new Map<string, number>();

vi.mock('../../../src/manager/managerModule', () => ({ registerManager: vi.fn() }));

vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisGetManagerEventState: vi.fn(),
  redisSetManagerEventState: vi.fn(),
  redisCurationQueueRestrictionRefresh: vi.fn(async (ids: string[]) => {
    ids.forEach((id) => retryQueue.set(id, 0));
  }),
  redisCurationGetQueuedRestrictionRefreshes: vi.fn(async () => [...retryQueue.entries()].map(([entityId, attempts]) => ({ entityId, attempts }))),
  redisCurationCompleteRestrictionRefresh: vi.fn(async (id: string) => {
    retryQueue.delete(id);
  }),
  redisCurationFailRestrictionRefresh: vi.fn(async (id: string) => {
    retryQueue.set(id, (retryQueue.get(id) ?? 0) + 1);
    return retryQueue.get(id);
  }),
}));

vi.mock('../../../src/modules/curation/curation-merge-record', () => ({
  completePendingMergeRecords: vi.fn(async () => ({ completed: 0, discarded: 0, irreversible: 0 })),
  expireMergeRecords: vi.fn(async () => 0),
  refreshMergeRecordRestrictions: vi.fn(),
}));

vi.mock('../../../src/modules/curation/curation-proposals', () => ({ refreshProposalRestrictions: vi.fn(), retireProposalsOfDeletedSubjects: vi.fn(async () => 0) }));

const OCTI_EXTENSION = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';

const update = (eventId: string, entityId: string, path: string) => ({
  id: eventId,
  event: 'update',
  data: {
    type: 'update',
    data: { name: entityId, extensions: { [OCTI_EXTENSION]: { id: entityId, type: 'Malware' } } },
    context: { patch: [{ op: 'add', path, value: ['marking-id'] }] },
  },
}) as unknown as SseEvent<DataEvent>;

describe('Curation records manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    retryQueue.clear();
    (refreshProposalRestrictions as any).mockImplementation(async () => undefined);
    (retireProposalsOfDeletedSubjects as any).mockResolvedValue(0);
  });

  it('starts the stream from the position saved by any node, without its cron handler having run', async () => {
    vi.mocked(redisGetManagerEventState).mockResolvedValueOnce('42-0');
    expect(await curationRecordsManagerStreamStartFrom()).toBe('42-0');
    expect(redisGetManagerEventState).toHaveBeenCalledWith('curation_records_manager');
    expect(completePendingMergeRecords).not.toHaveBeenCalled();
    vi.mocked(redisGetManagerEventState).mockResolvedValueOnce(undefined as never);
    expect(await curationRecordsManagerStreamStartFrom()).toBe('live');
  });

  it('only keeps the entities whose markings or organization sharing changed', () => {
    const batch = [
      update('1-0', 'malware-a', '/object_marking_refs/0'),
      update('2-0', 'malware-b', '/description'),
      update('3-0', 'malware-c', `/extensions/${OCTI_EXTENSION}/granted_refs/0`),
      update('4-0', 'malware-a', '/object_marking_refs'),
    ];
    expect(reclassifiedEntityIds(batch)).toEqual(['malware-a', 'malware-c']);
  });

  it('brings the endpoints of a reclassified relationship, whose proposals are found through them', () => {
    const relationship = update('1-0', 'attributed-to-a', '/object_marking_refs/0') as unknown as { data: { data: { extensions: Record<string, object> } } };
    relationship.data.data.extensions[OCTI_EXTENSION] = { id: 'attributed-to-a', type: 'attributed-to', source_ref: 'campaign-a', target_ref: 'intrusion-set-a' };
    const batch = [relationship as unknown as SseEvent<DataEvent>, update('2-0', 'campaign-a', '/object_marking_refs/0')];
    expect(reclassifiedEntityIds(batch)).toEqual(['attributed-to-a', 'campaign-a', 'intrusion-set-a']);
  });

  it('refreshes the merge records and the open proposals of reclassified entities, then saves the position', async () => {
    await curationRecordsManagerStreamHandler([update('5-0', 'malware-d', '/object_marking_refs/0'), update('6-0', 'malware-e', '/name')], '6-0');
    expect(refreshMergeRecordRestrictions).toHaveBeenCalledWith(expect.anything(), ['malware-d']);
    expect(refreshProposalRestrictions).toHaveBeenCalledWith(expect.anything(), ['malware-d']);
    expect(redisSetManagerEventState).toHaveBeenCalledWith('curation_records_manager', '6-0');
  });

  it('removes the open proposals about the deleted entities of a batch', async () => {
    const deletion = {
      id: '9-0',
      event: 'delete',
      data: { type: 'delete', data: { name: 'malware-g', extensions: { [OCTI_EXTENSION]: { id: 'malware-g', type: 'Malware' } } } },
    } as unknown as SseEvent<DataEvent>;
    const batch = [deletion, update('10-0', 'malware-h', '/description')];
    expect(deletedEntityIds(batch)).toEqual(['malware-g']);
    await curationRecordsManagerStreamHandler(batch, '10-0');
    expect(retireProposalsOfDeletedSubjects).toHaveBeenCalledWith(expect.anything(), ['malware-g']);
    expect(refreshProposalRestrictions).not.toHaveBeenCalled();
    expect(redisSetManagerEventState).toHaveBeenCalledWith('curation_records_manager', '10-0');
  });

  it('brings the endpoints of a deleted relationship, whose proposals are found through them', async () => {
    const deletion = {
      id: '12-0',
      event: 'delete',
      data: {
        type: 'delete',
        data: { extensions: { [OCTI_EXTENSION]: { id: 'attributed-to-b', type: 'attributed-to', source_ref: 'campaign-b', target_ref: 'intrusion-set-b' } } },
      },
    } as unknown as SseEvent<DataEvent>;
    expect(deletedEntityIds([deletion])).toEqual(['attributed-to-b', 'campaign-b', 'intrusion-set-b']);
    await curationRecordsManagerStreamHandler([deletion], '12-0');
    expect(retireProposalsOfDeletedSubjects).toHaveBeenCalledWith(expect.anything(), ['attributed-to-b', 'campaign-b', 'intrusion-set-b']);
  });

  it('queues a deleted entity whose proposals could not be removed, and removes them at a later cycle', async () => {
    const deletion = {
      id: '11-0',
      event: 'delete',
      data: { type: 'delete', data: { name: 'malware-gone', extensions: { [OCTI_EXTENSION]: { id: 'malware-gone', type: 'Malware' } } } },
    } as unknown as SseEvent<DataEvent>;
    (retireProposalsOfDeletedSubjects as any).mockRejectedValue(new Error('cannot remove'));
    for (let attempt = 1; attempt < 5; attempt += 1) {
      await expect(curationRecordsManagerStreamHandler([deletion], '11-0')).rejects.toThrow('cannot remove');
    }
    await curationRecordsManagerStreamHandler([deletion], '11-0');
    expect([...retryQueue.keys()]).toEqual(['malware-gone']);
    expect(redisSetManagerEventState).toHaveBeenCalledWith('curation_records_manager', '11-0');
    (retireProposalsOfDeletedSubjects as any).mockResolvedValue(1);
    expect(await retryQueuedRestrictionRefreshes({} as AuthContext)).toBe(1);
    expect(retireProposalsOfDeletedSubjects).toHaveBeenLastCalledWith(expect.anything(), ['malware-gone']);
    expect(retryQueue.has('malware-gone')).toBe(false);
  });

  it('processes a failing batch again, then entity by entity, and queues the entity that still fails before moving on', async () => {
    (refreshProposalRestrictions as any).mockImplementation(async (_context: unknown, ids: string[]) => {
      if (ids.includes('malware-poison')) throw new Error('cannot refresh');
    });
    const batch = [update('7-0', 'malware-f', '/object_marking_refs/0'), update('8-0', 'malware-poison', '/object_marking_refs/0')];
    for (let attempt = 1; attempt < 5; attempt += 1) {
      await expect(curationRecordsManagerStreamHandler(batch, '8-0')).rejects.toThrow('cannot refresh');
    }
    expect(redisSetManagerEventState).not.toHaveBeenCalled();
    await curationRecordsManagerStreamHandler(batch, '8-0');
    expect(refreshProposalRestrictions).toHaveBeenLastCalledWith(expect.anything(), ['malware-poison']);
    expect(refreshProposalRestrictions).toHaveBeenCalledWith(expect.anything(), ['malware-f']);
    expect([...retryQueue.keys()]).toEqual(['malware-poison']);
    expect(redisSetManagerEventState).toHaveBeenCalledWith('curation_records_manager', '8-0');
  });

  it('completes pending merge records at every cycle and closes expired ones once a day', async () => {
    await curationRecordsManagerCronHandler();
    await curationRecordsManagerCronHandler();
    expect(completePendingMergeRecords).toHaveBeenCalledTimes(2);
    expect(expireMergeRecords).toHaveBeenCalledTimes(1);
  });

  it('closes expired merge records again at the next cycle when closing them failed', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      vi.setSystemTime(Date.now() + 2 * 24 * 3600 * 1000);
      (expireMergeRecords as any).mockRejectedValueOnce(new Error('cannot expire'));
      await expect(curationRecordsManagerCronHandler()).rejects.toThrow('cannot expire');
      await curationRecordsManagerCronHandler();
      await curationRecordsManagerCronHandler();
      expect(expireMergeRecords).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('retries a queued refresh at every cycle until it succeeds', async () => {
    retryQueue.set('malware-poison', 0);
    (refreshProposalRestrictions as any).mockRejectedValueOnce(new Error('still failing'));
    await curationRecordsManagerCronHandler();
    expect(retryQueue.get('malware-poison')).toBe(1);
    await curationRecordsManagerCronHandler();
    expect(retryQueue.has('malware-poison')).toBe(false);
    expect(refreshMergeRecordRestrictions).toHaveBeenCalledWith(expect.anything(), ['malware-poison']);
  });
});
