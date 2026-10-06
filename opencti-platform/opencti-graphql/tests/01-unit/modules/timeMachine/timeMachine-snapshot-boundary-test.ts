import { afterEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import type { AuthContext } from '../../../../src/types/user';
import type { BasicStoreEntity } from '../../../../src/types/store';

// The stores are canned: the bounds of the reads that build a snapshot document are under test.
const fullRelationsListMock = vi.fn();
const internalFindByIdsMock = vi.fn();
const fetchElementsHistoryEventsMock = vi.fn();
const fetchRelationshipsHistoryEventsMock = vi.fn();
const findHistoryWatermarkMock = vi.fn();
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullRelationsList: (...args: unknown[]) => fullRelationsListMock(...args),
  internalFindByIds: (...args: unknown[]) => internalFindByIdsMock(...args),
}));
vi.mock('../../../../src/modules/timeMachine/timeMachine-history', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/timeMachine/timeMachine-history')>()),
  fetchElementsHistoryEvents: (...args: unknown[]) => fetchElementsHistoryEventsMock(...args),
  fetchRelationshipsHistoryEvents: (...args: unknown[]) => fetchRelationshipsHistoryEventsMock(...args),
  findHistoryWatermark: (...args: unknown[]) => findHistoryWatermarkMock(...args),
}));

import { buildCompactDocuments } from '../../../../src/manager/snapshotManager';

const SNAPSHOT_DATE = '2026-09-01T00:00:00.000Z';
const BEFORE_SNAPSHOT = '2026-08-31T00:00:00.000Z';
const AFTER_SNAPSHOT = '2026-09-02T00:00:00.000Z';

const loaded = (updatedAt: string) => ({ internal_id: 'malware-1', entity_type: 'Malware', name: 'Malware 1', updated_at: updatedAt } as unknown as BasicStoreEntity);
const entity = loaded(BEFORE_SNAPSHOT);
const relationship = { internal_id: 'relationship-at-date', entity_type: 'uses', fromId: 'malware-1', toId: 'attack-pattern-1', created_at: SNAPSHOT_DATE };
const stored = (updatedAt: string, refreshedAt: string) => [{ internal_id: 'malware-1', entity_type: 'Malware', updated_at: updatedAt, refreshed_at: refreshedAt }];

describe('Snapshot documents at the boundary of their date', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.resetAllMocks();
  });

  it('should list a relationship created at the snapshot date, the changes since being read strictly after it', async () => {
    fetchElementsHistoryEventsMock.mockResolvedValue([]);
    fetchRelationshipsHistoryEventsMock.mockResolvedValue([]);
    fullRelationsListMock.mockResolvedValue([relationship]);
    internalFindByIdsMock.mockResolvedValue(stored(BEFORE_SNAPSHOT, SNAPSHOT_DATE));
    const documents = await buildCompactDocuments({} as AuthContext, [entity], SNAPSHOT_DATE);
    const [, , , relationsOptions] = fullRelationsListMock.mock.calls[0];
    expect(relationsOptions).toMatchObject({ endDate: SNAPSHOT_DATE, dateAttribute: 'created_at', intervalInclude: true });
    expect(fetchRelationshipsHistoryEventsMock.mock.calls[0][3]).toMatchObject({ from: SNAPSHOT_DATE });
    expect(documents.get('malware-1')?.relationships).toEqual({ uses: ['relationship-at-date'] });
    expect(documents.get('malware-1')?.relationships_count).toEqual({ uses: 1 });
    // Nothing changed since the snapshot date: no history beyond it is needed
    expect(findHistoryWatermarkMock).not.toHaveBeenCalled();
  });

  it('should read the history of an entity changed since the snapshot date once it holds the knowledge reads', async () => {
    fetchElementsHistoryEventsMock.mockResolvedValue([]);
    fetchRelationshipsHistoryEventsMock.mockResolvedValue([]);
    fullRelationsListMock.mockResolvedValue([relationship]);
    // A relationship removed after the snapshot date moved refreshed_at before it disappeared from the index
    internalFindByIdsMock.mockResolvedValue(stored(BEFORE_SNAPSHOT, AFTER_SNAPSHOT));
    findHistoryWatermarkMock.mockImplementation(async () => new Date(Date.now() + 1000).toISOString());
    const documents = await buildCompactDocuments({} as AuthContext, [entity], SNAPSHOT_DATE);
    expect(findHistoryWatermarkMock).toHaveBeenCalledTimes(1);
    expect(findHistoryWatermarkMock.mock.invocationCallOrder[0]).toBeLessThan(fetchElementsHistoryEventsMock.mock.invocationCallOrder[0]);
    expect(findHistoryWatermarkMock.mock.invocationCallOrder[0]).toBeLessThan(fetchRelationshipsHistoryEventsMock.mock.invocationCallOrder[0]);
    expect(documents.get('malware-1')?.relationships_count).toEqual({ uses: 1 });
  });

  it('should read the history once it stayed quiet for longer than the indexing buffer', async () => {
    vi.useFakeTimers();
    fetchElementsHistoryEventsMock.mockResolvedValue([]);
    fetchRelationshipsHistoryEventsMock.mockResolvedValue([]);
    fullRelationsListMock.mockResolvedValue([relationship]);
    internalFindByIdsMock.mockResolvedValue(stored(AFTER_SNAPSHOT, AFTER_SNAPSHOT));
    // The newest history event is older than the reads and nothing is indexed any more
    findHistoryWatermarkMock.mockResolvedValue(AFTER_SNAPSHOT);
    const building = buildCompactDocuments({} as AuthContext, [loaded(AFTER_SNAPSHOT)], SNAPSHOT_DATE);
    await vi.advanceTimersByTimeAsync(5000);
    expect(fetchElementsHistoryEventsMock).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(6000);
    const documents = await building;
    expect(fetchElementsHistoryEventsMock).toHaveBeenCalledTimes(1);
    expect(documents.has('malware-1')).toBe(true);
  });

  it('should not take a stalled history behind the changes of the batch for a caught-up one', async () => {
    vi.useFakeTimers();
    fullRelationsListMock.mockResolvedValue([relationship]);
    internalFindByIdsMock.mockResolvedValue(stored(AFTER_SNAPSHOT, AFTER_SNAPSHOT));
    // The newest history event is older than the last change of the entity and nothing is indexed any more
    findHistoryWatermarkMock.mockResolvedValue('2026-09-01T12:00:00.000Z');
    const building = buildCompactDocuments({} as AuthContext, [loaded(AFTER_SNAPSHOT)], SNAPSHOT_DATE);
    await vi.advanceTimersByTimeAsync(11000);
    const documents = await building;
    expect(documents.size).toBe(0);
    expect(fetchElementsHistoryEventsMock).not.toHaveBeenCalled();
  });

  it('should leave to the next window an entity updated after its document was loaded', async () => {
    fetchElementsHistoryEventsMock.mockResolvedValue([]);
    fetchRelationshipsHistoryEventsMock.mockResolvedValue([]);
    fullRelationsListMock.mockResolvedValue([relationship]);
    // Unchanged since the snapshot date when the relationships are read, updated before the history is read
    internalFindByIdsMock.mockResolvedValueOnce(stored(BEFORE_SNAPSHOT, SNAPSHOT_DATE)).mockResolvedValueOnce(stored(AFTER_SNAPSHOT, AFTER_SNAPSHOT));
    const documents = await buildCompactDocuments({} as AuthContext, [entity], SNAPSHOT_DATE);
    expect(internalFindByIdsMock).toHaveBeenCalledTimes(2);
    expect(documents.has('malware-1')).toBe(false);
  });

  it('should leave the batch to the next window when the history manager stays behind the knowledge reads', async () => {
    vi.useFakeTimers();
    fullRelationsListMock.mockResolvedValue([relationship]);
    internalFindByIdsMock.mockResolvedValue(stored(AFTER_SNAPSHOT, AFTER_SNAPSHOT));
    // The history keeps indexing events older than the reads
    let indexed = 0;
    findHistoryWatermarkMock.mockImplementation(async () => {
      indexed += 1;
      return new Date(Date.parse(AFTER_SNAPSHOT) + indexed).toISOString();
    });
    const building = buildCompactDocuments({} as AuthContext, [loaded(AFTER_SNAPSHOT)], SNAPSHOT_DATE);
    await vi.advanceTimersByTimeAsync(61000);
    const documents = await building;
    expect(documents.size).toBe(0);
    expect(fetchElementsHistoryEventsMock).not.toHaveBeenCalled();
    expect(fetchRelationshipsHistoryEventsMock).not.toHaveBeenCalled();
  });
});
