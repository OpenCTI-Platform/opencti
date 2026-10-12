import { afterEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import type { AuthContext } from '../../../../src/types/user';

// The stored document and its history are canned: the pairing of the current document with its history is under test.
const internalLoadByIdMock = vi.fn();
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalLoadById: (...args: unknown[]) => internalLoadByIdMock(...args),
}));
const fetchElementHistoryEventsMock = vi.fn();
const findHistoryWatermarkMock = vi.fn();
vi.mock('../../../../src/modules/timeMachine/timeMachine-history', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/timeMachine/timeMachine-history')>()),
  fetchElementHistoryEvents: (...args: unknown[]) => fetchElementHistoryEventsMock(...args),
  findHistoryWatermark: (...args: unknown[]) => findHistoryWatermarkMock(...args),
}));
vi.mock('../../../../src/modules/timeMachine/timeMachine-store', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/timeMachine/timeMachine-store')>()),
  findSnapshotAtOrAfter: async () => undefined,
  findSnapshotAtOrBefore: async () => undefined,
}));

import { readCurrentAnchor, reconstructAt } from '../../../../src/modules/timeMachine/timeMachine-domain';
import type { BasicStoreEntity } from '../../../../src/types/store';

const context = {} as AuthContext;
const DATE = '2026-01-01T00:00:00.000Z';

const version = (name: string, updatedAt: string) => ({
  internal_id: 'intrusion-set-1',
  entity_type: 'Intrusion-Set',
  name,
  updated_at: updatedAt,
} as unknown as BasicStoreEntity);

describe('Current document anchor of the time machine', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should read the history once when the document did not change in between', async () => {
    const loaded = version('APT-TEST', '2026-02-01T00:00:00.000Z');
    fetchElementHistoryEventsMock.mockResolvedValue([]);
    internalLoadByIdMock.mockResolvedValue(version('APT-TEST', '2026-02-01T00:00:00.000Z'));
    const anchor = await readCurrentAnchor(context, loaded, DATE);
    expect(anchor.consistent).toBe(true);
    expect(anchor.document.name).toEqual(['APT-TEST']);
    expect(fetchElementHistoryEventsMock).toHaveBeenCalledTimes(1);
    expect(fetchElementHistoryEventsMock.mock.calls[0][3]).toMatchObject({ from: DATE, to: anchor.anchorDate });
  });

  it('should read the document and its history again when an update lands between the load and the history read', async () => {
    const loaded = version('APT-OLD', '2026-02-01T00:00:00.000Z');
    const updated = version('APT-NEW', '2026-02-02T00:00:00.000Z');
    fetchElementHistoryEventsMock.mockResolvedValue([]);
    internalLoadByIdMock.mockResolvedValueOnce(updated).mockResolvedValueOnce(version('APT-NEW', '2026-02-02T00:00:00.000Z'));
    const anchor = await readCurrentAnchor(context, loaded, DATE);
    expect(anchor.consistent).toBe(true);
    expect(anchor.document.name).toEqual(['APT-NEW']);
    expect(fetchElementHistoryEventsMock).toHaveBeenCalledTimes(2);
  });

  it('should keep the document when it was deleted after the load', async () => {
    fetchElementHistoryEventsMock.mockResolvedValue([]);
    internalLoadByIdMock.mockResolvedValue(undefined);
    const anchor = await readCurrentAnchor(context, version('APT-TEST', '2026-02-01T00:00:00.000Z'), DATE);
    expect(anchor.consistent).toBe(true);
    expect(anchor.document.name).toEqual(['APT-TEST']);
  });

  it('should only cover the document once the history holds its last change', async () => {
    const updatedAt = '2026-02-01T00:00:00.000Z';
    internalLoadByIdMock.mockResolvedValue(version('APT-TEST', updatedAt));
    // The event of the last update is searchable
    fetchElementHistoryEventsMock.mockResolvedValue([{ id: 'event-1', timestamp: '2026-02-01T00:00:00.020Z', event_scope: 'update', changes: [] }]);
    const indexed = await readCurrentAnchor(context, version('APT-TEST', updatedAt), DATE);
    expect(indexed.covered).toBe(true);
    expect(findHistoryWatermarkMock).not.toHaveBeenCalled();
    // The event of the last update is still waiting to be indexed: the rewind would keep the new value
    fetchElementHistoryEventsMock.mockResolvedValue([{ id: 'event-0', timestamp: '2026-01-15T00:00:00.000Z', event_scope: 'update', changes: [] }]);
    findHistoryWatermarkMock.mockResolvedValue('2026-02-01T00:00:01.000Z');
    const pending = await readCurrentAnchor(context, version('APT-TEST', updatedAt), DATE);
    expect(pending.consistent).toBe(true);
    expect(pending.covered).toBe(false);
    const { replay } = await reconstructAt(context, version('APT-TEST', updatedAt), DATE);
    expect(replay.complete).toBe(false);
    expect(replay.warnings).toContain('HISTORY_NOT_INDEXED_YET');
    // A change written without history event is covered once the history is past it by the indexing margin
    findHistoryWatermarkMock.mockResolvedValue('2026-02-01T00:02:00.000Z');
    const without = await readCurrentAnchor(context, version('APT-TEST', updatedAt), DATE);
    expect(without.covered).toBe(true);
  });

  it('should not require any history for a document unchanged since the date', async () => {
    fetchElementHistoryEventsMock.mockResolvedValue([]);
    internalLoadByIdMock.mockResolvedValue(version('APT-TEST', '2025-12-01T00:00:00.000Z'));
    const anchor = await readCurrentAnchor(context, version('APT-TEST', '2025-12-01T00:00:00.000Z'), DATE);
    expect(anchor.covered).toBe(true);
    expect(findHistoryWatermarkMock).not.toHaveBeenCalled();
  });

  it('should flag the reconstruction as incomplete when the document keeps changing', async () => {
    fetchElementHistoryEventsMock.mockResolvedValue([]);
    let updates = 0;
    internalLoadByIdMock.mockImplementation(async () => {
      updates += 1;
      return version(`APT-${updates}`, `2026-02-0${updates + 1}T00:00:00.000Z`);
    });
    const { replay, anchor } = await reconstructAt(context, version('APT-0', '2026-02-01T00:00:00.000Z'), DATE);
    expect(anchor).toBe('current');
    expect(replay.complete).toBe(false);
    expect(replay.warnings).toContain('DOCUMENT_CHANGED_DURING_READ');
    expect(fetchElementHistoryEventsMock).toHaveBeenCalledTimes(3);
  });
});
