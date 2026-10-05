import { afterEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import type { AuthContext } from '../../../../src/types/user';
import type { BasicStoreEntity } from '../../../../src/types/store';

// The stores are canned: the bounds of the reads that build a snapshot document are under test.
const fullRelationsListMock = vi.fn();
const fetchElementsHistoryEventsMock = vi.fn();
const fetchRelationshipsHistoryEventsMock = vi.fn();
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullRelationsList: (...args: unknown[]) => fullRelationsListMock(...args),
}));
vi.mock('../../../../src/modules/timeMachine/timeMachine-history', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/timeMachine/timeMachine-history')>()),
  fetchElementsHistoryEvents: (...args: unknown[]) => fetchElementsHistoryEventsMock(...args),
  fetchRelationshipsHistoryEvents: (...args: unknown[]) => fetchRelationshipsHistoryEventsMock(...args),
}));

import { buildCompactDocuments } from '../../../../src/manager/snapshotManager';

const SNAPSHOT_DATE = '2026-09-01T00:00:00.000Z';

describe('Snapshot documents at the boundary of their date', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should list a relationship created at the snapshot date, the changes since being read strictly after it', async () => {
    fetchElementsHistoryEventsMock.mockResolvedValue([]);
    fetchRelationshipsHistoryEventsMock.mockResolvedValue([]);
    fullRelationsListMock.mockResolvedValue([
      { internal_id: 'relationship-at-date', entity_type: 'uses', fromId: 'malware-1', toId: 'attack-pattern-1', created_at: SNAPSHOT_DATE },
    ]);
    const entity = { internal_id: 'malware-1', entity_type: 'Malware', name: 'Malware 1' } as unknown as BasicStoreEntity;
    const documents = await buildCompactDocuments({} as AuthContext, [entity], SNAPSHOT_DATE);
    const [, , , relationsOptions] = fullRelationsListMock.mock.calls[0];
    expect(relationsOptions).toMatchObject({ endDate: SNAPSHOT_DATE, dateAttribute: 'created_at', intervalInclude: true });
    expect(fetchRelationshipsHistoryEventsMock.mock.calls[0][3]).toMatchObject({ from: SNAPSHOT_DATE });
    expect(documents.get('malware-1')?.relationships).toEqual({ uses: ['relationship-at-date'] });
    expect(documents.get('malware-1')?.relationships_count).toEqual({ uses: 1 });
  });
});
