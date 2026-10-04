import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { TimeMachineHistoryEvent } from '../../../../src/modules/timeMachine/timeMachine-types';

// The relationships created in the period, the history and the access to targets are canned: the target of each change is under test.
const internalFindByIdsMappedMock = vi.fn();
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  topRelationsList: async () => [],
  internalFindByIdsMapped: (...args: unknown[]) => internalFindByIdsMappedMock(...args),
}));
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elCount: async () => 0,
}));
const fetchRelationshipsHistoryEventsMock = vi.fn();
vi.mock('../../../../src/modules/timeMachine/timeMachine-history', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/timeMachine/timeMachine-history')>()),
  fetchRelationshipsHistoryEvents: (...args: unknown[]) => fetchRelationshipsHistoryEventsMock(...args),
}));

import { computeRelationshipChanges } from '../../../../src/modules/timeMachine/timeMachine-domain';
import { SYSTEM_USER } from '../../../../src/utils/access';

const context = {} as AuthContext;
const user = { id: 'analyst-1' } as AuthUser;

const relationshipEvent = (relationshipId: string, toId: string, scope: 'delete' | 'update', changes: TimeMachineHistoryEvent['changes'] = []) => ({
  id: `event-${relationshipId}`,
  timestamp: '2026-01-15T00:00:00.000Z',
  event_scope: scope,
  context_id: relationshipId,
  context_entity_type: 'uses',
  context_entity_name: `APT-TEST uses ${toId}`,
  from_id: 'element-a',
  to_id: toId,
  changes,
} as unknown as TimeMachineHistoryEvent);

describe('Relationship changes of an entity', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should name each target with the rights of the user, never with the relationship label', async () => {
    fetchRelationshipsHistoryEventsMock.mockResolvedValue([
      relationshipEvent('rel-deleted-target', 'malware-deleted', 'delete'),
      relationshipEvent('rel-restricted-target', 'malware-restricted', 'delete'),
      relationshipEvent('rel-accessible-target', 'malware-accessible', 'update', [
        { field: 'uses--confidence', changes_added: [{ raw: '80' }], changes_removed: [{ raw: '50' }] },
      ] as TimeMachineHistoryEvent['changes']),
    ]);
    internalFindByIdsMappedMock.mockImplementation(async (_context: AuthContext, requester: AuthUser, ids: string[]) => {
      const known: Record<string, unknown> = requester === SYSTEM_USER
        ? { 'malware-restricted': { internal_id: 'malware-restricted', entity_type: 'Malware', name: 'Hidden' } }
        : { 'malware-accessible': { internal_id: 'malware-accessible', entity_type: 'Malware', name: 'LynxLoader' } };
      return Object.fromEntries(ids.filter((id) => known[id]).map((id) => [id, known[id]]));
    });
    const { allChanges } = await computeRelationshipChanges(context, user, 'element-a', '2026-01-01T00:00:00.000Z', '2026-02-01T00:00:00.000Z', new Map());
    const byId = new Map(allChanges.map((change) => [change.relationship_id, change]));
    expect(byId.get('rel-deleted-target')).toMatchObject({ action: 'removed', target_id: 'malware-deleted', target_name: 'Deleted', target_deleted: true, target_restricted: false });
    expect(byId.get('rel-restricted-target')).toMatchObject({ action: 'removed', target_id: null, target_name: 'Restricted', target_restricted: true });
    expect(byId.get('rel-accessible-target')).toMatchObject({ action: 'confidence_changed', target_name: 'LynxLoader', target_type: 'Malware', confidence_before: 50, confidence_after: 80 });
  });
});
