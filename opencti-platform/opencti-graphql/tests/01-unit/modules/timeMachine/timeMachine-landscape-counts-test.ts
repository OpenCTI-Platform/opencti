import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { TimeMachineHistoryEvent } from '../../../../src/modules/timeMachine/timeMachine-types';

// The scope, the history and the access to elements are canned: the counting rules of the computation are under test.
const topEntitiesListMock = vi.fn();
const fullRelationsListMock = vi.fn();
const internalFindByIdsMappedMock = vi.fn();
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  topEntitiesList: (...args: unknown[]) => topEntitiesListMock(...args),
  fullRelationsList: (...args: unknown[]) => fullRelationsListMock(...args),
  internalFindByIdsMapped: (...args: unknown[]) => internalFindByIdsMappedMock(...args),
}));
const fetchRelationshipsHistoryEventsMock = vi.fn();
const fetchElementsHistoryEventsMock = vi.fn();
vi.mock('../../../../src/modules/timeMachine/timeMachine-history', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/timeMachine/timeMachine-history')>()),
  fetchRelationshipsHistoryEvents: (...args: unknown[]) => fetchRelationshipsHistoryEventsMock(...args),
  fetchElementsHistoryEvents: (...args: unknown[]) => fetchElementsHistoryEventsMock(...args),
}));

import { computeLandscapeDiff, resolveCountedElements } from '../../../../src/modules/timeMachine/landscapeDiff-domain';
import { SYSTEM_USER } from '../../../../src/utils/access';

const FROM = '2026-01-01T00:00:00.000Z';
const TO = '2026-02-01T00:00:00.000Z';
const context = {} as AuthContext;
const user = { id: 'analyst-1' } as AuthUser;

const entity = (id: string) => ({ internal_id: id, standard_id: `intrusion-set--${id}`, entity_type: 'Intrusion-Set', name: id, created_at: '2025-06-01T00:00:00.000Z' });

const relationshipEvent = (
  relationshipId: string,
  fromId: string,
  toId: string,
  scope: 'delete' | 'update',
  changes: Array<{ key: string; added: string[]; removed: string[] }> = [],
): TimeMachineHistoryEvent => ({
  id: `event-${relationshipId}`,
  timestamp: '2026-01-15T00:00:00.000Z',
  event_scope: scope,
  context_id: relationshipId,
  context_entity_type: 'uses',
  context_entity_name: relationshipId,
  from_id: fromId,
  to_id: toId,
  changes: changes.map(({ key, added, removed }) => ({
    field: `uses--${key}`,
    changes_added: added.map((raw) => ({ raw })),
    changes_removed: removed.map((raw) => ({ raw })),
  })),
} as unknown as TimeMachineHistoryEvent);

// Elements the user can access, and the ones that exist but that only the system can access
const mockAccess = (accessible: string[], restricted: string[]) => {
  internalFindByIdsMappedMock.mockImplementation(async (_context: AuthContext, requester: AuthUser, ids: string[]) => {
    const known = requester === SYSTEM_USER ? [...accessible, ...restricted] : accessible;
    return Object.fromEntries(ids.filter((id) => known.includes(id)).map((id) => [id, { internal_id: id, entity_type: 'Malware' }]));
  });
};

describe('Landscape diff counts', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should separate accessible, restricted and deleted elements', async () => {
    mockAccess(['accessible'], ['restricted']);
    const { accessible, restricted } = await resolveCountedElements(context, user, ['accessible', 'restricted', 'deleted', 'accessible']);
    expect([...accessible]).toEqual(['accessible']);
    expect([...restricted]).toEqual(['restricted']);
    expect(await resolveCountedElements(context, user, [])).toEqual({ accessible: new Set(), restricted: new Set() });
  });

  it('should count relationship changes with the rights of the user and keep what shaped them', async () => {
    topEntitiesListMock.mockResolvedValue([entity('scoped-a'), entity('scoped-b')]);
    fullRelationsListMock.mockResolvedValue([]);
    fetchElementsHistoryEventsMock.mockResolvedValue([]);
    fetchRelationshipsHistoryEventsMock.mockResolvedValue([
      // Confidence of an accessible relationship changed
      relationshipEvent('rel-confidence', 'scoped-a', 'malware-x', 'update', [{ key: 'confidence', added: ['80'], removed: ['50'] }]),
      // Removed, towards an accessible entity, a restricted one and a deleted one
      relationshipEvent('rel-removed-accessible', 'scoped-a', 'malware-y', 'delete'),
      relationshipEvent('rel-removed-restricted', 'scoped-b', 'malware-z', 'delete'),
      relationshipEvent('rel-removed-deleted', 'scoped-b', 'malware-w', 'delete'),
      // Revoked, but the relationship itself is restricted
      relationshipEvent('rel-revoked-restricted', 'scoped-a', 'scoped-b', 'update', [{ key: 'revoked', added: ['true'], removed: ['false'] }]),
    ]);
    mockAccess(['scoped-a', 'scoped-b', 'rel-confidence', 'malware-y'], ['malware-z', 'rel-revoked-restricted']);
    const result = await computeLandscapeDiff(context, user, { filters: null, entityTypes: ['Intrusion-Set'] }, FROM, TO, 'entity_type');
    expect(result.aggregates.confidence_changes).toEqual(1);
    expect(result.aggregates.removed_relationships).toEqual(2);
    expect(result.aggregates.revocations).toEqual(0);
    expect(result.aggregates.entities_changed).toEqual(2);
    const byId = new Map(result.entities.map((summary) => [summary.entity_id, summary]));
    expect(byId.get('scoped-a')).toMatchObject({ relationships_confidence_changed: 1, relationships_removed: 1, relationships_revoked: 0, change_score: 3 });
    expect(byId.get('scoped-b')).toMatchObject({ relationships_confidence_changed: 0, relationships_removed: 1, relationships_revoked: 0, change_score: 2 });
    // A stored result is revalidated against the accessible elements behind its counts
    expect(result.contributors).toEqual(expect.arrayContaining(['scoped-a', 'scoped-b', 'rel-confidence', 'malware-y']));
    expect(result.contributors).not.toContain('malware-z');
    expect(result.contributors).not.toContain('malware-w');
    expect(result.contributors).not.toContain('rel-revoked-restricted');
  });
});
