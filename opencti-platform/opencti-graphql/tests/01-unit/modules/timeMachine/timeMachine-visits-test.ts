import { afterEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

// The entity, the stored visits and the counters are canned: whether a visit is recorded is under test.
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalLoadById: async () => ({ internal_id: 'element-a', entity_type: 'Intrusion-Set' }),
}));
const loadUserVisitsMock = vi.fn();
const indexVisitMock = vi.fn();
vi.mock('../../../../src/modules/timeMachine/timeMachine-store', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/timeMachine/timeMachine-store')>()),
  loadUserVisits: (...args: unknown[]) => loadUserVisitsMock(...args),
  indexVisit: (...args: unknown[]) => indexVisitMock(...args),
}));
vi.mock('../../../../src/modules/timeMachine/timeMachine-counters', () => ({
  countSinceReferenceDates: async () => new Map([['element-a', { relationships: 2, updates: 1, containerObjects: 0 }]]),
}));

import { recordEntityVisit } from '../../../../src/modules/timeMachine/timeMachine-domain';

const user = { id: 'analyst-1' } as AuthUser;
const previousVisit = {
  entity_id: 'element-a',
  last_seen_at: '2026-01-01T00:00:00.000Z',
  previous_seen_at: '2025-12-01T00:00:00.000Z',
  created_at: '2025-12-01T00:00:00.000Z',
};

describe('Last visit markers', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should not record a visit while the user works in a draft', async () => {
    loadUserVisitsMock.mockResolvedValue(new Map([['element-a', previousVisit]]));
    const result = await recordEntityVisit({ draft_context: 'draft-1' } as AuthContext, user, 'element-a');
    expect(indexVisitMock).not.toHaveBeenCalled();
    // The counters still compare with the visit recorded on the main knowledge
    expect(result).toMatchObject({ entity_id: 'element-a', first_visit: false, reference_date: previousVisit.previous_seen_at, new_relationships: 2 });
  });

  it('should record a visit on the main knowledge', async () => {
    loadUserVisitsMock.mockResolvedValue(new Map([['element-a', previousVisit]]));
    await recordEntityVisit({} as AuthContext, user, 'element-a');
    expect(indexVisitMock).toHaveBeenCalledTimes(1);
  });
});
