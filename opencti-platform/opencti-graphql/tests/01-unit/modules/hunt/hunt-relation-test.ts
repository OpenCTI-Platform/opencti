import { beforeEach, describe, expect, it, vi } from 'vitest';
import { stixDomainObjectAddRelation, stixDomainObjectDeleteRelation } from '../../../../src/domain/stixDomainObject';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { huntAddRelation, huntDeleteRelation } from '../../../../src/modules/hunt/hunt-domain';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { RELATION_HUNT_SOURCES, RELATION_HUNT_TARGETS } from '../../../../src/modules/hunt/hunt-types';
import { RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/domain/stixDomainObject', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/domain/stixDomainObject')>(),
  stixDomainObjectAddRelation: vi.fn(async () => ({ id: 'relation-added' })),
  stixDomainObjectDeleteRelation: vi.fn(async () => ({ id: 'hunt-1' })),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

const indicatorHunt = (status: string, sources: string[]) => ({
  internal_id: 'hunt-1',
  entity_type: 'Hunt',
  hunt_type: 'indicators',
  hunt_status: status,
  [RELATION_HUNT_SOURCES]: sources,
});

describe('Hunt relations changed through the API', () => {
  beforeEach(() => {
    vi.mocked(stixDomainObjectAddRelation).mockClear();
    vi.mocked(stixDomainObjectDeleteRelation).mockClear();
    vi.mocked(findByIds).mockImplementation((async (_context: unknown, _user: unknown, ids: string[]) => ids.map((id) => ({ internal_id: `internal-${id}` }))) as never);
  });

  it('should refuse to remove the last source of an active indicator hunt', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(indicatorHunt('active', ['internal-indicator--1']) as never);
    await expect(huntDeleteRelation(testContext, ADMIN_USER, 'hunt-1', 'indicator--1', RELATION_HUNT_SOURCES)).rejects.toThrow(/An active hunt cannot run/);
    expect(stixDomainObjectDeleteRelation).not.toHaveBeenCalled();
  });

  it('should remove a source the hunt can do without, and return what the relation removal returns', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(indicatorHunt('active', ['internal-indicator--1', 'internal-indicator--2']) as never);
    const removed = await huntDeleteRelation(testContext, ADMIN_USER, 'hunt-1', 'indicator--1', RELATION_HUNT_SOURCES);
    expect(removed).toEqual({ id: 'hunt-1' });
    expect(stixDomainObjectDeleteRelation).toHaveBeenCalledWith(testContext, ADMIN_USER, 'hunt-1', 'indicator--1', RELATION_HUNT_SOURCES);
    vi.mocked(storeLoadById).mockResolvedValue(indicatorHunt('draft', ['internal-indicator--1']) as never);
    await huntDeleteRelation(testContext, ADMIN_USER, 'hunt-1', 'indicator--1', RELATION_HUNT_SOURCES);
    expect(stixDomainObjectDeleteRelation).toHaveBeenCalledTimes(2);
  });

  it('should validate an added reference and return the relation it adds', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(indicatorHunt('active', ['internal-indicator--1']) as never);
    const input = { toId: 'intrusion-set--1', relationship_type: RELATION_HUNT_TARGETS };
    expect(await huntAddRelation(testContext, ADMIN_USER, 'hunt-1', input)).toEqual({ id: 'relation-added' });
    expect(stixDomainObjectAddRelation).toHaveBeenCalledWith(testContext, ADMIN_USER, 'hunt-1', input);
    expect(storeLoadById).toHaveBeenCalled();
  });

  it('should leave the other references of a hunt to the relation helpers', async () => {
    vi.mocked(storeLoadById).mockClear();
    await huntDeleteRelation(testContext, ADMIN_USER, 'hunt-1', 'marking-definition--1', RELATION_OBJECT_MARKING);
    expect(storeLoadById).not.toHaveBeenCalled();
    expect(stixDomainObjectDeleteRelation).toHaveBeenCalledWith(testContext, ADMIN_USER, 'hunt-1', 'marking-definition--1', RELATION_OBJECT_MARKING);
  });
});
