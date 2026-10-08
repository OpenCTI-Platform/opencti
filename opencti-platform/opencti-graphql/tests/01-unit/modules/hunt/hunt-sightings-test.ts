import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createRelation, patchAttribute } from '../../../../src/database/middleware';
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { huntSightingStandardId, upsertHuntSightings } from '../../../../src/modules/hunt/hunt-sightings';
import { type BasicStoreEntityHunt, RELATION_HUNT_TECHNIQUES } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  createRelation: vi.fn(async () => ({ standard_id: 'sighting--created' })),
  patchAttribute: vi.fn(async () => ({ element: { standard_id: 'sighting--updated' } })),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalLoadById: vi.fn(),
}));

const markingDefinitions = [
  { internal_id: 'marking-green', id: 'marking-green', definition_type: 'TLP', x_opencti_order: 2 },
  { internal_id: 'marking-red', id: 'marking-red', definition_type: 'TLP', x_opencti_order: 4 },
  { internal_id: 'marking-statement', id: 'marking-statement', definition_type: 'statement', x_opencti_order: 0 },
];

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesMapFromCache: vi.fn(async () => new Map(markingDefinitions.map((marking) => [marking.internal_id, marking]))),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(async () => []),
}));

vi.mock('../../../../src/modules/hunt/hunt-lock', () => ({
  withHuntLock: async <T>(_key: string, action: () => Promise<T>) => action(),
}));

const hunt = {
  internal_id: 'hunt-1',
  name: 'Encoded PowerShell',
  hunt_type: 'telemetry',
  [RELATION_HUNT_TECHNIQUES]: ['technique-1'],
} as unknown as BasicStoreEntityHunt;

const run = {
  internal_id: 'run-2',
  hunt_run_status: 'completed',
  security_platform_id: 'platform-1',
  hits_count: 3,
  hits_identified: false,
  first_hit_at: '2026-10-05T08:00:00.000Z',
  last_hit_at: '2026-10-05T09:00:00.000Z',
  [RELATION_OBJECT_MARKING]: ['marking-red'],
  [RELATION_GRANTED_TO]: ['organization-1'],
} as unknown as BasicStoreEntityHuntRun;

const platform = { internal_id: 'platform-1', name: 'Splunk prod' };

const loadWith = (sighting: Record<string, unknown> | null) => {
  vi.mocked(internalLoadById).mockImplementation((async (_context: AuthContext, _user: unknown, id: string) => {
    if (id === platform.internal_id) {
      return platform;
    }
    return id === huntSightingStandardId(hunt.internal_id, 'technique-1', platform.internal_id) ? sighting : null;
  }) as never);
};

describe('Hunt sightings access', () => {
  beforeEach(() => {
    vi.mocked(createRelation).mockClear();
    vi.mocked(patchAttribute).mockClear();
    vi.mocked(findByIds).mockResolvedValue([{ internal_id: 'technique-1', entity_type: 'Attack-Pattern' }] as never);
  });

  it('should restrict a new sighting like its run', async () => {
    loadWith(null);
    const outcome = await upsertHuntSightings({} as AuthContext, hunt, run);
    expect(outcome.created).toEqual(1);
    expect(createRelation).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      objectMarking: ['marking-red'],
      objectOrganization: ['organization-1'],
    }));
  });

  it('should restrict an updated sighting like every run that fed it', async () => {
    loadWith({
      internal_id: 'sighting-1',
      attribute_count: 2,
      first_seen: '2026-10-04T08:00:00.000Z',
      last_seen: '2026-10-04T09:00:00.000Z',
      x_opencti_hunt_run_id: 'run-1',
      [RELATION_OBJECT_MARKING]: ['marking-green', 'marking-statement'],
      [RELATION_GRANTED_TO]: ['organization-1', 'organization-2'],
    });
    const outcome = await upsertHuntSightings({} as AuthContext, hunt, run);
    expect(outcome.updated).toEqual(1);
    expect(patchAttribute).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'sighting-1', expect.anything(), expect.objectContaining({
      attribute_count: 5,
      objectMarking: ['marking-red', 'marking-statement'],
      objectOrganization: ['organization-1'],
    }), expect.anything());
  });

  it('should never widen the access of a sighting when a later run is less restricted', async () => {
    loadWith({
      internal_id: 'sighting-1',
      attribute_count: 2,
      first_seen: '2026-10-04T08:00:00.000Z',
      last_seen: '2026-10-04T09:00:00.000Z',
      x_opencti_hunt_run_id: 'run-1',
      [RELATION_OBJECT_MARKING]: ['marking-red'],
      [RELATION_GRANTED_TO]: ['organization-1'],
    });
    const lessRestricted = { ...run, [RELATION_OBJECT_MARKING]: ['marking-green'], [RELATION_GRANTED_TO]: ['organization-1', 'organization-2'] } as BasicStoreEntityHuntRun;
    await upsertHuntSightings({} as AuthContext, hunt, lessRestricted);
    expect(patchAttribute).toHaveBeenCalledTimes(1);
    const patch = vi.mocked(patchAttribute).mock.calls[0][4];
    expect(patch).toEqual(expect.objectContaining({ attribute_count: 5 }));
    expect(patch).not.toHaveProperty('objectMarking');
    expect(patch).not.toHaveProperty('objectOrganization');
  });

  it('should keep a sighting shared with no organization when a later run is shared with one', async () => {
    loadWith({
      internal_id: 'sighting-1',
      attribute_count: 2,
      first_seen: '2026-10-04T08:00:00.000Z',
      last_seen: '2026-10-04T09:00:00.000Z',
      x_opencti_hunt_run_id: 'run-1',
      [RELATION_OBJECT_MARKING]: ['marking-red'],
      [RELATION_GRANTED_TO]: [],
    });
    await upsertHuntSightings({} as AuthContext, hunt, run);
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).not.toHaveProperty('objectOrganization');
  });

  it('should leave a sighting to the platform organization only when its runs are shared with no common organization', async () => {
    loadWith({
      internal_id: 'sighting-1',
      attribute_count: 2,
      first_seen: '2026-10-04T08:00:00.000Z',
      last_seen: '2026-10-04T09:00:00.000Z',
      x_opencti_hunt_run_id: 'run-1',
      [RELATION_OBJECT_MARKING]: ['marking-red'],
      [RELATION_GRANTED_TO]: ['organization-2'],
    });
    await upsertHuntSightings({} as AuthContext, hunt, run);
    expect(vi.mocked(patchAttribute).mock.calls[0][4]).toEqual(expect.objectContaining({ objectOrganization: [] }));
  });

  it('should update the access of a sighting whose counters did not change, and leave unchanged refs out of the patch', async () => {
    loadWith({
      internal_id: 'sighting-1',
      attribute_count: 3,
      first_seen: '2026-10-05T08:00:00.000Z',
      last_seen: '2026-10-05T09:00:00.000Z',
      x_opencti_hunt_run_id: 'run-2',
      [RELATION_OBJECT_MARKING]: ['marking-green'],
      [RELATION_GRANTED_TO]: ['organization-1'],
    });
    await upsertHuntSightings({} as AuthContext, hunt, run);
    expect(patchAttribute).toHaveBeenCalledTimes(1);
    const patch = vi.mocked(patchAttribute).mock.calls[0][4];
    expect(patch).toEqual(expect.objectContaining({ objectMarking: ['marking-red'] }));
    expect(patch).not.toHaveProperty('objectOrganization');
  });

  it('should not write a sighting whose counters and access did not change', async () => {
    loadWith({
      internal_id: 'sighting-1',
      standard_id: 'sighting--kept',
      attribute_count: 3,
      first_seen: '2026-10-05T08:00:00.000Z',
      last_seen: '2026-10-05T09:00:00.000Z',
      x_opencti_hunt_run_id: 'run-2',
      [RELATION_OBJECT_MARKING]: ['marking-red'],
      [RELATION_GRANTED_TO]: ['organization-1'],
    });
    const outcome = await upsertHuntSightings({} as AuthContext, hunt, run);
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(outcome.ids).toEqual(['sighting--kept']);
  });
});
