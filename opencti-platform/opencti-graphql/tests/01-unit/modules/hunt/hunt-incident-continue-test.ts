import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesMapFromCache, getEntityFromCache } from '../../../../src/database/cache';
import { createEntity, createRelation, patchAttribute } from '../../../../src/database/middleware';
import { internalLoadById, topEntitiesList } from '../../../../src/database/middleware-loader';
import { continueHuntIncident, findOpenHuntIncident } from '../../../../src/modules/hunt/hunt-incident';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../../../../src/schema/stixDomainObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  createEntity: vi.fn(async () => ({ internal_id: 'note-1' })),
  createRelation: vi.fn(async () => ({ internal_id: 'relation-1' })),
  patchAttribute: vi.fn(async () => ({ element: {} })),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalLoadById: vi.fn(),
  topEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntityFromCache: vi.fn(),
  getEntitiesMapFromCache: vi.fn(),
}));

const hunt = {
  internal_id: 'hunt-1',
  name: 'Encoded PowerShell',
  hunt_type: 'telemetry',
} as unknown as BasicStoreEntityHunt;

const run = {
  internal_id: 'run-2',
  hunt_id: 'hunt-1',
  security_platform_id: 'platform-1',
  hits_count: 4,
  hits_new_count: 3,
  first_hit_at: '2026-10-05T08:00:00.000Z',
  last_hit_at: '2026-10-05T09:00:00.000Z',
  hit_observation_ids: ['observed-data-1'],
  [RELATION_OBJECT_MARKING]: ['marking-red'],
  [RELATION_GRANTED_TO]: ['organization-1'],
} as unknown as BasicStoreEntityHuntRun;

describe('Hunt incident continued by a later run', () => {
  beforeEach(() => {
    vi.mocked(createEntity).mockClear();
    vi.mocked(createRelation).mockClear();
    vi.mocked(patchAttribute).mockClear();
    vi.mocked(internalLoadById).mockImplementation((async (_context: AuthContext, _user: unknown, id: string) => {
      if (id === 'platform-1') {
        return { internal_id: 'platform-1', name: 'Splunk prod' };
      }
      return id === 'incident-1' ? { internal_id: 'incident-1', last_seen: '2026-10-04T09:00:00.000Z' } : null;
    }) as never);
  });

  it('should restrict the note of the later run like the run', async () => {
    await continueHuntIncident({} as AuthContext, hunt, run, { incidentId: 'incident-1', draftId: null });
    expect(createEntity).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      attribute_abstract: 'Encoded PowerShell - 3 new hits in a later run',
      objects: ['incident-1'],
      objectMarking: ['marking-red'],
      objectOrganization: ['organization-1'],
    }), ENTITY_TYPE_CONTAINER_NOTE);
  });

  it('should leave the note of a run shared with no organization unrestricted by organization', async () => {
    const unshared = { ...run, [RELATION_GRANTED_TO]: undefined } as unknown as BasicStoreEntityHuntRun;
    await continueHuntIncident({} as AuthContext, hunt, unshared, { incidentId: 'incident-1', draftId: null });
    expect(createEntity).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({ objectOrganization: [] }), ENTITY_TYPE_CONTAINER_NOTE);
  });
});

describe('Open hunt incident a later run continues', () => {
  const markings = new Map([
    ['marking-green', { internal_id: 'marking-green', definition_type: 'TLP', x_opencti_order: 2 }],
    ['marking-red', { internal_id: 'marking-red', definition_type: 'TLP', x_opencti_order: 4 }],
  ]);
  const openIncident = (access: Record<string, string[]>) => {
    vi.mocked(topEntitiesList).mockResolvedValue([{ internal_id: 'run-1', incident_id: 'incident-1' }] as never);
    vi.mocked(internalLoadById).mockImplementation((async (_context: AuthContext, _user: unknown, id: string) => {
      return id === 'incident-1' ? { internal_id: 'incident-1', standard_id: 'incident--1', ...access } : null;
    }) as never);
  };

  beforeEach(() => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: 'platform-organization' } as never);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(markings as never);
  });

  it('should continue an incident whose readers can all read the run', async () => {
    openIncident({ [RELATION_OBJECT_MARKING]: ['marking-red'], [RELATION_GRANTED_TO]: ['organization-1'] });
    expect(await findOpenHuntIncident({} as AuthContext, run)).toEqual({ incidentId: 'incident-1', draftId: null });
    // Shared with no organization, the incident is read by the platform organization only
    openIncident({ [RELATION_OBJECT_MARKING]: ['marking-red'] });
    expect(await findOpenHuntIncident({} as AuthContext, run)).toEqual({ incidentId: 'incident-1', draftId: null });
  });

  it('should give the run an incident of its own when a reader of the open one could not read the run', async () => {
    openIncident({ [RELATION_OBJECT_MARKING]: ['marking-green'], [RELATION_GRANTED_TO]: ['organization-1'] });
    expect(await findOpenHuntIncident({} as AuthContext, run)).toBeNull();
    openIncident({ [RELATION_OBJECT_MARKING]: ['marking-red'], [RELATION_GRANTED_TO]: ['organization-1', 'organization-2'] });
    expect(await findOpenHuntIncident({} as AuthContext, run)).toBeNull();
    // Without a platform organization, organizations do not restrict reading
    vi.mocked(getEntityFromCache).mockResolvedValue({} as never);
    expect(await findOpenHuntIncident({} as AuthContext, run)).toEqual({ incidentId: 'incident-1', draftId: null });
  });
});
