import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesMapFromCache, getEntityFromCache } from '../../../../src/database/cache';
import { createEntity, createRelation, patchAttribute } from '../../../../src/database/middleware';
import { internalLoadById, topEntitiesList } from '../../../../src/database/middleware-loader';
import { addDraftWorkspace, deleteDraftWorkspace } from '../../../../src/modules/draftWorkspace/draftWorkspace-domain';
import {
  continueHuntIncident,
  createHuntIncidentInWorkspace,
  createHuntIncidentWorkspace,
  findOpenHuntIncident,
  huntIncidentStixId,
} from '../../../../src/modules/hunt/hunt-incident';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_INCIDENT } from '../../../../src/schema/stixDomainObject';
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

vi.mock('../../../../src/modules/draftWorkspace/draftWorkspace-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/draftWorkspace/draftWorkspace-domain')>(),
  addDraftWorkspace: vi.fn(async () => ({ id: 'draft-new' })),
  deleteDraftWorkspace: vi.fn(async () => 'draft-new'),
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

describe('Incident of a run opened again after a failed attempt', () => {
  beforeEach(() => {
    vi.mocked(createEntity).mockClear();
    vi.mocked(addDraftWorkspace).mockClear();
    vi.mocked(deleteDraftWorkspace).mockClear();
    vi.mocked(topEntitiesList).mockReset();
    vi.mocked(internalLoadById).mockResolvedValue({ internal_id: 'platform-1', name: 'Splunk prod' } as never);
  });

  it('should record the draft it opens on the run, and never take a draft found by its name', async () => {
    const record = vi.fn(async (draftId: string) => ({ ...run, draft_id: draftId }));
    expect(await createHuntIncidentWorkspace({} as AuthContext, run, record)).toMatchObject({ draft_id: 'draft-new' });
    expect(record).toHaveBeenCalledWith('draft-new');
    expect(addDraftWorkspace).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({
      name: 'Hunt incident - run run-2',
      authorized_members: [{ id: 'organization-1', access_right: 'edit' }],
    }));
    expect(topEntitiesList).not.toHaveBeenCalled();
    expect(deleteDraftWorkspace).not.toHaveBeenCalled();
  });

  it('should delete the draft it could not record on the run, so that a later attempt opens a single one', async () => {
    const failing = vi.fn(async () => {
      throw new Error('engine unavailable');
    });
    await expect(createHuntIncidentWorkspace({} as AuthContext, run, failing)).rejects.toThrow('engine unavailable');
    expect(deleteDraftWorkspace).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'draft-new');
    // A deletion that fails too leaves the failure of the attempt as it is
    vi.mocked(deleteDraftWorkspace).mockRejectedValueOnce(new Error('draft locked'));
    await expect(createHuntIncidentWorkspace({} as AuthContext, run, failing)).rejects.toThrow('engine unavailable');
  });

  it('should give every attempt at the incident of a run the same STIX id, so a later one updates it', async () => {
    await createHuntIncidentInWorkspace({} as AuthContext, hunt, run, null, 'draft-1');
    await createHuntIncidentInWorkspace({} as AuthContext, hunt, { ...run, hits_count: 6 } as BasicStoreEntityHuntRun, null, 'draft-1');
    const stixIds = vi.mocked(createEntity).mock.calls.filter((call) => call[3] === ENTITY_TYPE_INCIDENT).map((call) => (call[2] as { stix_id: string }).stix_id);
    expect(stixIds).toEqual([huntIncidentStixId(run), huntIncidentStixId(run)]);
    expect(huntIncidentStixId(run)).toMatch(/^incident--[0-9a-f-]{36}$/);
    expect(huntIncidentStixId({ internal_id: 'run-3' })).not.toEqual(huntIncidentStixId(run));
  });
});
