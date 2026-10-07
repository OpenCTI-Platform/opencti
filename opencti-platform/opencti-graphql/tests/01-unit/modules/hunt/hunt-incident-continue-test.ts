import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createEntity, createRelation, patchAttribute } from '../../../../src/database/middleware';
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { continueHuntIncident } from '../../../../src/modules/hunt/hunt-incident';
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
