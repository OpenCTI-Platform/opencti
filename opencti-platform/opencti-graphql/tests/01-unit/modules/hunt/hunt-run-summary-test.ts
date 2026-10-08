import { beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesMapFromCache, getEntityFromCache } from '../../../../src/database/cache';
import { createEntity } from '../../../../src/database/middleware';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { resolveHuntConnectorTargets } from '../../../../src/modules/hunt/hunt-dispatch';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { createHuntRuns, recordHuntRunSummary } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntityFromCache: vi.fn(),
  getEntitiesMapFromCache: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  createEntity: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  resolveHuntConnectorTargets: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-stats', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-stats')>(),
  updateHuntRunInformation: vi.fn(),
}));

const markings = new Map([
  ['marking-green', { internal_id: 'marking-green', definition_type: 'TLP', x_opencti_order: 2 }],
  ['marking-amber', { internal_id: 'marking-amber', definition_type: 'TLP', x_opencti_order: 3 }],
  ['marking-secret', { internal_id: 'marking-secret', definition_type: 'PAP', x_opencti_order: 4 }],
]);

const hunt = {
  internal_id: 'hunt-1',
  name: 'Encoded PowerShell',
  hunt_type: 'telemetry',
  hunt_status: 'active',
  native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"' }],
  escalation_threshold: 10,
  time_window_hours: 24,
  [RELATION_OBJECT_MARKING]: ['marking-amber'],
  [RELATION_GRANTED_TO]: ['organization-1'],
} as unknown as BasicStoreEntityHunt;

const completed = { last_run_at: '2026-10-07T10:00:00.000Z', last_run_status: 'completed', last_hits_count: 3, last_new_hits_count: 1 };
const access = (objectMarking: string[], organizations: string[]) => ({ [RELATION_OBJECT_MARKING]: objectMarking, [RELATION_GRANTED_TO]: organizations });

describe('Run summary of a hunt', () => {
  beforeEach(() => {
    vi.mocked(updateHuntRunInformation).mockReset();
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: 'platform-organization' } as never);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(markings as never);
  });

  it('should follow a run every reader of the hunt can read', async () => {
    expect(await recordHuntRunSummary(testContext, hunt, [access(['marking-amber'], ['organization-1'])], completed)).toBe(true);
    // A marking of the platform no higher than one of the hunt of the same type hides nothing from its readers
    expect(await recordHuntRunSummary(testContext, hunt, [access(['marking-amber', 'marking-green'], ['organization-1'])], completed)).toBe(true);
    expect(updateHuntRunInformation).toHaveBeenCalledTimes(2);
    expect(updateHuntRunInformation).toHaveBeenCalledWith(testContext, 'hunt-1', completed, { onlyIfNewer: true });
  });

  it('should never follow a run its security platform restricts further than its hunt', async () => {
    // A marking of a type the hunt does not carry
    expect(await recordHuntRunSummary(testContext, hunt, [access(['marking-amber', 'marking-secret'], ['organization-1'])], completed)).toBe(false);
    // Readable by the platform organization only, while the hunt is shared with an organization
    expect(await recordHuntRunSummary(testContext, hunt, [access(['marking-amber'], [])], completed)).toBe(false);
    expect(updateHuntRunInformation).not.toHaveBeenCalled();
  });

  it('should ignore organizations without a platform organization', async () => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: undefined } as never);
    expect(await recordHuntRunSummary(testContext, hunt, [access(['marking-amber'], [])], completed)).toBe(true);
  });

  it('should record the queued runs of a hunt in its summary only when one of them is readable by every reader of the hunt', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([] as never);
    vi.mocked(createEntity).mockImplementation(async (_context, _user, input) => ({ ...input, internal_id: `run-${(input as { connector_id: string }).connector_id}` }) as never);
    const platform = (id: string, objectMarking: string[]) => ({
      connector: { internal_id: `connector-${id}`, name: `Splunk Hunt ${id}` },
      securityPlatform: { internal_id: `platform-${id}`, name: `Splunk ${id}`, [RELATION_OBJECT_MARKING]: objectMarking, [RELATION_GRANTED_TO]: ['organization-1'] },
    });
    vi.mocked(resolveHuntConnectorTargets).mockResolvedValue([platform('restricted', ['marking-secret'])] as never);
    const restricted = await createHuntRuns(testContext, hunt, { trigger: 'manual', requester: ADMIN_USER, dispatch: false });
    expect(restricted).toHaveLength(1);
    expect(updateHuntRunInformation).not.toHaveBeenCalled();
    vi.mocked(resolveHuntConnectorTargets).mockResolvedValue([platform('restricted', ['marking-secret']), platform('open', [])] as never);
    await createHuntRuns(testContext, hunt, { trigger: 'manual', requester: ADMIN_USER, dispatch: false });
    expect(updateHuntRunInformation).toHaveBeenCalledTimes(1);
    expect(vi.mocked(updateHuntRunInformation).mock.calls[0][2]).toMatchObject({ last_run_status: 'queued' });
  });
});
