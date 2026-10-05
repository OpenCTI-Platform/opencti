import { beforeEach, describe, expect, it, vi } from 'vitest';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import huntResolvers from '../../../../src/modules/hunt/hunt-resolvers';
import { HUNT_DEFAULT_EXPECTED_OBSERVABLES } from '../../../../src/modules/hunt/hunt-utils';
import { findHuntRunResultIds, findHuntRunResultsSummary, summarizeHuntRunResults } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import type { AuthUser } from '../../../../src/types/user';
import type { BasicStoreObject } from '../../../../src/types/store';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalFindByIds: vi.fn(),
}));

const result = (internalId: string, standardId: string, entityType: string) => ({
  internal_id: internalId,
  standard_id: standardId,
  entity_type: entityType,
}) as BasicStoreObject;

// What the hunt connector sent (STIX ids) and the observed data of the hits (internal ids) of one run
const readable = [
  result('sighting-1', 'sighting--1', 'stix-sighting-relationship'),
  result('sighting-2', 'sighting--2', 'stix-sighting-relationship'),
  result('observed-1', 'observed-data--1', 'Observed-Data'),
  result('observed-hit-1', 'observed-data--hit-1', 'Observed-Data'),
  result('ipv4-1', 'ipv4-addr--1', 'IPv4-Addr'),
  result('file-1', 'file--1', 'StixFile'),
  result('infrastructure-1', 'infrastructure--1', 'Infrastructure'),
];

const run = {
  internal_id: 'run-summary',
  updated_at: '2026-10-05T19:00:00.000Z',
  // A result the reader cannot read is recorded too, and the observed data of a hit is recorded by its internal id
  result_ids: [...readable.filter((element) => element.internal_id !== 'observed-hit-1').map((element) => element.standard_id), 'observed-hit-1', 'indicator--hidden'],
} as unknown as BasicStoreEntityHuntRun;

describe('Hunt run results summary', () => {
  beforeEach(() => {
    vi.mocked(internalFindByIds).mockReset();
    vi.mocked(internalFindByIds).mockResolvedValue(readable as never);
  });

  it('should count the results a reader can read by kind, with the access resolved once for the results', async () => {
    const user = { id: 'user-summary', internal_id: 'user-summary' } as AuthUser;
    const summary = await findHuntRunResultsSummary(testContext, user, run);
    expect(summary).toEqual({ sightings: 2, observed_data: 2, observables: 2, others: 1 });
    expect(await findHuntRunResultIds(testContext, user, run)).not.toContain('indicator--hidden');
    expect(internalFindByIds).toHaveBeenCalledTimes(1);
  });

  it('should count an object once, whatever the number of ids it is recorded with', () => {
    expect(summarizeHuntRunResults([...readable, readable[0], readable[4]])).toEqual({ sightings: 2, observed_data: 2, observables: 2, others: 1 });
    expect(summarizeHuntRunResults([])).toEqual({ sightings: 0, observed_data: 0, observables: 0, others: 0 });
  });

  it('should summarize a run without results as producing nothing, without reading anything', async () => {
    const user = { id: 'user-empty', internal_id: 'user-empty' } as AuthUser;
    const empty = { ...run, internal_id: 'run-empty', result_ids: [] } as unknown as BasicStoreEntityHuntRun;
    expect(await findHuntRunResultsSummary(testContext, user, empty)).toEqual({ sightings: 0, observed_data: 0, observables: 0, others: 0 });
    expect(internalFindByIds).not.toHaveBeenCalled();
  });
});

describe('Hunt configuration', () => {
  it('should give the user interface the observable types a run extracts when its hunt names none', () => {
    const resolver = (huntResolvers.Query as Record<string, () => { default_expected_observables: string[] }>).huntConfiguration;
    expect(resolver().default_expected_observables).toEqual(HUNT_DEFAULT_EXPECTED_OBSERVABLES);
  });
});
