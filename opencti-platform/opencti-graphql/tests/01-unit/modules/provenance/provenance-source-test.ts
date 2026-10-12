import { v5 as uuidv5 } from 'uuid';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as cache from '../../../../src/database/cache';
import * as engine from '../../../../src/database/engine';
import * as loader from '../../../../src/database/middleware-loader';
import { connectorIdFromWorkId, isOpenAevCoverageConnector, resolveAssertionSource, resolveSourceOfUserAt } from '../../../../src/modules/provenance/provenance-source';
import { buildCreationProvenance, buildStoreAssertion, removeProvenanceInputs } from '../../../../src/modules/provenance/provenance-write';
import { OPENCTI_NAMESPACE } from '../../../../src/schema/general';
import { ENTITY_TYPE_SYNC } from '../../../../src/schema/internalObject';
import { RULE_MANAGER_USER } from '../../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn(),
  getEntitiesMapFromCache: vi.fn(),
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elRawSearch: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));

const CONNECTOR_ID = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c001';
const SHARED_USER_CONNECTOR_ID = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c002';
const OPENAEV_CONNECTOR_ID = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c003';
const FEED_ID = 'b7f1b2b4-9a7e-4e0e-a4a7-2d3f2c8e1a10';
const FEED_CONNECTOR_ID = uuidv5(FEED_ID, OPENCTI_NAMESPACE);

const connectorUser = { id: 'c0000000-0000-4000-8000-000000000001', name: '[C] AlienVault' } as AuthUser;
const sharedUser = { id: 'c0000000-0000-4000-8000-000000000002', name: 'shared' } as AuthUser;
const humanUser = { id: 'c0000000-0000-4000-8000-000000000003', name: 'Jane Analyst' } as AuthUser;

const connectors = [
  { internal_id: CONNECTOR_ID, name: 'AlienVault', connector_user_id: connectorUser.id },
  { internal_id: SHARED_USER_CONNECTOR_ID, name: 'Shared A', connector_user_id: sharedUser.id },
  { internal_id: 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c004', name: 'Shared B', connector_user_id: sharedUser.id },
  { internal_id: OPENAEV_CONNECTOR_ID, name: 'OpenAEV Coverage', connector_user_id: 'c0000000-0000-4000-8000-000000000005' },
  { internal_id: FEED_CONNECTOR_ID, name: '[FEED - TAXII] Partner collection', connector_user_id: sharedUser.id, built_in: true },
];

const contextFor = (workId?: string) => ({ workId } as AuthContext);
const workOf = (connectorId: string) => `work_${connectorId}_2026-10-03T08:00:00.000Z`;

// The feed index is module state: the clock only moves forward so that every test sees a consistent index age
const realNow = Date.now.bind(Date);
let clockOffset = 0;
vi.spyOn(Date, 'now').mockImplementation(() => realNow() + clockOffset);
const advanceClock = (ms: number) => {
  clockOffset += ms;
};
const settle = () => new Promise((resolve) => {
  setTimeout(resolve, 0);
});

type FeedEntry = { internal_id: string; name: string };
const feedEntry = (id: string, name: string): FeedEntry => ({ internal_id: id, name });
const connectorIdOf = (feed: FeedEntry) => uuidv5(feed.internal_id, OPENCTI_NAMESPACE);
const builtInConnectorOf = (feed: FeedEntry) => ({ internal_id: connectorIdOf(feed), name: `[FEED - RSS] ${feed.name}`, connector_user_id: sharedUser.id, built_in: true });
const writeOf = (feed: FeedEntry) => resolveAssertionSource(contextFor(workOf(connectorIdOf(feed))), sharedUser, {});
const feedLoadsCount = () => vi.mocked(loader.fullEntitiesList).mock.calls.filter((args) => !(args[2] as string[]).includes(ENTITY_TYPE_SYNC)).length;
// Feed loads are held until released; each one returns the feeds that existed when it started
const holdFeedLoads = (feedsAtStart: () => FeedEntry[]) => {
  let released = false;
  const held: (() => void)[] = [];
  vi.mocked(loader.fullEntitiesList).mockImplementation(((...args: unknown[]) => {
    if ((args[2] as string[]).includes(ENTITY_TYPE_SYNC)) {
      return Promise.resolve([]);
    }
    const feeds = feedsAtStart();
    return new Promise((resolve) => {
      if (released) {
        resolve(feeds);
      } else {
        held.push(() => resolve(feeds));
      }
    });
  }) as never);
  vi.mocked(loader.fullEntitiesList).mockClear();
  return () => {
    released = true;
    held.splice(0).forEach((release) => release());
  };
};

describe('Provenance source resolution', () => {
  beforeEach(() => {
    vi.mocked(cache.getEntitiesListFromCache).mockResolvedValue(connectors as never);
    vi.mocked(loader.fullEntitiesList).mockResolvedValue([{ internal_id: FEED_ID, name: 'Partner collection' }] as never);
  });

  it('should read the connector id embedded in a work id', () => {
    expect(connectorIdFromWorkId(workOf(CONNECTOR_ID))).toEqual(CONNECTOR_ID);
    expect(connectorIdFromWorkId(undefined)).toBeNull();
    expect(connectorIdFromWorkId('')).toBeNull();
    expect(connectorIdFromWorkId('not-a-work')).toBeNull();
    expect(connectorIdFromWorkId('work_')).toBeNull();
  });

  it('should detect OpenAEV coverage connectors', () => {
    expect(isOpenAevCoverageConnector({ name: 'OpenAEV Coverage' })).toEqual(true);
    expect(isOpenAevCoverageConnector({ name: 'AlienVault' })).toEqual(false);
  });

  it('should attribute inference engine writes to the rule', async () => {
    const source = await resolveAssertionSource(contextFor(), RULE_MANAGER_USER, {}, { fromRule: 'i_rule_location_targets' });
    expect(source.source_kind).toEqual('inference');
    expect(source.source_id).toEqual('location_targets');
    expect(source.work_id).toBeNull();
  });

  it('should attribute a worker write to the connector of the work', async () => {
    const source = await resolveAssertionSource(contextFor(workOf(CONNECTOR_ID)), sharedUser, {});
    expect(source).toEqual({ source_id: CONNECTOR_ID, source_kind: 'connector', source_name: 'AlienVault', work_id: workOf(CONNECTOR_ID) });
  });

  it('should attribute a direct write to the unique connector of the user', async () => {
    const source = await resolveAssertionSource(contextFor(), connectorUser, { createdBy: { internal_id: 'identity-1', name: 'Vendor' } });
    expect(source.source_kind).toEqual('connector');
    expect(source.source_id).toEqual(CONNECTOR_ID);
  });

  it('should attribute OpenAEV coverage pushes to emulation', async () => {
    const source = await resolveAssertionSource(contextFor(workOf(OPENAEV_CONNECTOR_ID)), humanUser, {});
    expect(source.source_kind).toEqual('emulation');
    expect(source.source_id).toEqual(OPENAEV_CONNECTOR_ID);
  });

  it('should attribute built-in ingestion connectors to the feed', async () => {
    const source = await resolveAssertionSource(contextFor(workOf(FEED_CONNECTOR_ID)), sharedUser, {});
    expect(source).toEqual({ source_id: FEED_ID, source_kind: 'feed', source_name: 'Partner collection', work_id: workOf(FEED_CONNECTOR_ID) });
  });

  it('should attribute a feed created since the last index load to the feed right away', async () => {
    const newFeedId = 'b7f1b2b4-9a7e-4e0e-a4a7-2d3f2c8e1a11';
    const newFeedConnectorId = uuidv5(newFeedId, OPENCTI_NAMESPACE);
    await resolveAssertionSource(contextFor(workOf(FEED_CONNECTOR_ID)), sharedUser, {});
    vi.mocked(cache.getEntitiesListFromCache).mockResolvedValue([
      ...connectors,
      { internal_id: newFeedConnectorId, name: '[FEED - RSS] Vendor blog', connector_user_id: sharedUser.id, built_in: true },
    ] as never);
    vi.mocked(loader.fullEntitiesList).mockResolvedValue([{ internal_id: FEED_ID, name: 'Partner collection' }, { internal_id: newFeedId, name: 'Vendor blog' }] as never);
    // Under its connector id the same feed would be counted as a second source once the index catches up
    const source = await resolveAssertionSource(contextFor(workOf(newFeedConnectorId)), sharedUser, {});
    expect(source).toEqual({ source_id: newFeedId, source_kind: 'feed', source_name: 'Vendor blog', work_id: workOf(newFeedConnectorId) });
  });

  it('should not reload the index for a built-in connector that a fresh load did not find', async () => {
    const importConnectorId = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c009';
    vi.mocked(cache.getEntitiesListFromCache).mockResolvedValue([...connectors, { internal_id: importConnectorId, name: 'ImportCsv', built_in: true }] as never);
    await resolveAssertionSource(contextFor(workOf(importConnectorId)), sharedUser, {});
    vi.mocked(loader.fullEntitiesList).mockClear();
    const source = await resolveAssertionSource(contextFor(workOf(importConnectorId)), sharedUser, {});
    expect(source.source_id).toEqual(importConnectorId);
    expect(loader.fullEntitiesList).not.toHaveBeenCalled();
  });

  it('should resolve the writes that arrive during a load with that same load', async () => {
    const [first, ...others] = [1, 2, 3].map((n) => feedEntry(`b7f1b2b4-9a7e-4e0e-a4a7-2d3f2c8e1b0${n}`, `Blog ${n}`));
    vi.mocked(cache.getEntitiesListFromCache).mockResolvedValue([...connectors, ...[first, ...others].map(builtInConnectorOf)] as never);
    const release = holdFeedLoads(() => [feedEntry(FEED_ID, 'Partner collection'), first, ...others]);
    const firstWrite = writeOf(first);
    await settle();
    const otherWrites = others.map(writeOf);
    await settle();
    release();
    const sources = await Promise.all([firstWrite, ...otherWrites]);
    expect(sources.map((source) => source.source_id)).toEqual([first, ...others].map((feed) => feed.internal_id));
    expect(feedLoadsCount()).toBe(1);
  });

  it('should share one more load between the writes that the load in flight could not resolve', async () => {
    const [early, ...late] = [1, 2, 3, 4].map((n) => feedEntry(`b7f1b2b4-9a7e-4e0e-a4a7-2d3f2c8e1c0${n}`, `Vendor feed ${n}`));
    vi.mocked(cache.getEntitiesListFromCache).mockResolvedValue([...connectors, ...[early, ...late].map(builtInConnectorOf)] as never);
    let existingFeeds = [feedEntry(FEED_ID, 'Partner collection'), early];
    const release = holdFeedLoads(() => existingFeeds);
    const earlyWrite = writeOf(early);
    await settle();
    // Created while the first load runs: that load cannot hold them
    existingFeeds = [...existingFeeds, ...late];
    const lateWrites = late.map(writeOf);
    await settle();
    expect(feedLoadsCount()).toBe(1);
    release();
    const sources = await Promise.all([earlyWrite, ...lateWrites]);
    expect(sources.map((source) => source.source_id)).toEqual([early, ...late].map((feed) => feed.internal_id));
    expect(feedLoadsCount()).toBe(2);
  });

  it('should refresh an expired index with one load shared by the writes that arrive meanwhile', async () => {
    const release = holdFeedLoads(() => [feedEntry(FEED_ID, 'Partner collection')]);
    advanceClock(10 * 60 * 1000);
    const firstWrite = resolveAssertionSource(contextFor(workOf(FEED_CONNECTOR_ID)), sharedUser, {});
    await settle();
    const otherWrites = [1, 2].map(() => resolveAssertionSource(contextFor(workOf(FEED_CONNECTOR_ID)), sharedUser, {}));
    await settle();
    release();
    const sources = await Promise.all([firstWrite, ...otherWrites]);
    expect(sources.map((source) => source.source_id)).toEqual([FEED_ID, FEED_ID, FEED_ID]);
    expect(feedLoadsCount()).toBe(1);
  });

  it('should never record a feed under its connector while the feed index cannot be loaded', async () => {
    const feed = feedEntry('b7f1b2b4-9a7e-4e0e-a4a7-2d3f2c8e1d01', 'Vendor advisories');
    vi.mocked(cache.getEntitiesListFromCache).mockResolvedValue([...connectors, builtInConnectorOf(feed)] as never);
    vi.mocked(loader.fullEntitiesList).mockRejectedValue(new Error('search engine unavailable'));
    await expect(writeOf(feed)).rejects.toThrow('Ingestion feeds index unavailable');
    // A failed load is not retried by every write
    vi.mocked(loader.fullEntitiesList).mockClear();
    await expect(writeOf(feed)).rejects.toThrow('Ingestion feeds index unavailable');
    expect(loader.fullEntitiesList).not.toHaveBeenCalled();
    advanceClock(61 * 1000);
    vi.mocked(loader.fullEntitiesList).mockResolvedValue([feedEntry(FEED_ID, 'Partner collection'), feed] as never);
    const source = await writeOf(feed);
    expect(source).toEqual({ source_id: feed.internal_id, source_kind: 'feed', source_name: 'Vendor advisories', work_id: workOf(connectorIdOf(feed)) });
  });

  it('should never record a synchronized write under another source while the feed index cannot be loaded', async () => {
    const synchronizerUser = { id: 'c0000000-0000-4000-8000-000000000009', name: 'Remote platform' } as AuthUser;
    vi.mocked(loader.fullEntitiesList).mockRejectedValue(new Error('search engine unavailable'));
    const write = resolveAssertionSource({ synchronizedUpsert: true } as AuthContext, synchronizerUser, { createdBy: { internal_id: 'identity-1', name: 'ACME CERT' } });
    await expect(write).rejects.toThrow('Ingestion feeds index unavailable');
    advanceClock(61 * 1000);
  });

  it('should attribute a human write with an author to the author', async () => {
    const source = await resolveAssertionSource(contextFor(), humanUser, { createdBy: { internal_id: 'identity-1', name: 'ACME CERT' } });
    expect(source).toEqual({ source_id: 'identity-1', source_kind: 'author', source_name: 'ACME CERT', work_id: null });
  });

  it('should attribute a human write without author to the user', async () => {
    const source = await resolveAssertionSource(contextFor(), humanUser, {});
    expect(source).toEqual({ source_id: humanUser.id, source_kind: 'user', source_name: 'Jane Analyst', work_id: null });
  });

  it('should not guess between several connectors sharing a user', async () => {
    const source = await resolveAssertionSource(contextFor(), sharedUser, {});
    expect(source.source_kind).toEqual('user');
    expect(source.source_id).toEqual(sharedUser.id);
  });
});

describe('Source of a past write of a user shared by several connectors', () => {
  const SHARED_B_ID = 'a1f3c3b0-0d2c-4bf3-8d3c-1fd1c1d6c004';
  const at = '2026-10-03T08:00:00.000Z';
  const runningWorks = (connectorIds: string[]) => ({
    aggregations: { connectors: { buckets: connectorIds.map((key) => ({ key, work: { hits: { hits: [{ _source: { internal_id: `work-of-${key}` } }] } } })) } },
  });
  const assertionOf = (sourceId: string) => buildStoreAssertion({ source_id: sourceId, source_kind: 'connector', source_name: sourceId, work_id: null }, 50, at);

  beforeEach(() => {
    vi.mocked(cache.getEntitiesListFromCache).mockResolvedValue(connectors as never);
    vi.mocked(cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[sharedUser.id, sharedUser]]) as never);
    vi.mocked(loader.fullEntitiesList).mockResolvedValue([{ internal_id: FEED_ID, name: 'Partner collection' }] as never);
    vi.mocked(engine.elRawSearch).mockReset();
  });

  it('should resolve the connector whose work was running at the date of the write', async () => {
    vi.mocked(engine.elRawSearch).mockResolvedValue(runningWorks([SHARED_B_ID]) as never);
    const source = await resolveSourceOfUserAt(contextFor(), sharedUser.id, at, []);
    expect(source).toEqual({ source_id: SHARED_B_ID, source_kind: 'connector', source_name: 'Shared B', work_id: `work-of-${SHARED_B_ID}` });
  });

  it('should fall back to the only connector of the user that asserted the element', async () => {
    vi.mocked(engine.elRawSearch).mockResolvedValue(runningWorks([SHARED_USER_CONNECTOR_ID, SHARED_B_ID]) as never);
    const source = await resolveSourceOfUserAt(contextFor(), sharedUser.id, at, [assertionOf(SHARED_USER_CONNECTOR_ID), assertionOf(CONNECTOR_ID)]);
    expect(source).toMatchObject({ source_id: SHARED_USER_CONNECTOR_ID, source_kind: 'connector', source_name: 'Shared A' });
  });

  it('should keep the user when neither the works nor the assertions tell, or when the user asserted the element itself', async () => {
    vi.mocked(engine.elRawSearch).mockResolvedValue(runningWorks([]) as never);
    const withoutDate = await resolveSourceOfUserAt(contextFor(), sharedUser.id, null, [assertionOf(SHARED_USER_CONNECTOR_ID), assertionOf(SHARED_B_ID)]);
    expect(withoutDate).toMatchObject({ source_id: sharedUser.id, source_kind: 'user', source_name: 'shared' });
    expect(engine.elRawSearch).not.toHaveBeenCalled();
    const alsoHuman = await resolveSourceOfUserAt(contextFor(), sharedUser.id, at, [assertionOf(SHARED_USER_CONNECTOR_ID), assertionOf(sharedUser.id)]);
    expect(alsoHuman).toMatchObject({ source_id: sharedUser.id, source_kind: 'user' });
  });

  it('should resolve the user of a single connector to it without reading the works', async () => {
    const source = await resolveSourceOfUserAt(contextFor(), connectorUser.id, at, []);
    expect(source).toMatchObject({ source_id: CONNECTOR_ID, source_kind: 'connector', source_name: 'AlienVault' });
    expect(engine.elRawSearch).not.toHaveBeenCalled();
  });
});

describe('Provenance write helpers', () => {
  it('should never accept provenance from client inputs', () => {
    const input = removeProvenanceInputs({
      name: 'APT29',
      x_opencti_assertions: [{ source_id: 'forged' }],
      corroboration_count: 99,
      single_sourced: false,
      has_conflicts: true,
      x_opencti_conflicts: [],
      procedures: [{ text: 'forged' }],
      freshness_stale: true,
    });
    expect(input).toEqual({ name: 'APT29' });
  });

  it('should build the provenance of a created element', () => {
    const at = '2026-10-03T08:00:00.000Z';
    const source = { source_id: CONNECTOR_ID, source_kind: 'connector' as const, source_name: 'AlienVault', work_id: null };
    expect(buildCreationProvenance(source, 75, at)).toEqual({
      x_opencti_assertions: [{
        source_id: CONNECTOR_ID,
        source_kind: 'connector',
        source_name: 'AlienVault',
        first_asserted_at: at,
        last_asserted_at: at,
        assert_count: 1,
        confidence: 75,
        work_id: null,
      }],
      assertion_source_ids: [CONNECTOR_ID],
      assertion_source_kinds: ['connector'],
      corroboration_count: 1,
      last_asserted_at: at,
      single_sourced: true,
      has_conflicts: false,
    });
  });
});
