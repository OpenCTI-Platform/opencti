import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { pageEntitiesConnection, pageRegardingEntitiesConnection } from '../../../../src/database/middleware-loader';
import { resolveHuntIocSet } from '../../../../src/modules/hunt/hunt-iocs';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { type BasicStoreEntityHunt, INPUT_HUNT_SOURCES, RELATION_HUNT_SOURCES } from '../../../../src/modules/hunt/hunt-types';
import { HUNT_CONFIG } from '../../../../src/modules/hunt/hunt-utils';
import { validateHuntState } from '../../../../src/modules/hunt/hunt-validators';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { isBypassUser, SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesMapFromCache: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  pageEntitiesConnection: vi.fn(),
  pageRegardingEntitiesConnection: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

const report = (index: number) => ({ internal_id: `report-${index}`, standard_id: `report--${index}`, entity_type: 'Report' });
// The address of a report is distinct from the addresses of the other reports
const address = (reportId: string, index: number) => {
  const reportIndex = reportId.split('-')[1];
  return { internal_id: `${reportId}-ip-${index}`, standard_id: `ipv4-addr--${reportIndex}-${index}`, entity_type: 'IPv4-Addr', value: `10.${reportIndex}.0.${index}` };
};
const hunt = (reports: number) => ({ internal_id: 'hunt-1', hunt_type: 'indicators', [RELATION_HUNT_SOURCES]: Array.from({ length: reports }, (_, index) => `report-${index}`) }) as unknown as BasicStoreEntityHunt;

// Each report contains `contained` addresses, read at most as many as asked
const serveReports = (reports: number, contained: number) => {
  vi.mocked(findByIds).mockResolvedValue(Array.from({ length: reports }, (_, index) => report(index)) as never);
  vi.mocked(pageRegardingEntitiesConnection).mockImplementation(async (_context, _user, sourceId, _relation, _types, _reverse, opts) => ({
    edges: Array.from({ length: Math.min(contained, opts?.first ?? contained) }, (_, index) => ({ node: address(String(sourceId), index) })),
  }) as never);
};

describe('Values an indicator hunt looks up', () => {
  const { maxIocsPerRun } = HUNT_CONFIG;

  beforeEach(() => {
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map() as never);
    vi.mocked(pageRegardingEntitiesConnection).mockReset();
  });

  afterEach(() => {
    HUNT_CONFIG.maxIocsPerRun = maxIocsPerRun;
  });

  it('should read one budget of elements across every source, however many sources the hunt has', async () => {
    HUNT_CONFIG.maxIocsPerRun = 3;
    serveReports(50, 10);
    const set = await resolveHuntIocSet(testContext, hunt(50));
    expect(set.iocs).toHaveLength(3);
    expect(set.truncated).toBe(true);
    // One more element than a run looks up, read from the first report: the other reports are never queried
    expect(vi.mocked(pageRegardingEntitiesConnection).mock.calls.map((call) => call[6]?.first)).toEqual([4]);
  });

  it('should share the budget between the sources in turn, and keep every value when they fit', async () => {
    HUNT_CONFIG.maxIocsPerRun = 5;
    serveReports(3, 2);
    const set = await resolveHuntIocSet(testContext, hunt(3));
    expect(set.iocs).toHaveLength(5);
    expect(set.truncated).toBe(true);
    expect(vi.mocked(pageRegardingEntitiesConnection).mock.calls.map((call) => call[6]?.first)).toEqual([6, 4, 2]);
    vi.mocked(pageRegardingEntitiesConnection).mockReset();
    HUNT_CONFIG.maxIocsPerRun = 10;
    serveReports(3, 2);
    const complete = await resolveHuntIocSet(testContext, hunt(3));
    expect(complete.iocs).toHaveLength(6);
    expect(complete.truncated).toBe(false);
  });

  it('should count a source that holds nothing against the budget, so the queries stay bounded', async () => {
    HUNT_CONFIG.maxIocsPerRun = 3;
    serveReports(50, 0);
    const set = await resolveHuntIocSet(testContext, hunt(50));
    expect(set.iocs).toHaveLength(0);
    expect(pageRegardingEntitiesConnection).toHaveBeenCalledTimes(4);
  });

  it('should count the indicators and observables chosen as sources against the same budget', async () => {
    HUNT_CONFIG.maxIocsPerRun = 3;
    const direct = Array.from({ length: 10 }, (_, index) => address('report-9', index));
    vi.mocked(findByIds).mockImplementation(async (_context, _user, ids) => direct.filter((element) => ids.includes(element.internal_id)) as never);
    const set = await resolveHuntIocSet(testContext, { internal_id: 'hunt-1', hunt_type: 'indicators', [RELATION_HUNT_SOURCES]: direct.map((element) => element.internal_id) } as unknown as BasicStoreEntityHunt);
    // One more source than a run looks up is read, the others are left unread
    expect(vi.mocked(findByIds).mock.calls.at(-1)?.[2]).toHaveLength(4);
    expect(set.iocs).toHaveLength(3);
    expect(set.truncated).toBe(true);
    // Three addresses and a report: the addresses leave one element to read from the report
    vi.mocked(pageRegardingEntitiesConnection).mockReset();
    vi.mocked(pageRegardingEntitiesConnection).mockImplementation(async (_context, _user, sourceId, _relation, _types, _reverse, opts) => ({
      edges: Array.from({ length: Math.min(5, opts?.first ?? 5) }, (_, index) => ({ node: address(String(sourceId), index) })),
    }) as never);
    vi.mocked(findByIds).mockResolvedValue([...direct.slice(0, 3), report(1)] as never);
    const mixed = await resolveHuntIocSet(testContext, { internal_id: 'hunt-1', hunt_type: 'indicators', [RELATION_HUNT_SOURCES]: ['report-9-ip-0', 'report-9-ip-1', 'report-9-ip-2', 'report-1'] } as unknown as BasicStoreEntityHunt);
    expect(vi.mocked(pageRegardingEntitiesConnection).mock.calls.map((call) => call[6]?.first)).toEqual([1]);
    expect(mixed.truncated).toBe(true);
  });

  it('should take no value from an indicator, an observable or a report restricted to authorized members', async () => {
    const members = [{ id: 'user-analyst', access_right: 'view' }];
    vi.mocked(findByIds).mockResolvedValue([
      address('report-9', 0),
      { ...address('report-9', 1), restricted_members: members },
      { ...report(1), restricted_members: members },
      report(2),
    ] as never);
    vi.mocked(pageRegardingEntitiesConnection).mockImplementation(async (_context, _user, sourceId) => ({
      edges: [{ node: address(String(sourceId), 0) }],
    }) as never);
    const set = await resolveHuntIocSet(testContext, { internal_id: 'hunt-1', hunt_type: 'indicators', [RELATION_HUNT_SOURCES]: ['report-9-ip-0', 'report-9-ip-1', 'report-1', 'report-2'] } as unknown as BasicStoreEntityHunt);
    // The report restricted to authorized members is never read
    expect(vi.mocked(pageRegardingEntitiesConnection).mock.calls.map((call) => call[2])).toEqual(['report-2']);
    expect(set.iocs.map((ioc) => ioc.value).sort()).toEqual(['10.2.0.0', '10.9.0.0']);
    expect(set.restricted_count).toBe(1);
  });

  it('should name the source each value was reached from, and keep pasted values without one', async () => {
    vi.mocked(findByIds).mockResolvedValue([address('report-9', 0), { ...report(1), name: 'LockBit report' }] as never);
    vi.mocked(pageRegardingEntitiesConnection).mockImplementation(async (_context, _user, sourceId) => ({
      edges: [{ node: address(String(sourceId), 0) }],
    }) as never);
    const set = await resolveHuntIocSet(testContext, {
      internal_id: 'hunt-1',
      hunt_type: 'indicators',
      [RELATION_HUNT_SOURCES]: ['report-9-ip-0', 'report-1'],
      hunt_ioc_values: [{ observable_type: 'Domain-Name', value: 'pasted.example.com' }],
    } as unknown as BasicStoreEntityHunt);
    const byValue = new Map(set.iocs.map((ioc) => [ioc.value, ioc]));
    expect(byValue.get('10.9.0.0')?.sources).toEqual([expect.objectContaining({ id: 'report-9-ip-0', via: null, matched_filter: false })]);
    expect(byValue.get('10.1.0.0')?.sources).toEqual([expect.objectContaining({
      id: 'report-1-ip-0',
      via: { id: 'report-1', entity_type: 'Report', name: 'LockBit report', relation: 'object' },
    })]);
    expect(byValue.get('pasted.example.com')?.sources).toEqual([]);
  });
});

describe('Access a hunt reads its values with', () => {
  const marking = (id: string, order: number, type = 'TLP') => ({ id, internal_id: id, standard_id: `marking-definition--${id}`, definition_type: type, x_opencti_order: order });
  const markings = [marking('clear', 1), marking('green', 2), marking('amber', 3), marking('red', 4), marking('pap-red', 4, 'PAP')];
  const filter = JSON.stringify({ mode: 'and', filters: [{ key: ['name'], values: ['Hunt test'], operator: 'eq', mode: 'or' }], filterGroups: [] });
  const amberHunt = (sources: string[]) => ({
    internal_id: 'hunt-1',
    hunt_type: 'indicators',
    hunt_ioc_filters: filter,
    [RELATION_HUNT_SOURCES]: sources,
    [RELATION_OBJECT_MARKING]: ['amber'],
  }) as unknown as BasicStoreEntityHunt;

  beforeEach(() => {
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map(markings.flatMap((item) => [[item.internal_id, item], [item.standard_id, item]])) as never);
    vi.mocked(findByIds).mockReset();
    vi.mocked(pageRegardingEntitiesConnection).mockReset();
    vi.mocked(pageEntitiesConnection).mockReset();
  });

  it('should read the sources, what they contain and the filter with the markings the hunt covers, never as the system', async () => {
    vi.mocked(findByIds).mockResolvedValue([address('report-9', 0), report(1)] as never);
    vi.mocked(pageRegardingEntitiesConnection).mockResolvedValue({ edges: [] } as never);
    vi.mocked(pageEntitiesConnection).mockResolvedValue({ edges: [] } as never);
    await resolveHuntIocSet(testContext, amberHunt(['report-9-ip-0', 'report-1']));
    const readers = [findByIds, pageRegardingEntitiesConnection, pageEntitiesConnection].map((read) => vi.mocked(read).mock.calls[0][1] as AuthUser);
    readers.forEach((reader) => {
      expect(reader.id).not.toEqual(SYSTEM_USER.id);
      expect(isBypassUser(reader)).toBe(false);
      // The TLP markings up to the amber of the hunt, no red, and no marking of a type the hunt holds none of
      expect(reader.allowed_marking.map((item) => item.internal_id).sort()).toEqual(['amber', 'clear', 'green']);
    });
  });

  it('should count the elements left out for a viewer among those he reads himself, never the others', async () => {
    const red = { ...address('report-9', 1), [RELATION_OBJECT_MARKING]: ['red'] };
    const viewer = { ...ADMIN_USER, id: 'viewer' } as AuthUser;
    vi.mocked(findByIds).mockImplementation(async (_context, user) => (user.id === viewer.id ? [address('report-9', 0), red] : [address('report-9', 0)]) as never);
    vi.mocked(pageEntitiesConnection).mockResolvedValue({ edges: [] } as never);
    const hunt = amberHunt(['report-9-ip-0', 'report-9-ip-1']);
    const forViewer = await resolveHuntIocSet(testContext, hunt, viewer);
    expect(forViewer.iocs.map((ioc) => ioc.value)).toEqual(['10.9.0.0']);
    expect(forViewer.restricted_count).toBe(1);
    // A run, or a viewer who cannot read the red address, is told of nothing the hunt could not read
    const forRun = await resolveHuntIocSet(testContext, hunt);
    expect(forRun.iocs.map((ioc) => ioc.value)).toEqual(['10.9.0.0']);
    expect(forRun.restricted_count).toBe(0);
  });
});

describe('Sources of a hunt', () => {
  const { maxIocsPerRun } = HUNT_CONFIG;

  afterEach(() => {
    HUNT_CONFIG.maxIocsPerRun = maxIocsPerRun;
  });

  it('should refuse a hunt with more sources than a run looks up values', async () => {
    HUNT_CONFIG.maxIocsPerRun = 3;
    const ids = (count: number) => Array.from({ length: count }, (_, index) => `report-${index}`);
    await expect(validateHuntState(testContext, ADMIN_USER, { hunt_type: 'indicators', [INPUT_HUNT_SOURCES]: ids(4) })).rejects.toThrow('A hunt has at most 3 sources');
    // A source added to a stored hunt
    await expect(validateHuntState(testContext, ADMIN_USER, { hunt_type: 'indicators', [RELATION_HUNT_SOURCES]: ids(4) })).rejects.toThrow('A hunt has at most 3 sources');
    await expect(validateHuntState(testContext, ADMIN_USER, { hunt_type: 'indicators', [INPUT_HUNT_SOURCES]: ids(3) })).resolves.toBeUndefined();
  });
});
