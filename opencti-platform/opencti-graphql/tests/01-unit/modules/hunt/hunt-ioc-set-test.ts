import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { pageRegardingEntitiesConnection } from '../../../../src/database/middleware-loader';
import { resolveHuntIocSet } from '../../../../src/modules/hunt/hunt-iocs';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { type BasicStoreEntityHunt, RELATION_HUNT_SOURCES } from '../../../../src/modules/hunt/hunt-types';
import { HUNT_CONFIG } from '../../../../src/modules/hunt/hunt-utils';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/cache')>(),
  getEntitiesMapFromCache: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
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
});
