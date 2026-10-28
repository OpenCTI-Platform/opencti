/**
 * Unit tests of the public time series breakdowns: every breakdown setting is read from the stored widget,
 * and the query runs as the user built for the public dashboard. Only the breakdowns of entities and
 * relationships widgets are public: audits widgets can carry a breakdown as well, but the logs have no public API.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

// ── Infrastructure stubs (prevent DB / network connections on module load) ───

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  deleteElementById: vi.fn(),
  loadEntity: vi.fn(),
  updateAttribute: vi.fn(),
  TIME_SERIES_BREAKDOWN_DEFAULT_LIMIT: 10,
}));
vi.mock('../../../../src/database/middleware-loader', () => ({
  internalLoadById: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/database/engine', () => ({
  ES_MAX_CONCURRENCY: 5,
  elLoadById: vi.fn(),
  elPaginate: vi.fn(),
}));
vi.mock('../../../../src/database/redis', () => ({ notify: vi.fn() }));
vi.mock('../../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn(),
  getEntitiesMapFromCache: vi.fn(),
  getEntityFromCache: vi.fn().mockResolvedValue({ platform_organization: null }),
}));
vi.mock('../../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn() }));
vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...(actual as object),
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
  };
});
vi.mock('../../../../src/modules/workspace/workspace-domain', () => ({ findAllWorkspaces: vi.fn(), findById: vi.fn() }));
vi.mock('../../../../src/modules/user/user-domain', () => ({
  bookmarks: vi.fn(),
  checkUserCanShareMarkings: vi.fn(),
  computeAvailableMarkings: vi.fn(),
}));
vi.mock('../../../../src/domain/markingDefinition', () => ({ findById: vi.fn() }));
vi.mock('../../../../src/http/httpAuthenticatedContext', () => ({ computeLoaders: vi.fn().mockReturnValue({}) }));

// ── Key domain mocks ─────────────────────────────────────────────────────────

vi.mock('../../../../src/domain/stixCoreObject', () => ({
  findStixCoreObjectPaginated: vi.fn(),
  stixCoreObjectsDistribution: vi.fn(),
  stixCoreObjectsDistributionByEntity: vi.fn(),
  stixCoreObjectsMultiTimeSeries: vi.fn(),
  stixCoreObjectsNumber: vi.fn(),
  stixCoreObjectsTimeSeriesBreakdown: vi.fn(),
}));
vi.mock('../../../../src/domain/stixRelationship', () => ({
  findStixRelationPaginated: vi.fn(),
  stixRelationshipsDistribution: vi.fn(),
  stixRelationshipsMultiTimeSeries: vi.fn(),
  stixRelationshipsNumber: vi.fn(),
  stixRelationshipsTimeSeriesBreakdown: vi.fn(),
}));
// The widget is read from the cache of the public dashboards: only this read is replaced
vi.mock('../../../../src/modules/publicDashboard/publicDashboard-utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/publicDashboard/publicDashboard-utils')>()),
  getWidgetArguments: vi.fn(),
}));

// ── Imports (after mocks) ────────────────────────────────────────────────────

import { publicStixCoreObjectsTimeSeriesBreakdown, publicStixRelationshipsTimeSeriesBreakdown } from '../../../../src/modules/publicDashboard/publicDashboard-domain';
import * as StixCoreObjectDomain from '../../../../src/domain/stixCoreObject';
import * as StixRelationshipDomain from '../../../../src/domain/stixRelationship';
import * as PublicDashboardUtils from '../../../../src/modules/publicDashboard/publicDashboard-utils';

// ── Helpers ──────────────────────────────────────────────────────────────────

const publicUser = { id: 'public-dashboard-author', allowed_marking: [{ id: 'tlp-green' }] } as any;
const startDate = '2026-01-01T00:00:00.000Z';
const endDate = '2026-02-01T00:00:00.000Z';

const targets = { mode: 'and', filters: [{ key: ['relationship_type'], values: ['targets'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const malwares = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const sectors = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Sector'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const breakdownParameters = { interval: 'week', breakdownBy: 'toTypes', breakdownLimit: 20, breakdownOrder: 'asc', breakdownOther: true };

const storeWidget = (perspective: string | null, dataSelection: unknown[], parameters: unknown) => {
  vi.mocked(PublicDashboardUtils.getWidgetArguments).mockResolvedValue({ user: publicUser, perspective, dataSelection, parameters } as any);
};
const request = (overrides: Record<string, unknown> = {}) => ({ uriKey: 'public-key', widgetId: 'widget-1', startDate, endDate, ...overrides } as any);

describe('publicStixRelationshipsTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should break the stored dataset down with the stored settings, as the public user', async () => {
    storeWidget('relationships', [{ date_attribute: 'start_time', filters: targets, dynamicFrom: malwares, dynamicTo: sectors, isTo: false }], breakdownParameters);

    await publicStixRelationshipsTimeSeriesBreakdown({} as any, request());

    expect(PublicDashboardUtils.getWidgetArguments).toHaveBeenCalledWith(expect.anything(), 'public-key', 'widget-1');
    const [, user, args] = vi.mocked(StixRelationshipDomain.stixRelationshipsTimeSeriesBreakdown).mock.calls[0];
    expect(user).toBe(publicUser);
    expect(args).toEqual({
      field: 'toTypes',
      dateAttribute: 'start_time',
      startDate,
      endDate,
      interval: 'week',
      limit: 20,
      order: 'asc',
      includeOther: true,
      filters: targets,
      dynamicFrom: malwares,
      dynamicTo: sectors,
      // the field is checked against the relationship types the filters restrict to
      relationship_type: ['targets'],
    });
    // Like the relationships time series, the displayed side of the widget plays no part
    expect(args).not.toHaveProperty('isTo');
  });

  it('should default the settings of the widget, and break all the relationships down without type filter', async () => {
    storeWidget('relationships', [{ date_attribute: 'created_at' }], { breakdownBy: 'relationship_type' });

    await publicStixRelationshipsTimeSeriesBreakdown({} as any, request({ endDate: null }));

    expect(vi.mocked(StixRelationshipDomain.stixRelationshipsTimeSeriesBreakdown).mock.calls[0][2]).toMatchObject({
      field: 'relationship_type',
      endDate: null,
      interval: 'day',
      limit: 10,
      order: 'desc',
      includeOther: false,
      relationship_type: [],
    });
  });

  it('should refuse a widget without breakdown, or a request without start date', async () => {
    storeWidget('relationships', [{ date_attribute: 'created_at', filters: targets }], { interval: 'day' });
    await expect(publicStixRelationshipsTimeSeriesBreakdown({} as any, request())).rejects.toThrow('This widget has no breakdown');

    storeWidget('relationships', [{ date_attribute: 'created_at', filters: targets }], breakdownParameters);
    await expect(publicStixRelationshipsTimeSeriesBreakdown({} as any, request({ startDate: null }))).rejects.toThrow('A start date is required');
    expect(StixRelationshipDomain.stixRelationshipsTimeSeriesBreakdown).not.toHaveBeenCalled();
  });

  it('should refuse the widgets of the other perspectives, or without perspective, carrying a breakdown', async () => {
    for (const perspective of ['entities', 'audits', null]) {
      storeWidget(perspective, [{ date_attribute: 'created_at', filters: targets }], breakdownParameters);
      await expect(publicStixRelationshipsTimeSeriesBreakdown({} as any, request())).rejects.toThrow('This widget has no breakdown');
    }
    expect(StixRelationshipDomain.stixRelationshipsTimeSeriesBreakdown).not.toHaveBeenCalled();
  });
});

describe('publicStixCoreObjectsTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should keep breaking the stored entities dataset down with the stored settings', async () => {
    const reports = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' }], filterGroups: [] };
    storeWidget('entities', [{ date_attribute: 'published', filters: reports }], { interval: 'month', breakdownBy: 'objectLabel', breakdownLimit: 5 });

    await publicStixCoreObjectsTimeSeriesBreakdown({} as any, request());

    const [, user, args] = vi.mocked(StixCoreObjectDomain.stixCoreObjectsTimeSeriesBreakdown).mock.calls[0];
    expect(user).toBe(publicUser);
    expect(args).toEqual({
      field: 'objectLabel',
      dateAttribute: 'published',
      startDate,
      endDate,
      interval: 'month',
      limit: 5,
      order: 'desc',
      includeOther: false,
      filters: reports,
      types: ['Report'],
    });
  });

  it('should refuse an audits widget carrying a breakdown, without querying anything', async () => {
    storeWidget('audits', [{ date_attribute: 'timestamp', filters: null }], { interval: 'day', breakdownBy: 'event_scope', breakdownLimit: 5 });
    await expect(publicStixCoreObjectsTimeSeriesBreakdown({} as any, request())).rejects.toThrow('This widget has no breakdown');
    expect(StixCoreObjectDomain.stixCoreObjectsTimeSeriesBreakdown).not.toHaveBeenCalled();
  });

  it('should refuse the widgets of the other perspectives, or without perspective', async () => {
    for (const perspective of ['relationships', null]) {
      storeWidget(perspective, [{ date_attribute: 'published', filters: null }], { interval: 'day', breakdownBy: 'objectLabel' });
      await expect(publicStixCoreObjectsTimeSeriesBreakdown({} as any, request())).rejects.toThrow('This widget has no breakdown');
    }
    expect(StixCoreObjectDomain.stixCoreObjectsTimeSeriesBreakdown).not.toHaveBeenCalled();
  });
});
