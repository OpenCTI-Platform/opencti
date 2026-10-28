/**
 * Unit tests of publicStixCoreObjectsTimeSeriesBreakdown: only the breakdowns of entities widgets are public.
 * Audits widgets can carry a breakdown as well, but the logs have no public API.
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
  elPaginate: vi.fn(),
}));

vi.mock('../../../../src/database/redis', () => ({ notify: vi.fn() }));

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesMapFromCache: vi.fn(),
  getEntityFromCache: vi.fn().mockResolvedValue({ platform_organization: null }),
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...(actual as object),
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
  };
});

vi.mock('../../../../src/modules/workspace/workspace-domain', () => ({
  findAllWorkspaces: vi.fn(),
}));

vi.mock('../../../../src/modules/user/user-domain', () => ({
  bookmarks: vi.fn(),
  checkUserCanShareMarkings: vi.fn(),
}));

vi.mock('../../../../src/domain/markingDefinition', () => ({
  findById: vi.fn(),
}));

vi.mock('../../../../src/http/httpAuthenticatedContext', () => ({
  computeLoaders: vi.fn().mockReturnValue({}),
}));

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
}));

vi.mock('../../../../src/modules/publicDashboard/publicDashboard-utils', () => ({
  getWidgetArguments: vi.fn(),
  getBreakdownEntityTypes: vi.fn().mockReturnValue([]),
  checkUserIsAdminOnDashboard: vi.fn(),
  sanitizePublicDashboardUriKey: vi.fn(),
}));

// ── Imports (after mocks) ────────────────────────────────────────────────────

import { publicStixCoreObjectsTimeSeriesBreakdown } from '../../../../src/modules/publicDashboard/publicDashboard-domain';
import * as StixCoreObjectDomain from '../../../../src/domain/stixCoreObject';
import * as PublicDashboardUtils from '../../../../src/modules/publicDashboard/publicDashboard-utils';
import { SYSTEM_USER } from '../../../../src/utils/access';

const args = { uriKey: 'test-key', widgetId: 'widget-1', startDate: '2026-01-01T00:00:00.000Z', endDate: null } as any;
const selection = { date_attribute: 'timestamp', filters: null };
const breakdownParameters = { interval: 'day', breakdownBy: 'event_scope', breakdownLimit: 5 };

const setupWidget = (perspective: string | null, parameters: Record<string, unknown> = breakdownParameters) => {
  vi.mocked(PublicDashboardUtils.getWidgetArguments).mockResolvedValue({
    user: SYSTEM_USER,
    perspective,
    dataSelection: [selection],
    parameters,
  } as any);
};

describe('publicStixCoreObjectsTimeSeriesBreakdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('refuses an audits widget carrying a breakdown, without querying anything', async () => {
    setupWidget('audits');
    await expect(publicStixCoreObjectsTimeSeriesBreakdown({} as any, args)).rejects.toThrow('This widget has no breakdown');
    expect(StixCoreObjectDomain.stixCoreObjectsTimeSeriesBreakdown).not.toHaveBeenCalled();
  });

  it('refuses the widgets of the other perspectives, or without perspective', async () => {
    for (const perspective of ['relationships', null]) {
      setupWidget(perspective);
      await expect(publicStixCoreObjectsTimeSeriesBreakdown({} as any, args)).rejects.toThrow('This widget has no breakdown');
    }
    expect(StixCoreObjectDomain.stixCoreObjectsTimeSeriesBreakdown).not.toHaveBeenCalled();
  });

  it('breaks down an entities widget with the settings of its manifest', async () => {
    setupWidget('entities', { interval: 'week', breakdownBy: 'objectLabel', breakdownLimit: 5, breakdownOrder: 'asc', breakdownOther: true });
    await publicStixCoreObjectsTimeSeriesBreakdown({} as any, args);
    expect(StixCoreObjectDomain.stixCoreObjectsTimeSeriesBreakdown).toHaveBeenCalledTimes(1);
    expect(vi.mocked(StixCoreObjectDomain.stixCoreObjectsTimeSeriesBreakdown).mock.calls[0][2]).toMatchObject({
      field: 'objectLabel',
      interval: 'week',
      limit: 5,
      order: 'asc',
      includeOther: true,
      types: ['Stix-Core-Object'],
    });
  });
});
