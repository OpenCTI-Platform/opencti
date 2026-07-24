/**
 * Unit tests for the null-entity guard in publicStixCoreObjectsDistribution
 * and publicStixRelationshipsDistribution (lines 432-436 and 503-507).
 *
 * The 'unknown' bucket returned by ElasticSearch aggregations has entity: null.
 * These guards ensure the breakdown logic is skipped for such items, preventing
 * a "Cannot read properties of null" runtime crash.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Infrastructure stubs (prevent DB / network connections on module load) ───

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  deleteElementById: vi.fn(),
  loadEntity: vi.fn(),
  updateAttribute: vi.fn(),
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

vi.mock('../../../../src/database/cache', () => ({ getEntitiesMapFromCache: vi.fn() }));

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

vi.mock('../../../../src/domain/user', () => ({
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
}));

vi.mock('../../../../src/domain/stixRelationship', () => ({
  findStixRelationPaginated: vi.fn(),
  stixRelationshipsDistribution: vi.fn(),
  stixRelationshipsMultiTimeSeries: vi.fn(),
  stixRelationshipsNumber: vi.fn(),
}));

vi.mock('../../../../src/modules/publicDashboard/publicDashboard-utils', () => ({
  getWidgetArguments: vi.fn(),
  checkUserIsAdminOnDashboard: vi.fn(),
  sanitizePublicDashboardUriKey: vi.fn(),
}));

// ── Imports (after mocks) ────────────────────────────────────────────────────

import { publicStixCoreObjectsDistribution, publicStixRelationshipsDistribution } from '../../../../src/modules/publicDashboard/publicDashboard-domain';
import * as StixCoreObjectDomain from '../../../../src/domain/stixCoreObject';
import * as StixRelationshipDomain from '../../../../src/domain/stixRelationship';
import * as PublicDashboardUtils from '../../../../src/modules/publicDashboard/publicDashboard-utils';
import * as HttpContext from '../../../../src/http/httpAuthenticatedContext';
import { SYSTEM_USER } from '../../../../src/utils/access';

// ── Helpers ──────────────────────────────────────────────────────────────────

const mockContext = {} as any;

/** The 'unknown' distribution item — entity is null (no backing store object) */
const unknownItem = { label: 'unknown', value: 5, entity: null };
/** A normal distribution item with a real entity */
const malwareItem = {
  label: 'malware-id-1',
  value: 10,
  entity: { id: 'malware-id-1', entity_type: 'Malware' },
};

const baseSelection = {
  attribute: 'creator_id',
  filters: null,
  date_attribute: 'created_at',
  number: 10,
  toTypes: null,
};
const breakdownSelection = { ...baseSelection, number: 5, perspective: undefined };

const setupWidgetArgs = (selections: unknown[]) => {
  vi.mocked(PublicDashboardUtils.getWidgetArguments).mockResolvedValue({
    user: SYSTEM_USER,
    dataSelection: selections,
    parameters: {},
  } as any);
  vi.mocked(HttpContext.computeLoaders).mockReturnValue({} as any);
};

// ── Tests: publicStixCoreObjectsDistribution (lines 432-436) ─────────────────

describe('publicStixCoreObjectsDistribution', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the unknown item as-is when entity is null (no breakdown attempted)', async () => {
    setupWidgetArgs([baseSelection, breakdownSelection]);
    vi.mocked(StixCoreObjectDomain.stixCoreObjectsDistribution).mockResolvedValue(
      [unknownItem] as any,
    );

    const result = await publicStixCoreObjectsDistribution(mockContext, {
      uriKey: 'test-key',
      widgetId: 'widget-1',
      startDate: null,
      endDate: null,
    } as any);

    expect(result).toEqual([unknownItem]);
    // stixCoreObjectsDistribution called once (main only, no breakdown for null entity)
    expect(StixCoreObjectDomain.stixCoreObjectsDistribution).toHaveBeenCalledTimes(1);
  });

  it('returns a non-StixCoreObject entity item as-is (no breakdown attempted)', async () => {
    const nonCoreItem = {
      label: 'user-id-1',
      value: 3,
      entity: { id: 'user-id-1', entity_type: 'User' }, // not a StixCoreObject
    };
    setupWidgetArgs([baseSelection, breakdownSelection]);
    vi.mocked(StixCoreObjectDomain.stixCoreObjectsDistribution).mockResolvedValue(
      [nonCoreItem] as any,
    );

    const result = await publicStixCoreObjectsDistribution(mockContext, {
      uriKey: 'test-key',
      widgetId: 'widget-1',
      startDate: null,
      endDate: null,
    } as any);

    expect(result).toEqual([nonCoreItem]);
    expect(StixCoreObjectDomain.stixCoreObjectsDistribution).toHaveBeenCalledTimes(1);
  });

  it('returns mainDistribution directly when there is no breakdownSelection', async () => {
    setupWidgetArgs([baseSelection]);
    vi.mocked(StixCoreObjectDomain.stixCoreObjectsDistribution).mockResolvedValue(
      [unknownItem, malwareItem] as any,
    );

    const result = await publicStixCoreObjectsDistribution(mockContext, {
      uriKey: 'test-key',
      widgetId: 'widget-1',
      startDate: null,
      endDate: null,
    } as any);

    expect(result).toEqual([unknownItem, malwareItem]);
    expect(StixCoreObjectDomain.stixCoreObjectsDistribution).toHaveBeenCalledTimes(1);
  });
});

// ── Tests: publicStixRelationshipsDistribution (lines 503-507) ───────────────

describe('publicStixRelationshipsDistribution', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the unknown item as-is when entity is null (no breakdown attempted)', async () => {
    setupWidgetArgs([baseSelection, { ...breakdownSelection, perspective: 'entities' }]);
    vi.mocked(StixRelationshipDomain.stixRelationshipsDistribution).mockResolvedValue(
      [unknownItem] as any,
    );

    const result = await publicStixRelationshipsDistribution(mockContext, {
      uriKey: 'test-key',
      widgetId: 'widget-1',
      startDate: null,
      endDate: null,
    } as any);

    expect(result).toEqual([unknownItem]);
    // stixRelationshipsDistribution called once (main only, no breakdown for null entity)
    expect(StixRelationshipDomain.stixRelationshipsDistribution).toHaveBeenCalledTimes(1);
  });

  it('returns a non-StixCoreObject entity item as-is (no breakdown attempted)', async () => {
    const markingItem = {
      label: 'marking-id-1',
      value: 2,
      entity: { id: 'marking-id-1', entity_type: 'Marking-Definition' },
    };
    setupWidgetArgs([baseSelection, { ...breakdownSelection, perspective: 'entities' }]);
    vi.mocked(StixRelationshipDomain.stixRelationshipsDistribution).mockResolvedValue(
      [markingItem] as any,
    );

    const result = await publicStixRelationshipsDistribution(mockContext, {
      uriKey: 'test-key',
      widgetId: 'widget-1',
      startDate: null,
      endDate: null,
    } as any);

    expect(result).toEqual([markingItem]);
    expect(StixRelationshipDomain.stixRelationshipsDistribution).toHaveBeenCalledTimes(1);
  });

  it('returns mainDistribution directly when there is no breakdownSelection', async () => {
    setupWidgetArgs([baseSelection]);
    vi.mocked(StixRelationshipDomain.stixRelationshipsDistribution).mockResolvedValue(
      [unknownItem] as any,
    );

    const result = await publicStixRelationshipsDistribution(mockContext, {
      uriKey: 'test-key',
      widgetId: 'widget-1',
      startDate: null,
      endDate: null,
    } as any);

    expect(result).toEqual([unknownItem]);
    expect(StixRelationshipDomain.stixRelationshipsDistribution).toHaveBeenCalledTimes(1);
  });
});
