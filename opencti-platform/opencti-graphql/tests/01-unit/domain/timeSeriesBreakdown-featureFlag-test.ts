/**
 * The time series breakdowns are behind the TIME_SERIES_BREAKDOWN feature flag: besides the @ff directive of their
 * queries, their domain entry points refuse to run without it. The public breakdowns go through the same entry points.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as middleware from '../../../src/database/middleware';
import { ENABLED_FEATURE_FLAGS, TIME_SERIES_BREAKDOWN_FEATURE_FLAG } from '../../../src/config/conf';
import { stixCoreObjectsTimeSeriesBreakdown } from '../../../src/domain/stixCoreObject';
import { stixRelationshipsTimeSeriesBreakdown } from '../../../src/domain/stixRelationship';
import { auditsTimeSeriesBreakdown } from '../../../src/domain/log';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const context = {} as AuthContext;
const user = { capabilities: [{ name: 'KNOWLEDGE' }, { name: 'SETTINGS_SECURITYACTIVITY' }] } as unknown as AuthUser;
const args = { field: 'entity_type', startDate: '2026-01-01T00:00:00.000Z', interval: 'day' };

const breakdowns = [
  { name: 'stixCoreObjectsTimeSeriesBreakdown', breakDown: () => stixCoreObjectsTimeSeriesBreakdown(context, user, args), core: 'timeSeriesBreakdownEntities' },
  { name: 'stixRelationshipsTimeSeriesBreakdown', breakDown: () => stixRelationshipsTimeSeriesBreakdown(context, user, args), core: 'timeSeriesBreakdownRelations' },
  { name: 'auditsTimeSeriesBreakdown', breakDown: () => auditsTimeSeriesBreakdown(context, user, args as never), core: 'timeSeriesBreakdownHistory' },
] as const;

describe('time series breakdown feature flag', () => {
  const previousEnabledFeatureFlags = [...ENABLED_FEATURE_FLAGS];

  beforeEach(() => {
    breakdowns.forEach(({ core }) => vi.spyOn(middleware, core).mockResolvedValue({ truncated: false, dates: [], series: [] }));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, ...previousEnabledFeatureFlags);
  });

  it.each(breakdowns)('$name should refuse to break down without the flag, before querying', async ({ breakDown, core }) => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
    await expect(async () => breakDown()).rejects.toThrow('Feature is disabled');
    expect(middleware[core]).not.toHaveBeenCalled();
  });

  it.each(breakdowns)('$name should break down with the flag', async ({ breakDown, core }) => {
    ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length, TIME_SERIES_BREAKDOWN_FEATURE_FLAG);
    await breakDown();
    expect(middleware[core]).toHaveBeenCalledTimes(1);
  });
});
