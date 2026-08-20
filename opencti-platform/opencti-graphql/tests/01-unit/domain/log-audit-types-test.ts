/**
 * Security unit tests — Audit aggregation log-type authorization
 *
 * Regression coverage for the "Audit Log Leak via Audit Aggregation Queries" fix.
 *
 * Root cause: auditsDistribution / auditsNumber / auditsTimeSeries / auditsMultiTimeSeries
 * forwarded the caller-supplied `types` straight to the search engine without checking that
 * the caller may read that log type. An organization administrator (VIRTUAL_ORGANIZATION_ADMIN)
 * without SETTINGS_SECURITYACTIVITY could request types: ["Activity"] and read the security audit log.
 *
 * The fix extracts the type-resolution logic into `computeAuditTypes` and applies it in every
 * aggregation resolver. These tests assert:
 *  - computeAuditTypes strips types the caller is not authorized for and throws ForbiddenAccess when nothing remains
 *  - each aggregation resolver applies computeAuditTypes (passes the resolved types down / throws for org admins)
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

// ─── DB / External mocks (only what cannot run without infrastructure) ────────
const elCount = vi.fn().mockResolvedValue(0);
const elCardinalityCount = vi.fn().mockResolvedValue(0);
const elPaginate = vi.fn().mockResolvedValue({ edges: [] });

vi.mock('../../../src/database/engine', () => ({
  elCount: (...args: any[]) => elCount(...args),
  elCardinalityCount: (...args: any[]) => elCardinalityCount(...args),
  elPaginate: (...args: any[]) => elPaginate(...args),
}));

const distributionHistory = vi.fn().mockResolvedValue([]);
const timeSeriesHistory = vi.fn().mockResolvedValue([]);

vi.mock('../../../src/database/middleware', () => ({
  distributionHistory: (...args: any[]) => distributionHistory(...args),
  timeSeriesHistory: (...args: any[]) => timeSeriesHistory(...args),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  pageEntitiesConnection: vi.fn().mockResolvedValue({ edges: [] }),
  storeLoadById: vi.fn().mockResolvedValue({}),
}));

import { computeAuditTypes, auditsNumber, auditsDistribution, auditsTimeSeries, auditsMultiTimeSeries } from '../../../src/domain/log';

import type { AuthContext, AuthUser } from '../../../src/types/user';

const ENTITY_TYPE_ACTIVITY = 'Activity';
const ENTITY_TYPE_HISTORY = 'History';

const buildUser = (capabilityNames: string[]): AuthUser => ({
  capabilities: capabilityNames.map((name) => ({ name })),
} as unknown as AuthUser);

// Non-bypass users mirroring the vulnerability scenario
const orgAdmin = buildUser(['KNOWLEDGE_KNUPDATE', 'VIRTUAL_ORGANIZATION_ADMIN']); // no SETTINGS_SECURITYACTIVITY
const securityUser = buildUser(['SETTINGS_SECURITYACTIVITY']);
const knowledgeAndSecurityUser = buildUser(['KNOWLEDGE_KNUPDATE', 'SETTINGS_SECURITYACTIVITY']);
const noAuditUser = buildUser(['SOME_OTHER_CAPABILITY']);

const context = {} as AuthContext;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('computeAuditTypes — audit log-type authorization', () => {
  it('defaults to History for a knowledge user without security activity capability', () => {
    expect(computeAuditTypes(orgAdmin)).toEqual([ENTITY_TYPE_HISTORY]);
  });

  it('defaults to Activity for a security activity user', () => {
    expect(computeAuditTypes(securityUser)).toEqual([ENTITY_TYPE_ACTIVITY]);
  });

  it('THE BUG: an org admin requesting Activity is denied (Activity stripped -> ForbiddenAccess)', () => {
    expect(() => computeAuditTypes(orgAdmin, [ENTITY_TYPE_ACTIVITY])).toThrowError();
  });

  it('strips Activity but keeps History when an org admin requests both', () => {
    expect(computeAuditTypes(orgAdmin, [ENTITY_TYPE_HISTORY, ENTITY_TYPE_ACTIVITY])).toEqual([ENTITY_TYPE_HISTORY]);
  });

  it('allows Activity for a security activity user that requests it', () => {
    expect(computeAuditTypes(securityUser, [ENTITY_TYPE_ACTIVITY])).toEqual([ENTITY_TYPE_ACTIVITY]);
  });

  it('keeps both types for a user with knowledge + security activity', () => {
    expect(computeAuditTypes(knowledgeAndSecurityUser, [ENTITY_TYPE_HISTORY, ENTITY_TYPE_ACTIVITY]))
      .toEqual([ENTITY_TYPE_HISTORY, ENTITY_TYPE_ACTIVITY]);
  });

  it('strips History when the caller has no KNOWLEDGE capability', () => {
    expect(computeAuditTypes(securityUser, [ENTITY_TYPE_HISTORY, ENTITY_TYPE_ACTIVITY])).toEqual([ENTITY_TYPE_ACTIVITY]);
  });

  it('throws ForbiddenAccess when the caller has neither audit capability', () => {
    expect(() => computeAuditTypes(noAuditUser)).toThrowError();
    expect(() => computeAuditTypes(noAuditUser, [ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY])).toThrowError();
  });
});

describe('auditsNumber — applies computeAuditTypes', () => {
  it('forwards the resolved types to elCount and does not trust caller types for an org admin', async () => {
    await auditsNumber(context, orgAdmin, { field: 'context_data.message' });
    expect(elCount).toHaveBeenCalledTimes(2);
    const [, , , finalArgs] = elCount.mock.calls[0];
    expect(finalArgs.types).toEqual([ENTITY_TYPE_HISTORY]);
  });

  it('THE BUG (unique/cardinality path): org admin requesting Activity is denied', () => {
    expect(() => auditsNumber(context, orgAdmin, { unique: true, field: 'context_data.message', types: [ENTITY_TYPE_ACTIVITY] }))
      .toThrowError();
    expect(elCardinalityCount).not.toHaveBeenCalled();
  });

  it('forwards Activity to elCardinalityCount for an authorized security user', async () => {
    await auditsNumber(context, securityUser, { unique: true, field: 'context_data.message', types: [ENTITY_TYPE_ACTIVITY] });
    expect(elCardinalityCount).toHaveBeenCalledTimes(2);
    const [, , , , finalArgs] = elCardinalityCount.mock.calls[0];
    expect(finalArgs.types).toEqual([ENTITY_TYPE_ACTIVITY]);
  });
});

describe('auditsDistribution — applies computeAuditTypes', () => {
  it('THE BUG: org admin distribution over Activity is denied', async () => {
    await expect(auditsDistribution(context, orgAdmin, { field: 'context_data.message', types: [ENTITY_TYPE_ACTIVITY] }))
      .rejects.toThrowError();
    expect(distributionHistory).not.toHaveBeenCalled();
  });

  it('forwards resolved Activity types to distributionHistory for a security user', async () => {
    await auditsDistribution(context, securityUser, { field: 'context_data.message', types: [ENTITY_TYPE_ACTIVITY] });
    expect(distributionHistory).toHaveBeenCalledTimes(1);
    const [, , finalArgs] = distributionHistory.mock.calls[0];
    expect(finalArgs.types).toEqual([ENTITY_TYPE_ACTIVITY]);
  });
});

describe('auditsTimeSeries — applies computeAuditTypes', () => {
  it('THE BUG: org admin time series over Activity is denied', () => {
    expect(() => auditsTimeSeries(context, orgAdmin, { types: [ENTITY_TYPE_ACTIVITY] })).toThrowError();
    expect(timeSeriesHistory).not.toHaveBeenCalled();
  });

  it('forwards resolved types to timeSeriesHistory', async () => {
    await auditsTimeSeries(context, securityUser, { types: [ENTITY_TYPE_ACTIVITY] });
    expect(timeSeriesHistory).toHaveBeenCalledTimes(1);
    const [, , finalArgs] = timeSeriesHistory.mock.calls[0];
    expect(finalArgs.types).toEqual([ENTITY_TYPE_ACTIVITY]);
  });
});

describe('auditsMultiTimeSeries — applies computeAuditTypes per series', () => {
  it('THE BUG: a per-series Activity request from an org admin is denied', () => {
    expect(() => auditsMultiTimeSeries(context, orgAdmin, {
      timeSeriesParameters: [{ types: [ENTITY_TYPE_HISTORY] }, { types: [ENTITY_TYPE_ACTIVITY] }],
    })).toThrowError();
  });

  it('resolves types independently for each series', async () => {
    await Promise.all(await auditsMultiTimeSeries(context, knowledgeAndSecurityUser, {
      timeSeriesParameters: [{ types: [ENTITY_TYPE_HISTORY] }, { types: [ENTITY_TYPE_ACTIVITY] }],
    }).then((series: any[]) => series.map((s) => s.data)));
    expect(timeSeriesHistory).toHaveBeenCalledTimes(2);
    expect(timeSeriesHistory.mock.calls[0][2].types).toEqual([ENTITY_TYPE_HISTORY]);
    expect(timeSeriesHistory.mock.calls[1][2].types).toEqual([ENTITY_TYPE_ACTIVITY]);
  });
});
