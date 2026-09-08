/**
 * Unit tests for src/domain/log.ts
 *
 * Primary goal: exhaustive coverage of `computeAuditTypes` — the audit log-type
 * authorization helper that gates the security audit log (regression coverage for
 * "Audit Log Leak via Audit Aggregation Queries").
 *
 * Secondary goal: light coverage of every other exported function (findHistory,
 * findById, findAudits, findAuditById, auditsNumber, auditsTimeSeries,
 * auditsMultiTimeSeries, auditsDistribution) — asserting they wire arguments through
 * to the underlying database primitives and apply computeAuditTypes where relevant.
 *
 * All database primitives are mocked; these are pure unit tests.
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

const pageEntitiesConnection = vi.fn().mockResolvedValue({ edges: [] });
const storeLoadById = vi.fn().mockResolvedValue({ id: 'log-id' });

vi.mock('../../../src/database/middleware-loader', () => ({
  pageEntitiesConnection: (...args: any[]) => pageEntitiesConnection(...args),
  storeLoadById: (...args: any[]) => storeLoadById(...args),
}));

import {
  computeAuditTypes,
  findHistory,
  findById,
  findAudits,
  findAuditById,
  auditsNumber,
  auditsDistribution,
  auditsTimeSeries,
  auditsMultiTimeSeries,
} from '../../../src/domain/log';

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

  it('treats an empty requested-types array as "not provided" and falls back to defaults', () => {
    expect(computeAuditTypes(orgAdmin, [])).toEqual([ENTITY_TYPE_HISTORY]);
    expect(computeAuditTypes(securityUser, [])).toEqual([ENTITY_TYPE_ACTIVITY]);
  });

  it('treats null/undefined requested-types as "not provided" and falls back to defaults', () => {
    expect(computeAuditTypes(orgAdmin, null)).toEqual([ENTITY_TYPE_HISTORY]);
    expect(computeAuditTypes(securityUser, undefined)).toEqual([ENTITY_TYPE_ACTIVITY]);
  });

  it('throws ForbiddenAccess when the caller has neither audit capability', () => {
    expect(() => computeAuditTypes(noAuditUser)).toThrowError();
    expect(() => computeAuditTypes(noAuditUser, [ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY])).toThrowError();
  });

  it('ignores unknown requested types but keeps allowed ones', () => {
    expect(computeAuditTypes(knowledgeAndSecurityUser, ['Unknown', ENTITY_TYPE_ACTIVITY]))
      .toEqual(['Unknown', ENTITY_TYPE_ACTIVITY]);
  });
});

describe('findHistory', () => {
  it('queries History with historyFiltering and default ordering', async () => {
    await findHistory(context, orgAdmin, {});
    expect(pageEntitiesConnection).toHaveBeenCalledTimes(1);
    const [, , types, finalArgs] = pageEntitiesConnection.mock.calls[0];
    expect(types).toEqual([ENTITY_TYPE_HISTORY]);
    expect(finalArgs.historyFiltering).toBe(true);
    expect(finalArgs.orderBy).toBe('timestamp');
    expect(finalArgs.orderMode).toBe('desc');
  });

  it('keeps caller-provided ordering', async () => {
    await findHistory(context, orgAdmin, { orderBy: 'created_at' as any, orderMode: 'asc' as any });
    const [, , , finalArgs] = pageEntitiesConnection.mock.calls[0];
    expect(finalArgs.orderBy).toBe('created_at');
    expect(finalArgs.orderMode).toBe('asc');
  });
});

describe('findById', () => {
  it('loads a single History entry with historyFiltering', async () => {
    await findById(context, orgAdmin, 'log-1');
    expect(storeLoadById).toHaveBeenCalledTimes(1);
    const [, , logId, type, opts] = storeLoadById.mock.calls[0];
    expect(logId).toBe('log-1');
    expect(type).toBe(ENTITY_TYPE_HISTORY);
    expect(opts).toEqual({ historyFiltering: true });
  });
});

describe('findAudits — applies computeAuditTypes', () => {
  it('THE BUG: org admin requesting Activity is denied and does not query', () => {
    expect(() => findAudits(context, orgAdmin, { types: [ENTITY_TYPE_ACTIVITY] } as any)).toThrowError();
    expect(elPaginate).not.toHaveBeenCalled();
  });

  it('paginates the history index with the resolved types', async () => {
    await findAudits(context, securityUser, { types: [ENTITY_TYPE_ACTIVITY] } as any);
    expect(elPaginate).toHaveBeenCalledTimes(1);
    const [, , , finalArgs] = elPaginate.mock.calls[0];
    expect(finalArgs.types).toEqual([ENTITY_TYPE_ACTIVITY]);
    expect(finalArgs.historyFiltering).toBe(true);
  });
});

describe('findAuditById — applies computeAuditTypes', () => {
  it('loads with both types resolved for a fully-capable user', async () => {
    await findAuditById(context, knowledgeAndSecurityUser, 'audit-1');
    expect(storeLoadById).toHaveBeenCalledTimes(1);
    const [, , auditId, types, opts] = storeLoadById.mock.calls[0];
    expect(auditId).toBe('audit-1');
    expect(types).toEqual([ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY]);
    expect(opts).toEqual({ historyFiltering: true });
  });

  it('narrows to History-only for a knowledge-only user', async () => {
    await findAuditById(context, orgAdmin, 'audit-1');
    const [, , , types] = storeLoadById.mock.calls[0];
    expect(types).toEqual([ENTITY_TYPE_HISTORY]);
  });

  it('throws ForbiddenAccess and does not load for a user with no audit capability', async () => {
    await expect(findAuditById(context, noAuditUser, 'audit-1')).rejects.toThrowError();
    expect(storeLoadById).not.toHaveBeenCalled();
  });
});

describe('auditsNumber — applies computeAuditTypes', () => {
  it('forwards the resolved types to elCount and does not trust caller types for an org admin', async () => {
    await auditsNumber(context, orgAdmin, { field: 'context_data.message' });
    expect(elCount).toHaveBeenCalledTimes(2);
    const [, , , finalArgs] = elCount.mock.calls[0];
    expect(finalArgs.types).toEqual([ENTITY_TYPE_HISTORY]);
    // total drops the endDate bound
    const [, , , totalArgs] = elCount.mock.calls[1];
    expect(totalArgs.endDate).toBeUndefined();
  });

  it('THE BUG (unique/cardinality path): org admin requesting Activity is denied', () => {
    expect(() => auditsNumber(context, orgAdmin, { unique: true, field: 'context_data.message', types: [ENTITY_TYPE_ACTIVITY] }))
      .toThrowError();
    expect(elCardinalityCount).not.toHaveBeenCalled();
  });

  it('forwards Activity to elCardinalityCount for an authorized security user', async () => {
    await auditsNumber(context, securityUser, { unique: true, field: 'context_data.message', types: [ENTITY_TYPE_ACTIVITY] });
    expect(elCardinalityCount).toHaveBeenCalledTimes(2);
    const [, , , field, finalArgs] = elCardinalityCount.mock.calls[0];
    expect(field).toBe('context_data.message');
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
    expect(finalArgs.historyFiltering).toBe(true);
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

  it('adds a user filter when a userId is provided', async () => {
    await auditsTimeSeries(context, securityUser, { types: [ENTITY_TYPE_ACTIVITY], userId: 'user-42', filters: null });
    const [, , finalArgs] = timeSeriesHistory.mock.calls[0];
    // addFilter builds a filter group targeting the user id on the *_id key
    expect(JSON.stringify(finalArgs.filters)).toContain('user-42');
    expect(JSON.stringify(finalArgs.filters)).toContain('*_id');
  });
});

describe('auditsMultiTimeSeries — applies computeAuditTypes per series', () => {
  it('THE BUG: a per-series Activity request from an org admin is denied', () => {
    expect(() => auditsMultiTimeSeries(context, orgAdmin, {
      timeSeriesParameters: [{ types: [ENTITY_TYPE_HISTORY] }, { types: [ENTITY_TYPE_ACTIVITY] }],
    })).toThrowError();
  });

  it('resolves types independently for each series', async () => {
    const series = await auditsMultiTimeSeries(context, knowledgeAndSecurityUser, {
      timeSeriesParameters: [{ types: [ENTITY_TYPE_HISTORY] }, { types: [ENTITY_TYPE_ACTIVITY] }],
    });
    await Promise.all(series.map((s: any) => s.data));
    expect(timeSeriesHistory).toHaveBeenCalledTimes(2);
    expect(timeSeriesHistory.mock.calls[0][2].types).toEqual([ENTITY_TYPE_HISTORY]);
    expect(timeSeriesHistory.mock.calls[1][2].types).toEqual([ENTITY_TYPE_ACTIVITY]);
  });
});
