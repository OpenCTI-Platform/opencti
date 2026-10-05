import { describe, expect, it } from 'vitest';
import {
  buildKpiFilters,
  buildSavedListFilters,
  buildSavedListIndicatorsLink,
  buildValidationCandidateFilters,
  canRemoveDeployment,
  canRetryDeployment,
  computeDeploymentKpis,
  DEFAULT_TEST_KINDS,
  DEPLOYMENT_STATUS_SEVERITIES,
  DEPLOYMENT_STATUSES,
  funnelShare,
  IOC_VALIDATION_MAX_INDICATORS,
  isHttpUrl,
  isLiveDeployment,
  isOpenRequest,
  isProvenValidation,
  periodStartDate,
  REQUEST_STATUS_SEVERITIES,
  SAVED_LISTS,
  selectValidationCandidates,
  sumStatuses,
  TEST_KINDS,
  toggleTestKind,
  VALIDATION_STATUS_SEVERITIES,
  VALIDATION_STATUSES,
} from './disseminationAssuranceUtils';

describe('dissemination assurance statuses', () => {
  it('should follow the backend contract of the deployed-on attributes', () => {
    expect(DEPLOYMENT_STATUSES).toEqual(['pending', 'deployed', 'active', 'failed', 'removed', 'expired']);
    expect(VALIDATION_STATUSES).toEqual(['not_requested', 'requested', 'detected', 'prevented', 'missed', 'error']);
  });

  it('should give a chip severity to every status', () => {
    DEPLOYMENT_STATUSES.forEach((status) => expect(DEPLOYMENT_STATUS_SEVERITIES[status]).toBeDefined());
    VALIDATION_STATUSES.forEach((status) => expect(VALIDATION_STATUS_SEVERITIES[status]).toBeDefined());
    expect(Object.keys(REQUEST_STATUS_SEVERITIES)).toHaveLength(9);
    expect(DEPLOYMENT_STATUS_SEVERITIES.failed).toEqual('critical');
    // Tones by meaning: a missed test is a failure, a rejected or timed out request needs attention
    expect(VALIDATION_STATUS_SEVERITIES.missed).toEqual('critical');
    expect(REQUEST_STATUS_SEVERITIES.rejected).toEqual('medium');
    expect(REQUEST_STATUS_SEVERITIES.expired).toEqual('medium');
  });

  it('should classify live, proven and open states', () => {
    expect(isLiveDeployment('deployed')).toBe(true);
    expect(isLiveDeployment('active')).toBe(true);
    expect(isLiveDeployment('pending')).toBe(false);
    expect(isLiveDeployment(null)).toBe(false);
    expect(isProvenValidation('detected')).toBe(true);
    expect(isProvenValidation('prevented')).toBe(true);
    expect(isProvenValidation('missed')).toBe(false);
    expect(isOpenRequest('awaiting_approval')).toBe(true);
    expect(isOpenRequest('completed')).toBe(false);
  });

  it('should only offer retry and removal when they make sense', () => {
    expect(canRetryDeployment('failed')).toBe(true);
    expect(canRetryDeployment('expired')).toBe(true);
    expect(canRetryDeployment('active')).toBe(false);
    expect(canRemoveDeployment('active', false)).toBe(true);
    expect(canRemoveDeployment('active', true)).toBe(false);
    expect(canRemoveDeployment('removed', false)).toBe(false);
    // Expired by the manager while the removal was never confirmed: it can still be withdrawn, once
    expect(canRemoveDeployment('expired', false)).toBe(true);
    expect(canRemoveDeployment('expired', true)).toBe(false);
  });
});

describe('IOC validation test kinds', () => {
  it('should default to DNS resolution only', () => {
    expect(DEFAULT_TEST_KINDS).toEqual(['dns_resolution']);
    expect(TEST_KINDS.find((kind) => kind.kind === 'dns_resolution')?.contactsInfrastructure).toBe(false);
    expect(TEST_KINDS.filter((kind) => kind.contactsInfrastructure).map((kind) => kind.kind)).toEqual(['http_head', 'network_traffic']);
  });

  it('should toggle test kinds and keep the catalog order', () => {
    expect(toggleTestKind(['dns_resolution'], 'dns_resolution')).toEqual([]);
    expect(toggleTestKind(['log_injection'], 'dns_resolution')).toEqual(['dns_resolution', 'log_injection']);
  });
});

describe('dissemination assurance saved lists', () => {
  const now = new Date('2026-10-03T10:00:00.000Z');

  it('should define the three lists of the plan', () => {
    expect(SAVED_LISTS.map((list) => list.id)).toEqual(['disseminated_not_deployed', 'deployed_never_validated', 'expired_still_deployed']);
  });

  it('should match indicators recorded by a connector without live deployment, including not yet backfilled ones', () => {
    const filters = buildSavedListFilters('disseminated_not_deployed', now);
    expect(filters.mode).toEqual('and');
    expect(filters.filters).toEqual([
      { key: 'deployments_count', values: ['0'], operator: 'gt', mode: 'or' },
      { key: 'revoked', values: ['false'], operator: 'eq', mode: 'or' },
    ]);
    expect(filters.filterGroups[0].mode).toEqual('or');
    expect(filters.filterGroups[0].filters.map((f) => f.operator)).toEqual(['eq', 'nil']);
  });

  it('should match live indicators without proof', () => {
    const filters = buildSavedListFilters('deployed_never_validated', now);
    expect(filters.filters).toEqual([{ key: 'deployment_platforms_count', values: ['0'], operator: 'gt', mode: 'or' }]);
    expect(filters.filterGroups[0].filters.map((f) => f.key)).toEqual(['validated_platforms_count', 'validated_platforms_count']);
  });

  it('should match revoked or expired indicators still live, or flagged expired after an unconfirmed removal', () => {
    const filters = buildSavedListFilters('expired_still_deployed', now);
    expect(filters.mode).toEqual('or');
    expect(filters.filters).toEqual([{ key: 'deployment_expired_count', values: ['0'], operator: 'gt', mode: 'or' }]);
    const stillLive = filters.filterGroups[0];
    expect(stillLive.mode).toEqual('and');
    expect(stillLive.filters).toEqual([{ key: 'deployment_platforms_count', values: ['0'], operator: 'gt', mode: 'or' }]);
    expect(stillLive.filterGroups[0].filters).toEqual([
      { key: 'revoked', values: ['true'], operator: 'eq', mode: 'or' },
      { key: 'valid_until', values: ['2026-10-03T10:00:00.000Z'], operator: 'lt', mode: 'or' },
    ]);
  });

  it('should open a list in the indicators screen with the same filters', () => {
    const link = buildSavedListIndicatorsLink('/dashboard/observations/indicators', 'expired_still_deployed', now);
    expect(link.startsWith('/dashboard/observations/indicators?filters=')).toBe(true);
    const encoded = link.split('?filters=')[1];
    expect(JSON.parse(decodeURIComponent(encoded))).toEqual(buildSavedListFilters('expired_still_deployed', now));
  });
});

describe('validation request candidate filters', () => {
  it('should query the unproven live deployments of a platform, in-flight validations and removals excluded', () => {
    const filters = buildValidationCandidateFilters('platform', 'platform-id', false);
    expect(filters.filters).toEqual([
      { key: 'relationship_type', values: ['deployed-on'], operator: 'eq', mode: 'or' },
      { key: 'toId', values: ['platform-id'], operator: 'eq', mode: 'or' },
      { key: 'deployment_status', values: ['deployed', 'active'], operator: 'eq', mode: 'or' },
      { key: 'revoked', values: ['false'], operator: 'eq', mode: 'or' },
    ]);
    expect(filters.filterGroups[0].mode).toEqual('or');
    expect(filters.filterGroups[0].filters).toEqual([
      { key: 'validation_status', values: ['not_requested', 'missed', 'error'], operator: 'eq', mode: 'or' },
      { key: 'validation_status', values: [], operator: 'nil', mode: 'or' },
    ]);
  });

  it('should query the proven live deployments of an indicator separately', () => {
    const filters = buildValidationCandidateFilters('indicator', 'indicator-id', true);
    expect(filters.filters[1]).toEqual({ key: 'fromId', values: ['indicator-id'], operator: 'eq', mode: 'or' });
    expect(filters.filters[3]).toEqual({ key: 'revoked', values: ['false'], operator: 'eq', mode: 'or' });
    expect(filters.filters[4]).toEqual({ key: 'validation_status', values: ['detected', 'prevented'], operator: 'eq', mode: 'or' });
    expect(filters.filterGroups).toEqual([]);
  });
});

describe('validation request candidates', () => {
  it('should keep live deployments, never proven first, without duplicates', () => {
    const ids = selectValidationCandidates([
      { indicatorId: 'a', platformId: 'p', deploymentStatus: 'active', validationStatus: 'detected' },
      { indicatorId: 'b', platformId: 'p', deploymentStatus: 'deployed', validationStatus: 'not_requested' },
      { indicatorId: 'c', platformId: 'p', deploymentStatus: 'failed', validationStatus: 'not_requested' },
      { indicatorId: 'b', platformId: 'p', deploymentStatus: 'active', validationStatus: 'missed' },
    ], false);
    expect(ids).toEqual(['b', 'a']);
  });

  it('should drop proven deployments when asked and bound the request size', () => {
    expect(selectValidationCandidates([
      { indicatorId: 'a', platformId: 'p', deploymentStatus: 'active', validationStatus: 'prevented' },
      { indicatorId: 'b', platformId: 'p', deploymentStatus: 'active', validationStatus: 'error' },
    ], true)).toEqual(['b']);
    const many = Array.from({ length: IOC_VALIDATION_MAX_INDICATORS + 50 }, (_, i) => ({
      indicatorId: `i${i}`,
      platformId: 'p',
      deploymentStatus: 'active',
      validationStatus: 'not_requested',
    }));
    expect(selectValidationCandidates(many, false)).toHaveLength(IOC_VALIDATION_MAX_INDICATORS);
  });
});

describe('dissemination assurance helpers', () => {
  it('should compute funnel shares with one decimal', () => {
    expect(funnelShare(1, 3)).toEqual(33.3);
    expect(funnelShare(5, 0)).toEqual(0);
  });

  it('should compute period start dates', () => {
    const now = new Date('2026-10-03T00:00:00.000Z');
    expect(periodStartDate('all', now)).toBeNull();
    expect(periodStartDate('7d', now)).toEqual('2026-09-26T00:00:00.000Z');
  });

  it('should only accept web links from OpenAEV', () => {
    expect(isHttpUrl('https://openaev.example.com/admin/simulations/1')).toBe(true);
    expect(isHttpUrl('http://localhost:8080')).toBe(true);
    expect(isHttpUrl('javascript:alert(1)')).toBe(false);
    expect(isHttpUrl('not a url')).toBe(false);
    expect(isHttpUrl(null)).toBe(false);
  });
});

describe('KPI strip', () => {
  const buckets = [{ status: 'deployed', count: 4 }, { status: 'active', count: 6 }, { status: 'failed', count: 2 }];

  it('should sum the status buckets, all of them or the given statuses', () => {
    expect(sumStatuses(buckets)).toEqual(12);
    expect(sumStatuses(buckets, ['active', 'failed'])).toEqual(8);
    expect(sumStatuses([], ['active'])).toEqual(0);
  });

  it('should filter the deployments of the selected counter, and none for all deployments', () => {
    const reported = { key: 'last_sync_at', values: [], operator: 'not_nil', mode: 'or' };
    expect(buildKpiFilters(null)).toBeUndefined();
    expect(buildKpiFilters('disseminated')?.filters).toEqual([reported]);
    expect(buildKpiFilters('deployed')?.filters).toEqual([{ key: 'deployment_status', values: ['deployed', 'active'], operator: 'eq', mode: 'or' }, reported]);
    expect(buildKpiFilters('active')?.filters[0].values).toEqual(['active']);
    expect(buildKpiFilters('validated')?.filters).toEqual([{ key: 'validation_status', values: ['detected', 'prevented'], operator: 'eq', mode: 'or' }, reported]);
    expect(buildKpiFilters('missed')?.filters).toEqual([{ key: 'validation_status', values: ['missed'], operator: 'eq', mode: 'or' }, reported]);
  });
});

describe('KPI strip key figures', () => {
  it('should count the deployments its filters list, from the status breakdowns', () => {
    const kpis = computeDeploymentKpis(
      [{ status: 'active', count: 4 }, { status: 'deployed', count: 2 }, { status: 'failed', count: 3 }, { status: 'removed', count: 1 }],
      [{ status: 'detected', count: 2 }, { status: 'prevented', count: 1 }, { status: 'missed', count: 2 }, { status: 'not_requested', count: 5 }],
    );
    expect(kpis).toEqual({ disseminated: 10, deployed: 6, active: 4, failed: 3, validated: 3, missed: 2 });
    expect(computeDeploymentKpis([], [])).toEqual({ disseminated: 0, deployed: 0, active: 0, failed: 0, validated: 0, missed: 0 });
  });
});
