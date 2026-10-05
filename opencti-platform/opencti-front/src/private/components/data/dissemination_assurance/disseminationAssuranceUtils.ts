import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

export const PATH_DISSEMINATION_ASSURANCE = '/dashboard/defense/assurance';

/** The pages of the area, in order: the Defense hub shows them as tabs and names the open one in the breadcrumb. */
export const DISSEMINATION_ASSURANCE_SECTIONS = [
  { path: 'overview', label: 'Overview' },
  { path: 'lists', label: 'Lists' },
  { path: 'validations', label: 'Validation requests' },
] as const;

export type DisseminationAssuranceSectionPath = typeof DISSEMINATION_ASSURANCE_SECTIONS[number]['path'];
export const PATH_DISSEMINATION_ASSURANCE_OVERVIEW = `${PATH_DISSEMINATION_ASSURANCE}/overview`;
export const PATH_DISSEMINATION_ASSURANCE_LISTS = `${PATH_DISSEMINATION_ASSURANCE}/lists`;
export const PATH_DISSEMINATION_ASSURANCE_VALIDATIONS = `${PATH_DISSEMINATION_ASSURANCE}/validations`;

export const RELATION_DEPLOYED_ON = 'deployed-on';

export type DeploymentStatus = 'pending' | 'deployed' | 'active' | 'failed' | 'removed' | 'expired';
export type ValidationStatus = 'not_requested' | 'requested' | 'detected' | 'prevented' | 'missed' | 'error';
export type IocValidationTestKind = 'dns_resolution' | 'network_traffic' | 'http_head' | 'file_drop' | 'log_injection';
export type IocValidationRequestStatus = 'pending' | 'sent' | 'awaiting_approval' | 'running' | 'completed' | 'partial' | 'failed' | 'rejected' | 'expired';
export type ChipSeverity = 'neutral' | 'info' | 'low' | 'medium' | 'high' | 'critical';

export const DEPLOYMENT_STATUSES: DeploymentStatus[] = ['pending', 'deployed', 'active', 'failed', 'removed', 'expired'];
export const LIVE_DEPLOYMENT_STATUSES: DeploymentStatus[] = ['deployed', 'active'];
export const VALIDATION_STATUSES: ValidationStatus[] = ['not_requested', 'requested', 'detected', 'prevented', 'missed', 'error'];
export const PROVEN_VALIDATION_STATUSES: ValidationStatus[] = ['detected', 'prevented'];
export const OPEN_REQUEST_STATUSES: IocValidationRequestStatus[] = ['pending', 'sent', 'awaiting_approval', 'running'];

// Limits enforced by indicatorsRequestValidation (one OpenAEV scenario, one approval).
export const IOC_VALIDATION_MAX_INDICATORS = 200;
export const IOC_VALIDATION_MAX_PLATFORMS = 10;

export const DEPLOYMENT_STATUS_SEVERITIES: Record<DeploymentStatus, ChipSeverity> = {
  pending: 'neutral',
  deployed: 'info',
  active: 'low',
  failed: 'critical',
  removed: 'neutral',
  expired: 'medium',
};

export const VALIDATION_STATUS_SEVERITIES: Record<ValidationStatus, ChipSeverity> = {
  not_requested: 'neutral',
  requested: 'info',
  detected: 'low',
  prevented: 'low',
  missed: 'critical',
  error: 'critical',
};

export const REQUEST_STATUS_SEVERITIES: Record<IocValidationRequestStatus, ChipSeverity> = {
  pending: 'neutral',
  sent: 'info',
  awaiting_approval: 'medium',
  running: 'info',
  completed: 'low',
  partial: 'medium',
  failed: 'critical',
  rejected: 'medium',
  expired: 'medium',
};

export interface TestKindDefinition {
  kind: IocValidationTestKind;
  label: string;
  description: string;
  // Test kinds that can reach the network or write on the endpoint need an explicit allow-list entry in OpenAEV.
  contactsInfrastructure: boolean;
}

export const TEST_KINDS: TestKindDefinition[] = [
  {
    kind: 'dns_resolution',
    label: 'DNS resolution',
    description: 'Resolves domain names and hostnames, never connects to them.',
    contactsInfrastructure: false,
  },
  {
    kind: 'http_head',
    label: 'HTTP HEAD through the egress proxy',
    description: 'Sends a HEAD request for URLs through the egress proxy configured in OpenAEV.',
    contactsInfrastructure: true,
  },
  {
    kind: 'network_traffic',
    label: 'Network connection (safe mode)',
    description: 'Opens and immediately closes a TCP connection to IP addresses, or to the sinkhole configured in OpenAEV.',
    contactsInfrastructure: true,
  },
  {
    kind: 'file_drop',
    label: 'Benign file surrogate',
    description: 'Drops a harmless file carrying the name of the file indicator, then removes it.',
    contactsInfrastructure: false,
  },
  {
    kind: 'log_injection',
    label: 'Log injection',
    description: 'Writes a benign log line containing the indicator value (hashes and other values).',
    contactsInfrastructure: false,
  },
];

export const DEFAULT_TEST_KINDS: IocValidationTestKind[] = ['dns_resolution'];

export const isDeploymentStatus = (value: unknown): value is DeploymentStatus => DEPLOYMENT_STATUSES.includes(value as DeploymentStatus);
export const isValidationStatus = (value: unknown): value is ValidationStatus => VALIDATION_STATUSES.includes(value as ValidationStatus);
export const isLiveDeployment = (status: string | null | undefined) => LIVE_DEPLOYMENT_STATUSES.includes(status as DeploymentStatus);
export const isProvenValidation = (status: string | null | undefined) => PROVEN_VALIDATION_STATUSES.includes(status as ValidationStatus);
export const isOpenRequest = (status: string | null | undefined) => OPEN_REQUEST_STATUSES.includes(status as IocValidationRequestStatus);

/** A deployment can be retried when the platform does not hold it (or holds it in error). */
export const canRetryDeployment = (status: string | null | undefined) => ['failed', 'removed', 'expired'].includes(status ?? '');
/**
 * A deployment can be withdrawn while it is (or is about to be) on the platform, including an expired one whose
 * removal the platform never confirmed, until a withdrawal is already requested (revoked relationship).
 */
export const canRemoveDeployment = (status: string | null | undefined, revoked?: boolean | null) => !revoked && ['pending', 'deployed', 'active', 'failed', 'expired'].includes(status ?? '');

export const toggleTestKind = (selected: IocValidationTestKind[], kind: IocValidationTestKind): IocValidationTestKind[] => {
  if (selected.includes(kind)) {
    return selected.filter((k) => k !== kind);
  }
  return TEST_KINDS.map((definition) => definition.kind).filter((k) => k === kind || selected.includes(k));
};

/** Links coming from OpenAEV are rendered only when they are plain web links (no javascript: or data: URI). */
export const isHttpUrl = (value: string | null | undefined) => {
  if (!value) return false;
  try {
    const { protocol } = new URL(value);
    return protocol === 'http:' || protocol === 'https:';
  } catch {
    return false;
  }
};

export type Period = 'all' | '7d' | '30d' | '90d' | '1y';
const PERIOD_DAYS: Record<Exclude<Period, 'all'>, number> = { '7d': 7, '30d': 30, '90d': 90, '1y': 365 };

/** Start of the dashboard period (indicators and deployments created since), null for all time. */
export const periodStartDate = (period: Period, now: Date = new Date()) => {
  if (period === 'all') return null;
  return new Date(now.getTime() - PERIOD_DAYS[period] * 24 * 3600 * 1000).toISOString();
};

/** Percentage of a stage relative to the first stage of the funnel, one decimal. */
export const funnelShare = (value: number, reference: number) => (reference > 0 ? Math.round((value / reference) * 1000) / 10 : 0);

export const DISSEMINATION_ASSURANCE_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/dissemination-assurance/';

/** Total of the status buckets of the metrics, restricted to some statuses when given. */
export const sumStatuses = (buckets: ReadonlyArray<{ status: string; count: number }>, statuses?: string[]) => buckets
  .filter((bucket) => !statuses || statuses.includes(bucket.status))
  .reduce((total, bucket) => total + bucket.count, 0);

export type KpiId = 'disseminated' | 'deployed' | 'active' | 'validated' | 'missed';

export interface DeploymentKpis {
  disseminated: number;
  deployed: number;
  active: number;
  failed: number;
  validated: number;
  missed: number;
}

/**
 * Key figures of the KPI strip. They count deployments (one per indicator and security platform) from the status
 * breakdowns, which use the same period and platform as the deployments listed under the strip, so a counter always
 * equals the number of deployments its filter shows (see buildKpiFilters).
 */
export const computeDeploymentKpis = (
  deploymentStatuses: ReadonlyArray<{ status: string; count: number }>,
  validationStatuses: ReadonlyArray<{ status: string; count: number }>,
): DeploymentKpis => ({
  disseminated: sumStatuses(deploymentStatuses),
  deployed: sumStatuses(deploymentStatuses, LIVE_DEPLOYMENT_STATUSES),
  active: sumStatuses(deploymentStatuses, ['active']),
  failed: sumStatuses(deploymentStatuses, ['failed']),
  validated: sumStatuses(validationStatuses, PROVEN_VALIDATION_STATUSES),
  missed: sumStatuses(validationStatuses, ['missed']),
});

const reportedFilter = { key: 'last_sync_at', values: [], operator: 'not_nil', mode: 'or' };

// The status breakdowns count reported deployments only, so every counter filter keeps the same restriction.
const statusFilter = (key: string, values: string[]): FilterGroup => ({
  mode: 'and',
  filters: [{ key, values, operator: 'eq', mode: 'or' }, reportedFilter],
  filterGroups: [],
});

/**
 * Deployments shown under the KPI strip for the selected counter, every deployment without selection.
 * Counters count the deployments a connector reported: a hand-recorded pending one is out.
 */
export const buildKpiFilters = (kpi: KpiId | null): FilterGroup | undefined => {
  switch (kpi) {
    case 'disseminated':
      return { mode: 'and', filters: [reportedFilter], filterGroups: [] };
    case 'deployed':
      return statusFilter('deployment_status', LIVE_DEPLOYMENT_STATUSES);
    case 'active':
      return statusFilter('deployment_status', ['active']);
    case 'validated':
      return statusFilter('validation_status', PROVEN_VALIDATION_STATUSES);
    case 'missed':
      return statusFilter('validation_status', ['missed']);
    default:
      return undefined;
  }
};

// region saved lists
export type SavedListId = 'disseminated_not_deployed' | 'deployed_never_validated' | 'expired_still_deployed';

export interface SavedListDefinition {
  id: SavedListId;
  label: string;
  description: string;
}

export const SAVED_LISTS: SavedListDefinition[] = [
  {
    id: 'disseminated_not_deployed',
    label: 'Disseminated but not deployed',
    description: 'Indicators recorded by a stream connector that no security platform reports as live.',
  },
  {
    id: 'deployed_never_validated',
    label: 'Deployed but never validated',
    description: 'Indicators live on at least one security platform without any detection or prevention proof.',
  },
  {
    id: 'expired_still_deployed',
    label: 'Expired but still deployed',
    description: 'Revoked or expired indicators still live on a security platform, or whose removal was never confirmed.',
  },
];

const filter = (key: string, values: unknown[], operator = 'eq', mode = 'or') => ({ key, values, operator, mode });
// Indicators created before dissemination assurance may not carry the counter until the background backfill reaches them.
const noLiveDeployment = (): FilterGroup => ({
  mode: 'or',
  filters: [filter('deployment_platforms_count', ['0']), filter('deployment_platforms_count', [], 'nil')],
  filterGroups: [],
}) as FilterGroup;
const hasLiveDeployment = () => filter('deployment_platforms_count', ['0'], 'gt');

/**
 * Filters of the saved lists, aligned with the lifecycle funnel of disseminationAssuranceMetrics:
 * disseminated = recorded on a security platform by a stream connector, whatever the outcome;
 * expired still deployed = revoked or past valid_until while live, or removal never confirmed (flagged expired).
 */
export const buildSavedListFilters = (id: SavedListId, now: Date = new Date()): FilterGroup => {
  switch (id) {
    case 'disseminated_not_deployed':
      return {
        mode: 'and',
        filters: [filter('deployments_count', ['0'], 'gt'), filter('revoked', ['false'])],
        filterGroups: [noLiveDeployment()],
      } as FilterGroup;
    case 'deployed_never_validated':
      return {
        mode: 'and',
        filters: [hasLiveDeployment()],
        filterGroups: [{
          mode: 'or',
          filters: [filter('validated_platforms_count', ['0']), filter('validated_platforms_count', [], 'nil')],
          filterGroups: [],
        }],
      } as FilterGroup;
    case 'expired_still_deployed':
    default:
      return {
        mode: 'or',
        filters: [filter('deployment_expired_count', ['0'], 'gt')],
        filterGroups: [{
          mode: 'and',
          filters: [hasLiveDeployment()],
          filterGroups: [{
            mode: 'or',
            filters: [filter('revoked', ['true']), filter('valid_until', [now.toISOString()], 'lt')],
            filterGroups: [],
          }],
        }],
      } as FilterGroup;
  }
};

/** Same filter group as the saved list, so a list opens in the Indicators screen with every tool of that screen. */
export const buildSavedListIndicatorsLink = (indicatorsPath: string, id: SavedListId, now: Date = new Date()) => {
  return `${indicatorsPath}?filters=${encodeURIComponent(JSON.stringify(buildSavedListFilters(id, now)))}`;
};
// endregion

// region validation request candidates
export interface DeploymentCandidate {
  indicatorId: string;
  platformId: string;
  deploymentStatus?: string | null;
  validationStatus?: string | null;
}

// Outcomes a new request can (re)validate; `requested` deployments are awaiting another request.
export const RETRYABLE_VALIDATION_STATUSES: ValidationStatus[] = ['not_requested', 'missed', 'error'];

/**
 * Live deployments of an indicator or a security platform that a new validation request can include,
 * validations in flight and deployments awaiting removal (revoked) excluded: the unproven ones (retryable or
 * never set), or the proven ones. Applied by the API before pagination, so the request limit is filled with
 * deployments the request accepts, unproven first.
 */
export const buildValidationCandidateFilters = (side: 'indicator' | 'platform', entityId: string, proven: boolean): FilterGroup => ({
  mode: 'and',
  filters: [
    filter('relationship_type', [RELATION_DEPLOYED_ON]),
    filter(side === 'indicator' ? 'fromId' : 'toId', [entityId]),
    filter('deployment_status', LIVE_DEPLOYMENT_STATUSES),
    filter('revoked', ['false']),
    ...(proven ? [filter('validation_status', PROVEN_VALIDATION_STATUSES)] : []),
  ],
  filterGroups: proven ? [] : [{
    mode: 'or',
    filters: [filter('validation_status', RETRYABLE_VALIDATION_STATUSES), filter('validation_status', [], 'nil')],
    filterGroups: [],
  }],
}) as FilterGroup;

/**
 * Indicators to validate on a platform: live deployments first, never proven first, bounded by the request limit.
 * Input order (most recently synchronized first) is kept inside each group.
 */
export const selectValidationCandidates = (candidates: DeploymentCandidate[], onlyNotProven: boolean) => {
  const live = candidates.filter((c) => isLiveDeployment(c.deploymentStatus));
  const eligible = onlyNotProven ? live.filter((c) => !isProvenValidation(c.validationStatus)) : live;
  const notProven = eligible.filter((c) => !isProvenValidation(c.validationStatus));
  const proven = eligible.filter((c) => isProvenValidation(c.validationStatus));
  const ids = [...notProven, ...proven].map((c) => c.indicatorId);
  return [...new Set(ids)].slice(0, IOC_VALIDATION_MAX_INDICATORS);
};
// endregion
