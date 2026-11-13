import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../../types/store';
import { logApp } from '../../../config/conf';
import { elRawUpdateByQuery } from '../../../database/engine';
import { fullRelationsList, storeLoadById } from '../../../database/middleware-loader';
import { READ_INDEX_STIX_CYBER_OBSERVABLES, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../../database/utils';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../../schema/general';
import { isStixCoreRelationship } from '../../../schema/stixCoreRelationship';
import { HUNT_MANAGER_USER } from '../../../utils/access';
import { truncate } from '../hunt-utils';
import {
  type BasicStoreEntityHuntRun,
  HUNT_IOC_HOSTS_MAX,
  HUNT_IOC_VERDICT_NOT_SEARCHED,
  HUNT_IOC_VERDICT_NOT_SEEN,
  HUNT_IOC_VERDICT_PENDING,
  HUNT_IOC_VERDICT_SEEN,
  HUNT_RUN_STATUS_COMPLETED,
  type HuntIocResult,
} from './huntRun-types';

const HOST_MAX_LENGTH = 256;
const REASON_MAX_LENGTH = 512;
// Relationship of the dissemination assurance (Indicator -> Security Platform), registered once that module is installed
export const RELATION_DEPLOYED_ON = 'deployed-on';

export interface HuntIocResultInputLike {
  key?: string | null;
  searched?: boolean | null;
  seen?: boolean | null;
  hits_count?: number | null;
  first_seen?: string | Date | null;
  last_seen?: string | Date | null;
  hosts?: (string | null)[] | null;
  reason?: string | null;
}

const toIsoDate = (value: string | Date | null | undefined): string | null => {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

const sanitizeHosts = (hosts: (string | null)[] | null | undefined) => {
  const unique = new Set<string>();
  (hosts ?? []).forEach((host) => {
    const trimmed = typeof host === 'string' ? host.trim() : '';
    if (trimmed.length > 0 && unique.size < HUNT_IOC_HOSTS_MAX) {
      unique.add(truncate(trimmed, HOST_MAX_LENGTH));
    }
  });
  return Array.from(unique);
};

/**
 * The values of a run as its connector reported them: only the values the run was dispatched with are kept, whatever
 * the connector sent; a value the report leaves out was not searched.
 */
export const mergeHuntIocResults = (stored: HuntIocResult[], reported: HuntIocResultInputLike[]): HuntIocResult[] => {
  const byKey = new Map<string, HuntIocResultInputLike>();
  reported.forEach((item) => {
    if (typeof item.key === 'string' && item.key.length > 0) {
      byKey.set(item.key, item);
    }
  });
  return stored.map((result) => {
    const report = byKey.get(result.key);
    if (!report) {
      return { ...result, verdict: HUNT_IOC_VERDICT_NOT_SEARCHED, hits_count: 0, hosts: [], reason: 'The connector did not report this value' };
    }
    if (report.searched === false) {
      const reason = typeof report.reason === 'string' && report.reason.trim().length > 0 ? report.reason.trim() : 'The platform cannot look up this type of value';
      return { ...result, verdict: HUNT_IOC_VERDICT_NOT_SEARCHED, hits_count: 0, hosts: [], reason: truncate(reason, REASON_MAX_LENGTH) };
    }
    const hits = Math.max(0, Math.round(Number(report.hits_count ?? 0)) || 0);
    const seen = report.seen === true || hits > 0;
    return {
      ...result,
      verdict: seen ? HUNT_IOC_VERDICT_SEEN : HUNT_IOC_VERDICT_NOT_SEEN,
      hits_count: seen ? Math.max(1, hits) : 0,
      first_seen: seen ? toIsoDate(report.first_seen) : null,
      last_seen: seen ? toIsoDate(report.last_seen) : null,
      hosts: seen ? sanitizeHosts(report.hosts) : [],
      reason: null,
    };
  });
};

export const countIocHits = (results: HuntIocResult[]) => results.reduce((total, result) => total + (result.hits_count ?? 0), 0);

/** Whether a value of an indicator run was left unsearched: no hit then proves nothing about it. */
export const hasUnsearchedIoc = (results: HuntIocResult[] | null | undefined) => {
  return (results ?? []).some((result) => result.verdict === HUNT_IOC_VERDICT_NOT_SEARCHED || result.verdict === HUNT_IOC_VERDICT_PENDING);
};

/**
 * Links each seen value to the deployments of its indicators on the security platform of the run, when the
 * dissemination assurance is installed: the hunt confirms that a deployed indicator is seen on that platform.
 */
export const linkIocDeployments = async (context: AuthContext, run: BasicStoreEntityHuntRun, results: HuntIocResult[]): Promise<HuntIocResult[]> => {
  const sourceIds = Array.from(new Set(results.filter((result) => result.verdict === HUNT_IOC_VERDICT_SEEN).flatMap((result) => result.source_ids)));
  if (!run.security_platform_id || sourceIds.length === 0 || !isStixCoreRelationship(RELATION_DEPLOYED_ON)) {
    return results;
  }
  try {
    const deployments = await fullRelationsList<BasicStoreRelation>(context, HUNT_MANAGER_USER, RELATION_DEPLOYED_ON, {
      fromId: sourceIds,
      toId: run.security_platform_id,
    });
    const byIndicator = new Map<string, string[]>();
    deployments.forEach((deployment) => {
      byIndicator.set(deployment.fromId, [...(byIndicator.get(deployment.fromId) ?? []), deployment.internal_id]);
    });
    return results.map((result) => {
      const deploymentIds = result.source_ids.flatMap((sourceId) => byIndicator.get(sourceId) ?? []);
      return deploymentIds.length > 0 ? { ...result, deployment_ids: deploymentIds } : result;
    });
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Hunt run values cannot be linked to their deployments', { cause: error, runId: run.internal_id });
    return results;
  }
};

/** The indicators and observables whose values a run searched, and those of the values it found. */
export const huntedIocIds = (results: HuntIocResult[] | null | undefined) => {
  const searched = (results ?? []).filter((result) => result.verdict === HUNT_IOC_VERDICT_SEEN || result.verdict === HUNT_IOC_VERDICT_NOT_SEEN);
  const idsOf = (list: HuntIocResult[]) => Array.from(new Set(list.flatMap((result) => result.source_ids ?? [])));
  return { huntedIds: idsOf(searched), matchedIds: idsOf(searched.filter((result) => result.verdict === HUNT_IOC_VERDICT_SEEN)) };
};

// A date only moves forward: a run finalized late never takes back the date a later run wrote
const HUNTED_DATES_SCRIPT = `
  boolean changed = false;
  if (ctx._source.x_opencti_hunted_at == null || ctx._source.x_opencti_hunted_at.compareTo(params.at) < 0) {
    ctx._source.x_opencti_hunted_at = params.at;
    changed = true;
  }
  if (params.matched.contains(ctx._source.internal_id)
    && (ctx._source.x_opencti_hunt_matched_at == null || ctx._source.x_opencti_hunt_matched_at.compareTo(params.at) < 0)) {
    ctx._source.x_opencti_hunt_matched_at = params.at;
    changed = true;
  }
  if (!changed) { ctx.op = 'noop'; }
`;

/**
 * Records on the indicators and observables a completed run searched when a hunt last looked them up, and on those it
 * found when a hunt last matched them. The dates are platform bookkeeping written in place, without stream event nor
 * history: they tell the next hunts what was already hunted, they are not knowledge to share.
 */
export const recordHuntedIocs = async (run: Pick<BasicStoreEntityHuntRun, 'ioc_results' | 'completed_at'>) => {
  const { huntedIds, matchedIds } = huntedIocIds(run.ioc_results);
  if (huntedIds.length === 0) {
    return;
  }
  const at = new Date(run.completed_at ?? Date.now()).toISOString();
  await elRawUpdateByQuery({
    index: [READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES],
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source: HUNTED_DATES_SCRIPT, lang: 'painless', params: { at, matched: matchedIds } },
      query: { terms: { 'internal_id.keyword': huntedIds } },
    },
  });
};

/**
 * Whether a completed run matched an entity of its hunt: an indicator or observable whose values the run searched is
 * matched when one of them was seen; a source the values come from (a report, a threat) or the source of another kind
 * of hunt is matched when the run has hits. Null when the run is not completed or did not search the entity.
 */
export const huntRunEntityMatched = (run: Pick<BasicStoreEntityHuntRun, 'hunt_run_status' | 'hits_count' | 'ioc_results'>, entityId: string) => {
  if (run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED) {
    return null;
  }
  const results = (run.ioc_results ?? []).filter((result) => (result.source_ids ?? []).includes(entityId));
  if (results.length === 0) {
    return (run.hits_count ?? 0) > 0;
  }
  if (results.some((result) => result.verdict === HUNT_IOC_VERDICT_SEEN)) {
    return true;
  }
  return results.some((result) => result.verdict === HUNT_IOC_VERDICT_NOT_SEEN) ? false : null;
};

/** When a hunt last looked up an indicator or observable the user can read, and last found it. */
export const findHuntEntityActivity = async (context: AuthContext, user: AuthUser, entityId: string) => {
  const entity = await storeLoadById<BasicStoreEntity & { x_opencti_hunted_at?: string; x_opencti_hunt_matched_at?: string }>(
    context,
    user,
    entityId,
    ABSTRACT_STIX_CORE_OBJECT,
  );
  if (!entity) {
    return null;
  }
  return { hunted_at: entity.x_opencti_hunted_at ?? null, matched_at: entity.x_opencti_hunt_matched_at ?? null };
};
