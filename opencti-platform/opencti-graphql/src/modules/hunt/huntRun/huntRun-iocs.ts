import type { AuthContext } from '../../../types/user';
import type { BasicStoreRelation } from '../../../types/store';
import { logApp } from '../../../config/conf';
import { fullRelationsList } from '../../../database/middleware-loader';
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
