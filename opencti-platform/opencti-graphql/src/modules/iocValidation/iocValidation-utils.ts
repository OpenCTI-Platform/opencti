import { extractValidObservablesFromIndicatorPattern, STIX_PATTERN_TYPE } from '../../utils/syntax';
import { isBypassUser, isUserHasCapability } from '../../utils/access';
import type { StixId } from '../../types/stix-2-1-common';
import type { AuthUser } from '../../types/user';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import {
  type IocValidationIoc,
  type IocValidationResultsSummary,
  type IocValidationTestKind,
  IOC_VALIDATION_TEST_KINDS,
  TEST_KIND_DNS_RESOLUTION,
  TEST_KIND_FILE_DROP,
  TEST_KIND_HTTP_HEAD,
  TEST_KIND_LOG_INJECTION,
  TEST_KIND_NETWORK_TRAFFIC,
} from './iocValidation-types';
import {
  VALIDATION_STATUS_DETECTED,
  VALIDATION_STATUS_ERROR,
  VALIDATION_STATUS_MISSED,
  VALIDATION_STATUS_PREVENTED,
  VALIDATION_STATUS_REQUESTED,
} from '../indicatorDeployment/indicatorDeployment-types';

export const isIocValidationTestKind = (value: unknown): value is IocValidationTestKind => {
  return typeof value === 'string' && (IOC_VALIDATION_TEST_KINDS as readonly string[]).includes(value);
};

/**
 * The requester of a validation request is the user who created it.
 * It is read from creator_id rather than a dedicated attribute, so a user merge rewrites it with every other creator.
 */
export const requesterIdOf = (request: { creator_id?: string | string[] | null }) => {
  const creators = Array.isArray(request.creator_id) ? request.creator_id : [request.creator_id];
  return creators.find((id): id is string => typeof id === 'string' && id.length > 0);
};

type AccessControlledElement = { [RELATION_OBJECT_MARKING]?: string[] | null; [RELATION_GRANTED_TO]?: string[] | null };

/**
 * Read access of a validation request: its name, description and OpenAEV run describe all its indicators and security
 * platforms, so it is read only by who reads every one of them. It carries the markings of all of them and is shared
 * with the organizations all of them are shared with (none when they share none: then only the platform organization
 * reads it, as for an element shared with no organization).
 */
export const requestAccessOf = (ends: AccessControlledElement[]) => {
  const markingIds = [...new Set(ends.flatMap((end) => end[RELATION_OBJECT_MARKING] ?? []))];
  const [first, ...others] = ends.map((end) => end[RELATION_GRANTED_TO] ?? []);
  const organizationIds = [...new Set((first ?? []).filter((organization) => others.every((granted) => granted.includes(organization))))];
  return { markingIds, organizationIds };
};

/**
 * Ends the access of a request is computed from. The request still describes an indicator or security platform that
 * can no longer be read (deleted meanwhile), so it then also keeps its own current access: it can only get stricter.
 */
export const requestAccessEndsOf = (request: AccessControlledElement, ends: AccessControlledElement[], referencedCount: number) => {
  return ends.length < referencedCount ? [...ends, request] : ends;
};

/**
 * The creator_id of a deployed-on relationship lists the accounts that created or upserted it: the integrations
 * that record the lifecycle of this indicator on this security platform, the only ones speaking for the platform.
 */
export const isDeploymentReporter = (deployment: { creator_id?: string | string[] | null }, userId: string) => {
  const creators = Array.isArray(deployment.creator_id) ? deployment.creator_id : [deployment.creator_id];
  return creators.includes(userId);
};

/** Accounts allowed to write the deployment lifecycle outside the write-back mutations: connectors (imports, synchronization) and administrators. */
export const isLifecycleWriter = (user: AuthUser) => isBypassUser(user) || isUserHasCapability(user, 'CONNECTORAPI');

/**
 * Whether the account speaks for the security platform of a deployment: a connector account among the accounts that
 * recorded it. Being a creator is not enough on its own, since any editor who upserts the relationship (a description,
 * a new deployment in its default state) is added to its creators.
 */
export const isTrustedDeploymentReporter = (deployment: { creator_id?: string | string[] | null }, user: AuthUser) => {
  return isLifecycleWriter(user) && isDeploymentReporter(deployment, user.id);
};

interface ExtractedObservable {
  type: string;
  value?: string;
  name?: string;
  hashes?: Record<string, string>;
}

export interface IndicatorForValidation {
  internal_id: string;
  standard_id: string;
  pattern?: string | null;
  pattern_type?: string | null;
}

export type IocExtraction = { ioc: IocValidationIoc; reason?: undefined } | { ioc?: undefined; reason: string };

/**
 * Deterministic choice of the benign test for an observable, given the allowed test kinds.
 * Returns undefined when no allowed kind can validate this observable.
 */
export const resolveTestKind = (
  observable: ExtractedObservable,
  allowed: IocValidationTestKind[],
): { kind: IocValidationTestKind; value: string } | undefined => {
  const allows = (kind: IocValidationTestKind) => allowed.includes(kind);
  switch (observable.type) {
    case 'Domain-Name':
    case 'Hostname':
      return observable.value && allows(TEST_KIND_DNS_RESOLUTION) ? { kind: TEST_KIND_DNS_RESOLUTION, value: observable.value } : undefined;
    case 'IPv4-Addr':
    case 'IPv6-Addr':
      return observable.value && allows(TEST_KIND_NETWORK_TRAFFIC) ? { kind: TEST_KIND_NETWORK_TRAFFIC, value: observable.value } : undefined;
    // A DNS resolution of the host would only prove the detection of the domain, not of the URL indicator.
    case 'Url':
      return observable.value && allows(TEST_KIND_HTTP_HEAD) ? { kind: TEST_KIND_HTTP_HEAD, value: observable.value } : undefined;
    case 'StixFile': {
      const hashValues = Object.values(observable.hashes ?? {});
      if (observable.name && allows(TEST_KIND_FILE_DROP)) return { kind: TEST_KIND_FILE_DROP, value: observable.name };
      const logValue = hashValues[0] ?? observable.name;
      return logValue && allows(TEST_KIND_LOG_INJECTION) ? { kind: TEST_KIND_LOG_INJECTION, value: logValue } : undefined;
    }
    default:
      return undefined;
  }
};

// Merge the file components (name, hashes) of a pattern into a single observable.
const mergeObservables = (observables: ExtractedObservable[]): ExtractedObservable[] => {
  const files = observables.filter((o) => o.type === 'StixFile');
  const others = observables.filter((o) => o.type !== 'StixFile');
  if (files.length === 0) return others;
  const merged: ExtractedObservable = { type: 'StixFile', hashes: {} };
  files.forEach((file) => {
    if (file.name && !merged.name) merged.name = file.name;
    merged.hashes = { ...merged.hashes, ...(file.hashes ?? {}) };
  });
  return [merged, ...others];
};

const PATTERN_STRING_LITERAL = /'(?:\\.|[^'\\])*'/g;
const PATTERN_OBJECT_TYPE = /([a-z][a-z0-9-]*):/g;
const UNSUPPORTED_PATTERN_OPERATORS = /!=|<|>|\b(?:FOLLOWEDBY|NOT|IN|LIKE|MATCHES|ISSUBSET|ISSUPERSET|EXISTS|WITHIN|REPEATS|START|STOP)\b/;

export interface ValidationPatternAnalysis {
  supported: boolean;
  // Every comparison of an AND must hold: only a test carrying all the file values can satisfy it.
  conjunctiveFile: boolean;
}

/**
 * A tested value satisfies the indicator only when every comparison is an equality and the comparisons are
 * alternatives (OR), or all constrain the same file (AND). Negations, ranges, set or regex operators,
 * FOLLOWEDBY and qualifiers would let the test use a value the indicator does not match.
 */
export const analyzeValidationPattern = (pattern: string): ValidationPatternAnalysis => {
  const structure = pattern.replace(PATTERN_STRING_LITERAL, "''");
  if (!structure.includes('=') || UNSUPPORTED_PATTERN_OPERATORS.test(structure)) {
    return { supported: false, conjunctiveFile: false };
  }
  if (!/\bAND\b/.test(structure)) {
    return { supported: true, conjunctiveFile: false };
  }
  const objectTypes = new Set([...structure.matchAll(PATTERN_OBJECT_TYPE)].map((match) => match[1]));
  const singleFile = !/\bOR\b/.test(structure) && (structure.match(/\[/g) ?? []).length === 1 && objectTypes.size === 1 && objectTypes.has('file');
  return { supported: singleFile, conjunctiveFile: singleFile };
};

/**
 * Build the IOC tested for an indicator, or the reason why it cannot be validated.
 * Only equality comparisons joined by OR are supported; the first testable observable of the pattern is used.
 */
export const extractIocFromIndicator = (indicator: IndicatorForValidation, allowed: IocValidationTestKind[]): IocExtraction => {
  if (indicator.pattern_type !== STIX_PATTERN_TYPE || !indicator.pattern) {
    return { reason: 'Only STIX patterns can be validated' };
  }
  const analysis = analyzeValidationPattern(indicator.pattern);
  if (!analysis.supported) {
    return { reason: 'Only patterns made of equality comparisons joined by OR, or on a single file, can be validated' };
  }
  const testKinds = analysis.conjunctiveFile ? allowed.filter((kind) => kind === TEST_KIND_LOG_INJECTION) : allowed;
  let observables: ExtractedObservable[];
  try {
    observables = mergeObservables(extractValidObservablesFromIndicatorPattern(indicator.pattern) as ExtractedObservable[]);
  } catch {
    return { reason: 'The indicator pattern cannot be parsed' };
  }
  if (observables.length === 0) {
    return { reason: 'No observable can be extracted from the pattern' };
  }
  for (let index = 0; index < observables.length; index += 1) {
    const observable = observables[index];
    const resolved = resolveTestKind(observable, testKinds);
    if (resolved) {
      const hashes = observable.type === 'StixFile' && Object.keys(observable.hashes ?? {}).length > 0 ? observable.hashes : null;
      return {
        ioc: {
          indicator_id: indicator.internal_id,
          indicator_ref: indicator.standard_id as StixId,
          observable_type: observable.type,
          value: resolved.value,
          test_kind: resolved.kind,
          file_name: observable.type === 'StixFile' ? observable.name ?? null : null,
          hashes,
        },
      };
    }
  }
  return { reason: 'No allowed test kind applies to this indicator' };
};

export const emptyResultsSummary = (total = 0, skipped = 0): IocValidationResultsSummary => ({
  total,
  requested: total,
  detected: 0,
  prevented: 0,
  missed: 0,
  error: 0,
  skipped,
});

/**
 * Summarize the validation status of the request pairs, read from their deployed-on relationships.
 * Pairs whose relationship no longer carries this request id count as requested (not answered).
 */
export const summarizeValidationResults = (
  pairsTotal: number,
  skipped: number,
  statuses: Array<string | null | undefined>,
): IocValidationResultsSummary => {
  const summary = emptyResultsSummary(pairsTotal, skipped);
  summary.requested = 0;
  statuses.forEach((status) => {
    switch (status) {
      case VALIDATION_STATUS_DETECTED:
        summary.detected += 1;
        break;
      case VALIDATION_STATUS_PREVENTED:
        summary.prevented += 1;
        break;
      case VALIDATION_STATUS_MISSED:
        summary.missed += 1;
        break;
      case VALIDATION_STATUS_ERROR:
        summary.error += 1;
        break;
      case VALIDATION_STATUS_REQUESTED:
      default:
        summary.requested += 1;
    }
  });
  summary.requested += Math.max(0, pairsTotal - statuses.length);
  return summary;
};

export const isSummaryComplete = (summary: IocValidationResultsSummary) => summary.total > 0 && summary.requested === 0;
