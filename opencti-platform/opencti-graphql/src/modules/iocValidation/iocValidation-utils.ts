import { extractValidObservablesFromIndicatorPattern, STIX_PATTERN_TYPE } from '../../utils/syntax';
import type { StixId } from '../../types/stix-2-1-common';
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

const urlHost = (value: string): string | undefined => {
  try {
    const url = new URL(value.includes('://') ? value : `http://${value}`);
    return url.hostname || undefined;
  } catch {
    return undefined;
  }
};

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
    case 'Url': {
      if (!observable.value) return undefined;
      if (allows(TEST_KIND_HTTP_HEAD)) return { kind: TEST_KIND_HTTP_HEAD, value: observable.value };
      const host = urlHost(observable.value);
      return host && allows(TEST_KIND_DNS_RESOLUTION) ? { kind: TEST_KIND_DNS_RESOLUTION, value: host } : undefined;
    }
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

/**
 * Build the IOC tested for an indicator, or the reason why it cannot be validated.
 * Only simple STIX patterns are supported; the first testable observable of the pattern is used.
 */
export const extractIocFromIndicator = (indicator: IndicatorForValidation, allowed: IocValidationTestKind[]): IocExtraction => {
  if (indicator.pattern_type !== STIX_PATTERN_TYPE || !indicator.pattern) {
    return { reason: 'Only STIX patterns can be validated' };
  }
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
    const resolved = resolveTestKind(observable, allowed);
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
