import { logApp } from '../config/conf';

const SUMMARY_INTERVAL_MS = 60000;

export interface EmailFailure {
  cause: unknown;
  userId: string;
  triggerIds: string[];
}

interface EmailFailureSummary {
  failures: Map<string, number>;
  triggerIds: Set<string>;
  sample: EmailFailure;
}

let currentSummary: EmailFailureSummary | undefined;

const failureCode = (cause: unknown): string => {
  if (cause instanceof Error && 'code' in cause && typeof cause.code === 'string') {
    return cause.code;
  }
  return 'UNKNOWN';
};

const logSummary = () => {
  if (!currentSummary) {
    return;
  }
  const summary = currentSummary;
  currentSummary = undefined;
  logApp.warn('[OPENCTI-MODULE] Publisher manager email notifications failed in the last minute', {
    manager: 'PUBLISHER_MANAGER',
    failures: Object.fromEntries(summary.failures),
    triggerCount: summary.triggerIds.size,
    sample: summary.sample,
  });
};

const startSummary = (sample: EmailFailure): EmailFailureSummary => {
  const summary = { failures: new Map<string, number>(), triggerIds: new Set<string>(), sample };
  currentSummary = summary;
  setTimeout(logSummary, SUMMARY_INTERVAL_MS).unref();
  return summary;
};

export const recordEmailFailure = (failure: EmailFailure) => {
  const summary = currentSummary ?? startSummary(failure);
  const code = failureCode(failure.cause);
  summary.failures.set(code, (summary.failures.get(code) ?? 0) + 1);
  failure.triggerIds.forEach((triggerId) => summary.triggerIds.add(triggerId));
};
