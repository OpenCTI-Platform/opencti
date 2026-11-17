const RETENTION_LAST_ERROR_MAX_LENGTH = 1000;

// What one execution of a retention rule did, for the rule status and the audit summary
export interface RetentionRunSummary {
  deletedCount: number;
  failedCount: number;
  lastError: string | null;
  // Knowledge can delete up to a batch of entities per run: counts per type, not the ids
  deletedCountByType: Record<string, number>;
  deletedHistoryEntries: Array<{ id: string; timestamp: string }>;
}

export const newRetentionRunSummary = (candidatesCount: number): RetentionRunSummary => ({
  deletedCount: candidatesCount,
  failedCount: 0,
  lastError: null,
  deletedCountByType: {},
  deletedHistoryEntries: [],
});

// The element is not deleted: it is not counted as deleted, and the rule keeps the error to show it
export const recordRetentionFailure = (summary: RetentionRunSummary, elementId: string, err: any) => {
  summary.deletedCount -= 1;
  summary.failedCount += 1;
  summary.lastError = `${elementId}: ${err?.message ?? 'Unknown error'}`.substring(0, RETENTION_LAST_ERROR_MAX_LENGTH);
};

export const buildRetentionAuditMessage = (name: string, scope: string, summary: RetentionRunSummary) => {
  const failures = summary.failedCount > 0 ? `, \`${summary.failedCount}\` failed` : '';
  return `Retention rule \`${name}\` deleted \`${summary.deletedCount}\` \`${scope}\` entries${failures}`;
};

export const buildRetentionAuditInput = (scope: string, summary: RetentionRunSummary) => {
  const input: Record<string, unknown> = { deleted_count: summary.deletedCount, failed_count: summary.failedCount };
  if (scope === 'knowledge') {
    input.deleted_count_by_type = summary.deletedCountByType;
  }
  if (scope === 'history' || scope === 'activity') {
    input.deleted_entries = summary.deletedHistoryEntries;
  }
  return input;
};
