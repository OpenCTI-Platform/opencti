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

// Only deletes that happened are counted: candidates left by a shutdown, protected or already deleted are not
export const newRetentionRunSummary = (): RetentionRunSummary => ({
  deletedCount: 0,
  failedCount: 0,
  lastError: null,
  deletedCountByType: {},
  deletedHistoryEntries: [],
});

export const recordRetentionDeleted = (summary: RetentionRunSummary, scope: string, element: { id: string; entity_type: string; timestamp: string }) => {
  summary.deletedCount += 1;
  if (scope === 'knowledge') {
    summary.deletedCountByType[element.entity_type] = (summary.deletedCountByType[element.entity_type] ?? 0) + 1;
  }
  if (scope === 'history' || scope === 'activity') {
    summary.deletedHistoryEntries.push({ id: element.id, timestamp: element.timestamp });
  }
};

// The rule keeps the last error to show it
export const recordRetentionFailure = (summary: RetentionRunSummary, elementId: string, err: any) => {
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
