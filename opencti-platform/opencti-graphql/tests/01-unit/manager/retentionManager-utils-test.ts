import { describe, expect, it } from 'vitest';
import { buildRetentionAuditInput, buildRetentionAuditMessage, newRetentionRunSummary, recordRetentionFailure } from '../../../src/manager/retentionManager-utils';

describe('Retention manager run summary', () => {
  it('should not count a failed delete as deleted, and keep the last error', () => {
    const summary = newRetentionRunSummary(3);
    recordRetentionFailure(summary, 'id-1', new Error('first failure'));
    recordRetentionFailure(summary, 'id-2', new Error('second failure'));
    expect(summary.deletedCount).toBe(1);
    expect(summary.failedCount).toBe(2);
    expect(summary.lastError).toBe('id-2: second failure');
  });

  it('should truncate the last error', () => {
    const summary = newRetentionRunSummary(1);
    recordRetentionFailure(summary, 'id-1', new Error('x'.repeat(5000)));
    expect(summary.lastError).toHaveLength(1000);
  });

  it('should have no last error when nothing failed', () => {
    expect(newRetentionRunSummary(10).lastError).toBeNull();
  });

  it('should mention failures in the audit message only when there are some', () => {
    const summary = newRetentionRunSummary(2);
    expect(buildRetentionAuditMessage('Rule', 'knowledge', summary)).toBe('Retention rule `Rule` deleted `2` `knowledge` entries');
    recordRetentionFailure(summary, 'id-1', new Error('failure'));
    expect(buildRetentionAuditMessage('Rule', 'knowledge', summary)).toBe('Retention rule `Rule` deleted `1` `knowledge` entries, `1` failed');
  });

  it('should carry counts per type for knowledge, and the entries for history and activity', () => {
    const summary = newRetentionRunSummary(3);
    summary.deletedCountByType = { Malware: 2, Report: 1 };
    summary.deletedHistoryEntries = [{ id: 'h-1', timestamp: '2026-01-01T00:00:00.000Z' }];
    expect(buildRetentionAuditInput('knowledge', summary)).toEqual({ deleted_count: 3, failed_count: 0, deleted_count_by_type: { Malware: 2, Report: 1 } });
    expect(buildRetentionAuditInput('history', summary)).toEqual({ deleted_count: 3, failed_count: 0, deleted_entries: summary.deletedHistoryEntries });
    expect(buildRetentionAuditInput('activity', summary)).toEqual({ deleted_count: 3, failed_count: 0, deleted_entries: summary.deletedHistoryEntries });
    expect(buildRetentionAuditInput('file', summary)).toEqual({ deleted_count: 3, failed_count: 0 });
  });
});
