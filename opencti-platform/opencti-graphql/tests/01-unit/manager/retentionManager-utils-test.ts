import { describe, expect, it } from 'vitest';
import {
  buildRetentionAuditInput,
  buildRetentionAuditMessage,
  newRetentionRunSummary,
  recordRetentionDeleted,
  recordRetentionFailure,
} from '../../../src/manager/retentionManager-utils';

const TIMESTAMP = '2026-01-01T00:00:00.000Z';
const element = (id: string, entityType = 'Malware') => ({ id, entity_type: entityType, timestamp: TIMESTAMP });

describe('Retention manager run summary', () => {
  it('should count only the deletes that happened', () => {
    const summary = newRetentionRunSummary();
    expect(summary.deletedCount).toBe(0);
    recordRetentionDeleted(summary, 'knowledge', element('id-1'));
    recordRetentionFailure(summary, 'id-2', new Error('first failure'));
    recordRetentionFailure(summary, 'id-3', new Error('second failure'));
    expect(summary.deletedCount).toBe(1);
    expect(summary.failedCount).toBe(2);
    expect(summary.lastError).toBe('id-3: second failure');
  });

  it('should truncate the last error', () => {
    const summary = newRetentionRunSummary();
    recordRetentionFailure(summary, 'id-1', new Error('x'.repeat(5000)));
    expect(summary.lastError).toHaveLength(1000);
  });

  it('should have no last error when nothing failed', () => {
    expect(newRetentionRunSummary().lastError).toBeNull();
  });

  it('should mention failures in the audit message only when there are some', () => {
    const summary = newRetentionRunSummary();
    recordRetentionDeleted(summary, 'knowledge', element('id-1'));
    expect(buildRetentionAuditMessage('Rule', 'knowledge', summary)).toBe('Retention rule `Rule` deleted `1` `knowledge` entries');
    recordRetentionFailure(summary, 'id-2', new Error('failure'));
    expect(buildRetentionAuditMessage('Rule', 'knowledge', summary)).toBe('Retention rule `Rule` deleted `1` `knowledge` entries, `1` failed');
  });

  it('should carry counts per type for knowledge', () => {
    const summary = newRetentionRunSummary();
    recordRetentionDeleted(summary, 'knowledge', element('id-1'));
    recordRetentionDeleted(summary, 'knowledge', element('id-2'));
    recordRetentionDeleted(summary, 'knowledge', element('id-3', 'Report'));
    expect(buildRetentionAuditInput('knowledge', summary)).toEqual({ deleted_count: 3, failed_count: 0, deleted_count_by_type: { Malware: 2, Report: 1 } });
  });

  it('should carry the entries for history and activity, and only the counts for files', () => {
    const history = newRetentionRunSummary();
    recordRetentionDeleted(history, 'history', element('h-1', 'History'));
    const entries = [{ id: 'h-1', timestamp: TIMESTAMP }];
    expect(buildRetentionAuditInput('history', history)).toEqual({ deleted_count: 1, failed_count: 0, deleted_entries: entries });
    expect(buildRetentionAuditInput('activity', history)).toEqual({ deleted_count: 1, failed_count: 0, deleted_entries: entries });
    const files = newRetentionRunSummary();
    recordRetentionDeleted(files, 'file', element('import/global/file.txt', 'InternalFile'));
    expect(buildRetentionAuditInput('file', files)).toEqual({ deleted_count: 1, failed_count: 0 });
  });
});
