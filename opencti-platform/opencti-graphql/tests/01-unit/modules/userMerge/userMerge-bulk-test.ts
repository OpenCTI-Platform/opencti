import { beforeEach, describe, expect, it, vi } from 'vitest';

const elRawUpdateByQuery = vi.fn();
vi.mock('../../../../src/database/engine', () => ({ elRawUpdateByQuery: (query: unknown) => elRawUpdateByQuery(query) }));

const { userMergeBulkUpdate } = await import('../../../../src/modules/userMerge/userMerge-bulk');

describe('User merge bulk update', () => {
  beforeEach(() => {
    elRawUpdateByQuery.mockReset();
  });

  it('should surface the counters of a clean update', async () => {
    elRawUpdateByQuery.mockResolvedValue({ updated: 10, total: 10, failures: [], version_conflicts: 0 });
    const result = await userMergeBulkUpdate('label', ['index'], { query: {} });
    expect(result).toEqual({ updated: 10, total: 10, failures: [], version_conflicts: 0 });
  });

  it('should fail on a version conflict instead of reporting success', async () => {
    // The exact shape elOperationForMigration reports as a success today.
    elRawUpdateByQuery.mockResolvedValue({ updated: 3000, total: 10000, failures: [], version_conflicts: 7000 });
    await expect(userMergeBulkUpdate('label', ['index'], { query: {} })).rejects.toThrow('failures or version conflicts');
  });

  it('should fail on a non-empty failure list', async () => {
    elRawUpdateByQuery.mockResolvedValue({ updated: 9, total: 10, failures: [{ reason: 'mapping' }], version_conflicts: 0 });
    await expect(userMergeBulkUpdate('label', ['index'], { query: {} })).rejects.toThrow('failures or version conflicts');
  });

  it('should never let the engine skip conflicting documents', async () => {
    elRawUpdateByQuery.mockResolvedValue({ updated: 1, total: 1, failures: [], version_conflicts: 0 });
    await userMergeBulkUpdate('label', ['index'], { query: {} });
    const [query] = elRawUpdateByQuery.mock.calls[0];
    expect(query.conflicts).toBe('abort');
    expect(query.wait_for_completion).toBe(true);
    expect(query.refresh).toBe(true);
  });

  it('should wrap a raw engine error', async () => {
    elRawUpdateByQuery.mockRejectedValue(new Error('connection reset'));
    await expect(userMergeBulkUpdate('label', ['index'], { query: {} })).rejects.toThrow('User merge bulk update failed');
  });

  it('should treat missing counters as zero rather than as absent', async () => {
    elRawUpdateByQuery.mockResolvedValue({});
    const result = await userMergeBulkUpdate('label', ['index'], { query: {} });
    expect(result).toEqual({ updated: 0, total: 0, failures: [], version_conflicts: 0 });
  });
});
