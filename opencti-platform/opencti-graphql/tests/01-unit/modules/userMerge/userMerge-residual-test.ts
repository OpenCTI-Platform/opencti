import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/modules/userMerge/userMerge-bulk', () => ({
  userMergeScanPagesForRewrite: async () => undefined,
}));

const { summarizeResidualFindings, userMergeResidualHandler } = await import('../../../../src/modules/userMerge/userMerge-residualHandler');

describe('residual references handler', () => {
  it('should declare no read and no write', () => {
    expect(userMergeResidualHandler.reads).toEqual([]);
    expect(userMergeResidualHandler.writes).toEqual([]);
  });

  it('should report an empty sweep in plain words', () => {
    expect(summarizeResidualFindings([])).toEqual(
      'no serialized reference to the source found outside the rows the handlers claim',
    );
  });

  it('should order the findings by decreasing count', () => {
    const summary = summarizeResidualFindings([
      { entity_type: 'Report', count: 2 },
      { entity_type: 'Note', count: 7 },
    ]);
    expect(summary).toEqual('best-effort sweep, nothing rewritten: Note (7), Report (2)');
  });

  it('should order equal counts by entity type so the summary is stable', () => {
    const summary = summarizeResidualFindings([
      { entity_type: 'Report', count: 3 },
      { entity_type: 'Note', count: 3 },
    ]);
    expect(summary).toEqual('best-effort sweep, nothing rewritten: Note (3), Report (3)');
  });

  // The plan fingerprint carries the count, not the detail. A detector registered last runs after
  // every other handler has written, so a non-zero count would differ between the dry pass and the
  // recompute and abort the merge.
  it('should never plan a change', async () => {
    const plan = await userMergeResidualHandler.compute({
      context: {} as never,
      sourceId: 'source-id',
      targetId: 'target-id',
      dryRun: true,
      mergeStartedAt: new Date(),
    } as never);
    expect(plan.changes.every((change) => change.count === 0)).toBe(true);
  });
});
