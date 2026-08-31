import { beforeEach, describe, expect, it, vi } from 'vitest';
import { UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

interface DryRunStub {
  status: UserMergeStatus;
  message?: string;
  report?: { handlers: { changes: { count: number }[] }[] };
}

const coverage = { is_complete: true, gating_uncovered_count: 0 };
let dryRun: DryRunStub;

vi.mock('../../../../src/modules/userMerge/userMerge-coverage', () => ({
  buildUserMergeCoverage: () => coverage,
}));

vi.mock('../../../../src/modules/userMerge/userMerge-engine', () => ({
  executeUserMerge: async () => dryRun,
}));

const { computeUserMergeSourceDeletionReadiness } = await import('../../../../src/modules/userMerge/userMerge-sourceDeletion');

const succeededWith = (...counts: number[]): DryRunStub => ({
  status: UserMergeStatus.Success,
  report: { handlers: counts.map((count) => ({ changes: [{ count }] })) },
});

const readiness = () => computeUserMergeSourceDeletionReadiness({} as never, 'source-id', 'target-id');

describe('source deletion gate', () => {
  beforeEach(() => {
    coverage.is_complete = true;
    coverage.gating_uncovered_count = 0;
    dryRun = succeededWith(0, 0);
  });

  it('should allow the deletion when coverage is complete and nothing is left to move', async () => {
    const result = await readiness();
    expect(result.allowed).toBe(true);
    expect(result.blockers).toEqual([]);
    expect(result.pending_change_count).toEqual(0);
  });

  it('should refuse while register rows a handler must claim are uncovered', async () => {
    coverage.is_complete = false;
    coverage.gating_uncovered_count = 61;
    const result = await readiness();
    expect(result.allowed).toBe(false);
    expect(result.coverage_complete).toBe(false);
    expect(result.blockers[0]).toContain('61 register rows');
  });

  // The case a stored attestation of a past merge could not catch: coverage is complete and the
  // merge did run, but references to the source appeared afterwards.
  it('should refuse when the dry-run still plans changes, and report their total', async () => {
    dryRun = succeededWith(3, 0, 4);
    const result = await readiness();
    expect(result.allowed).toBe(false);
    expect(result.pending_change_count).toEqual(7);
    expect(result.blockers[0]).toContain('7 references to the source');
  });

  it('should refuse when the dry-run itself did not complete', async () => {
    dryRun = { status: UserMergeStatus.Failed, message: 'elastic unavailable' };
    const result = await readiness();
    expect(result.allowed).toBe(false);
    expect(result.blockers[0]).toContain('elastic unavailable');
  });

  it('should report both blockers when coverage is partial and changes are pending', async () => {
    coverage.is_complete = false;
    coverage.gating_uncovered_count = 61;
    dryRun = succeededWith(2);
    const result = await readiness();
    expect(result.blockers).toHaveLength(2);
  });
});
