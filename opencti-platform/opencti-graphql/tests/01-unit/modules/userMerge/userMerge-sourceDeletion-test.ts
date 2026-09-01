import { beforeEach, describe, expect, it, vi } from 'vitest';
import { UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

interface DryRunStub {
  status: UserMergeStatus;
  message?: string;
  report?: { handlers: { changes: { count: number }[] }[] };
}

const coverage = { is_complete: true, gating_uncovered_count: 0 };
let dryRun: DryRunStub;
let sourceAccount: { account_status?: string; merged_into?: string } | undefined;

vi.mock('../../../../src/modules/userMerge/userMerge-coverage', () => ({
  buildUserMergeCoverage: () => coverage,
}));

vi.mock('../../../../src/modules/userMerge/userMerge-engine', () => ({
  executeUserMerge: async () => dryRun,
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  storeLoadById: async () => sourceAccount,
}));

const deleteElementById = vi.fn(async () => ({ user_email: 'merged@example.com' }));
const killUserSessions = vi.fn(async () => undefined);
const publishUserAction = vi.fn(async () => undefined);

vi.mock('../../../../src/database/middleware', () => ({ deleteElementById: (...args: unknown[]) => deleteElementById(...(args as [])) }));
vi.mock('../../../../src/database/session', () => ({ killUserSessions: (...args: unknown[]) => killUserSessions(...(args as [])) }));
vi.mock('../../../../src/listener/UserActionListener', () => ({ publishUserAction: (...args: unknown[]) => publishUserAction(...(args as [])) }));

const { computeUserMergeSourceDeletionReadiness, deleteUserMergeSource } = await import('../../../../src/modules/userMerge/userMerge-sourceDeletion');

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
    sourceAccount = { account_status: 'Expired', merged_into: 'target-id' };
    deleteElementById.mockClear();
    killUserSessions.mockClear();
    publishUserAction.mockClear();
  });

  it('should refuse while the source account is still active', async () => {
    sourceAccount = { account_status: 'Active' };
    const result = await readiness();
    expect(result.allowed).toBe(false);
    expect(result.blockers).toEqual(['no merge into this target has been recorded on the source account']);
  });

  // A disabled account is not a merged account: an administrator disables one, and so does an
  // expiration date coming due. Read the status alone and a wrong pair walks through whenever the
  // dry-run plans nothing because the two accounts have nothing to do with each other -- which is
  // precisely the case on a typo, and the deletion is permanent.
  it('should refuse a disabled source no merge ever ran on', async () => {
    sourceAccount = { account_status: 'Expired' };
    const result = await readiness();
    expect(result.allowed).toBe(false);
    expect(result.blockers).toEqual(['no merge into this target has been recorded on the source account']);
  });

  it('should refuse a source merged into a different target', async () => {
    sourceAccount = { account_status: 'Expired', merged_into: 'another-target-id' };
    const result = await readiness();
    expect(result.allowed).toBe(false);
    expect(result.blockers).toEqual(['no merge into this target has been recorded on the source account']);
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

  describe('deletion', () => {
    const remove = () => deleteUserMergeSource({} as never, {} as never, 'source-id', 'target-id');

    it('should delete the account and return its id when the gate allows it', async () => {
      await expect(remove()).resolves.toEqual('source-id');
      expect(deleteElementById).toHaveBeenCalledTimes(1);
    });

    // The cascades of userDelete are deliberately not reused: they are no-ops when the merge
    // covered everything, and delete objects belonging to the target when it did not.
    it('should trace the deletion and close the sessions', async () => {
      await remove();
      expect(publishUserAction).toHaveBeenCalledTimes(1);
      expect(killUserSessions).toHaveBeenCalledTimes(1);
    });

    it('should refuse and write nothing when the gate refuses', async () => {
      dryRun = succeededWith(2);
      await expect(remove()).rejects.toThrow('Source account cannot be deleted yet');
      expect(deleteElementById).not.toHaveBeenCalled();
    });

    it('should refuse while the source account is still active', async () => {
      sourceAccount = { account_status: 'Active' };
      await expect(remove()).rejects.toThrow('Source account cannot be deleted yet');
      expect(deleteElementById).not.toHaveBeenCalled();
    });

    it('should refuse a disabled source no merge into this target ever ran on', async () => {
      sourceAccount = { account_status: 'Expired' };
      await expect(remove()).rejects.toThrow('Source account cannot be deleted yet');
      expect(deleteElementById).not.toHaveBeenCalled();
    });
  });
});
