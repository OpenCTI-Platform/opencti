import { describe, expect, it } from 'vitest';
import { buildApiUserMergeCoverage, buildUserMergeCoverage } from '../../../../src/modules/userMerge/userMerge-coverage';
import { USER_MERGE_REGISTER, USER_MERGE_REGISTRY_VERSION, UserMergeDisposition } from '../../../../src/modules/userMerge/userMerge-register';
import type { UserMergeHandler } from '../../../../src/modules/userMerge/userMerge-handler';

const mockHandler = (identifier: string, covers: string[]): UserMergeHandler => ({
  identifier,
  covers,
  registryVersion: USER_MERGE_REGISTRY_VERSION,
  reads: [],
  writes: [],
  compute: async () => ({ handler: identifier, changes: [], alerts: [] }),
  apply: async () => 0,
});

describe('userMerge coverage manifest', () => {
  it('should name every register row as uncovered when no handler is registered', () => {
    const coverage = buildUserMergeCoverage([]);
    expect(coverage.total).toEqual(101);
    expect(coverage.covered_count).toEqual(0);
    expect(coverage.uncovered_count).toEqual(101);
    expect(coverage.gating_uncovered_count).toEqual(61);
    expect(coverage.is_complete).toBe(false);
    expect(coverage.rows.length).toEqual(101);
    expect(coverage.rows.every((row) => !row.covered && row.handler === undefined)).toBe(true);
    // Named, not merely counted: this is what makes a blind spot actionable.
    expect(coverage.rows.map((row) => row.row_id)).toContain('basic-object.creator-id');
  });

  it('should report a partial coverage as incomplete', () => {
    const coverage = buildUserMergeCoverage([mockHandler('creator', ['basic-object.creator-id', 'user.password'])]);
    expect(coverage.covered_count).toEqual(2);
    expect(coverage.uncovered_count).toEqual(99);
    expect(coverage.is_complete).toBe(false);
    const creatorRow = coverage.rows.find((row) => row.row_id === 'basic-object.creator-id');
    expect(creatorRow?.covered).toBe(true);
    expect(creatorRow?.handler).toEqual('creator');
  });

  it('should be complete once the rows a handler must claim are claimed', () => {
    const gating = USER_MERGE_REGISTER
      .filter((row) => row.disposition === UserMergeDisposition.Transfer || row.disposition === UserMergeDisposition.Conditional)
      .map((row) => row.id);
    const coverage = buildUserMergeCoverage([mockHandler('gating', gating)]);
    expect(coverage.gating_uncovered_count).toEqual(0);
    expect(coverage.is_complete).toBe(true);
    // Completeness is not "everything is claimed": the invalidated, retained and out-of-scope
    // rows are deliberately left to no handler, so requiring them would shut the gate for good.
    expect(coverage.uncovered_count).toEqual(40);
  });

  it('should stay incomplete when a single gating row is left uncovered', () => {
    const gating = USER_MERGE_REGISTER
      .filter((row) => row.disposition === UserMergeDisposition.Transfer || row.disposition === UserMergeDisposition.Conditional)
      .map((row) => row.id);
    const coverage = buildUserMergeCoverage([mockHandler('gating', gating.slice(1))]);
    expect(coverage.gating_uncovered_count).toEqual(1);
    expect(coverage.is_complete).toBe(false);
  });

  it('should not be made complete by claiming rows no handler is expected to claim', () => {
    const retained = USER_MERGE_REGISTER
      .filter((row) => row.disposition === UserMergeDisposition.Retain || row.disposition === UserMergeDisposition.OutOfScope)
      .map((row) => row.id);
    const coverage = buildUserMergeCoverage([mockHandler('retained', retained)]);
    expect(coverage.covered_count).toEqual(18);
    expect(coverage.is_complete).toBe(false);
  });

  it('should keep the counts on the whole register when rows are filtered', () => {
    const handlers = [mockHandler('creator', ['basic-object.creator-id'])];
    const filtered = buildUserMergeCoverage(handlers, UserMergeDisposition.Transfer);
    expect(filtered.rows.length).toEqual(40);
    expect(filtered.rows.every((row) => row.disposition === UserMergeDisposition.Transfer)).toBe(true);
    // A filtered view must not be able to claim completeness by narrowing the question.
    expect(filtered.total).toEqual(101);
    expect(filtered.uncovered_count).toEqual(100);
    expect(filtered.is_complete).toBe(false);
  });

  it('should expose GraphQL-compatible disposition values', () => {
    const coverage = buildApiUserMergeCoverage([], 'OUT_OF_SCOPE');
    expect(coverage.rows.length).toEqual(6);
    expect(coverage.rows.every((row) => (row.disposition as string) === 'OUT_OF_SCOPE')).toBe(true);
  });

  it('should refuse an unknown disposition filter rather than answer another question', () => {
    expect(() => buildApiUserMergeCoverage([], 'NOT_A_DISPOSITION')).toThrow('Unknown merge register disposition');
  });
});
