import { describe, expect, it } from 'vitest';
import { registerModules } from '../../../../src/composition-root';
import { buildUserMergeCoverage } from '../../../../src/modules/userMerge/userMerge-coverage';
import { UserMergeDisposition } from '../../../../src/modules/userMerge/userMerge-register';
import { userMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';

registerModules();

const GATING = [UserMergeDisposition.Transfer, UserMergeDisposition.Conditional];

/**
 * The coverage suite proves the manifest logic on mock handlers. This one asks the question of
 * the handlers the platform actually registers.
 *
 * The deletion gate refuses to delete a merged source while a `transfer` or `conditional` row has
 * no handler. A row added to the register without one would ship a merge whose source can never
 * be deleted, and nothing but this test would say so before an operator hits the refusal.
 */
describe('userMerge registered handlers coverage', () => {
  it('should register the handlers at module load', () => {
    expect(userMergeHandlers().length).toBeGreaterThan(0);
  });

  it('should answer for every transfer and conditional row of the register', () => {
    const coverage = buildUserMergeCoverage();
    const uncovered = coverage.rows.filter((row) => GATING.includes(row.disposition) && !row.covered).map((row) => row.row_id);
    expect(uncovered, 'register rows a handler must claim: add the row to a handler `covers`').toEqual([]);
    expect(coverage.is_complete).toBe(true);
  });
});
