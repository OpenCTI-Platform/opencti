import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_EDITOR, USER_PARTICIPATE } from '../../../utils/testQuery';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { addUser, userDelete, userEditField } from '../../../../src/domain/user';
import { deleteMergeableUser } from './userMerge-testFixtures';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { ACCOUNT_STATUS_ACTIVE, ACCOUNT_STATUS_EXPIRED } from '../../../../src/config/conf';
import { registerRowsByDisposition, USER_MERGE_REGISTER, UserMergeDisposition } from '../../../../src/modules/userMerge/userMerge-register';
import { USER_MERGE_SOURCE_DISABLE_HANDLER } from '../../../../src/modules/userMerge/userMerge-handler';
import { USER_MERGED_INTO_FIELD } from '../../../../src/modules/userMerge/userMerge-types';

/**
 * Handlers that write on the source account itself rather than on what it owns. A chunk adding
 * one belongs here; a handler appearing here that was not added on purpose is the bug this test
 * is looking for.
 */
const SOURCE_ACCOUNT_HANDLERS: string[] = [USER_MERGE_SOURCE_DISABLE_HANDLER];

/**
 * Read from the register rather than written down. What these tests state is that the API reports
 * the register whole and keeps its counts under a filter — not how many rows it holds today. A
 * transcribed count says nothing more and turns every register edit into a test to fix.
 */
const REGISTER_SIZE = USER_MERGE_REGISTER.length;
const TRANSFER_ROWS = registerRowsByDisposition(UserMergeDisposition.Transfer).length;

const USER_MERGE_MUTATION = gql`
  mutation UserMerge($sourceId: ID!, $targetId: ID!, $options: UserMergeOptions) {
    userMerge(sourceId: $sourceId, targetId: $targetId, options: $options) {
      id
      source_id
      target_id
      dry_run
      rights_strategy
      status
      started_at
      completed_at
      message
      report {
        merge_id
        register_version
        total_updated
        handlers {
          handler
          updated
        }
        coverage {
          total
          covered_count
          is_complete
        }
      }
    }
  }
`;

const USER_MERGE_COVERAGE_QUERY = gql`
  query UserMergeCoverage($disposition: UserMergeDisposition) {
    userMergeCoverage(disposition: $disposition) {
      register_version
      total
      covered_count
      uncovered_count
      is_complete
      rows {
        row_id
        label
        path
        disposition
        covered
        handler
      }
    }
  }
`;

const USER_MERGE_JOURNAL_QUERY = gql`
  query UserMergeJournal($mergeId: ID, $first: Int) {
    userMergeJournal(mergeId: $mergeId, first: $first) {
      id
      merge_id
      source_id
      target_id
      handler
      dry_run
      status
      started_at
      completed_at
      message
    }
  }
`;

const USER_MERGE_READINESS_QUERY = gql`
  query UserMergeSourceDeletionReadiness($sourceId: ID!, $targetId: ID!) {
    userMergeSourceDeletionReadiness(sourceId: $sourceId, targetId: $targetId) {
      allowed
      coverage_complete
      pending_change_count
      blockers
    }
  }
`;

const readUser = async (userId: string) => {
  const { data } = await queryAsAdminWithSuccess({
    query: gql`query ReadUser($id: String!) { user(id: $id) { id name user_email account_status } }`,
    variables: { id: userId },
  });
  return data.user;
};

/** The fields a merge never rewrites, isolated from the status, which it does rewrite. */
const profileOf = (user: { id: string; name: string; user_email: string }) => ({ id: user.id, name: user.name, user_email: user.user_email });

const SUFFIX = 'userMergeResolvers';

// The engine writes for real in these tests, so it is given two accounts of its own rather than
// the shared fixtures: what the rest of the suite hangs on USER_PARTICIPATE would otherwise be
// rewritten here, and the "nothing was touched" assertions would depend on the run order. The
// default groups are declined so that the two accounts own strictly nothing, which is what makes
// a write of zero the expected outcome.
let mergeSourceId: string;
let mergeTargetId: string;

describe('User merge resolvers', () => {
  beforeAll(async () => {
    const account = (role: string) => ({
      name: `${SUFFIX}-${role}`,
      password: SUFFIX,
      user_email: `${SUFFIX}-${role}@opencti.invalid`,
      prevent_default_groups: true,
    });
    const source = await addUser(testContext, SYSTEM_USER, account('source'));
    const target = await addUser(testContext, SYSTEM_USER, account('target'));
    mergeSourceId = source.id;
    mergeTargetId = target.id;
    // The engine resolves both users from the platform cache, which the stream only refreshes
    // asynchronously.
    resetCacheForEntity(ENTITY_TYPE_USER);
  });

  afterAll(async () => {
    await deleteMergeableUser(mergeSourceId);
    await deleteMergeableUser(mergeTargetId);
  });

  describe('Access control - BYPASS capability required', () => {
    it('should refuse the mutation to a user without BYPASS', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: USER_MERGE_MUTATION,
        variables: { sourceId: USER_EDITOR.id, targetId: USER_PARTICIPATE.id },
      });
    });

    it('should refuse the journal query to a user without BYPASS', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: USER_MERGE_JOURNAL_QUERY,
        variables: {},
      });
    });
  });

  describe('Input validation', () => {
    it('should refuse to merge a user into itself', async () => {
      await queryAsAdminWithError({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: USER_PARTICIPATE.id, targetId: USER_PARTICIPATE.id },
      }, 'Cannot merge a user into itself');
    });

    it('should refuse an unknown source user', async () => {
      await queryAsAdminWithError({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: 'not-an-existing-user', targetId: USER_PARTICIPATE.id },
      }, 'Unknown source user');
    });

    it('should refuse an unknown target user', async () => {
      await queryAsAdminWithError({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: USER_PARTICIPATE.id, targetId: 'not-an-existing-user' },
      }, 'Unknown target user');
    });
  });

  describe('Contract of the engine', () => {
    it('should default to a dry-run when no option is provided', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId },
      });
      expect(data.userMerge.dry_run).toBe(true);
      expect(data.userMerge.rights_strategy).toBe('STRICT');
    });

    it('should return the same shape in dry and in real mode', async () => {
      const dry = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId, options: { dryRun: true } },
      });
      const real = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId, options: { dryRun: false } },
      });
      expect(Object.keys(real.data.userMerge).sort()).toEqual(Object.keys(dry.data.userMerge).sort());
      expect(real.data.userMerge.dry_run).toBe(false);
      expect(dry.data.userMerge.dry_run).toBe(true);
      // The two accounts are created empty by this file, so nothing a handler moves on behalf of
      // the source can be found. What a real merge still writes here is the source account itself,
      // which is not a handler reaching outside what the source owns — it is the merge closing it.
      // Asserting a total instead would have to be revised by every chunk that touches the account.
      const reachedOutside = real.data.userMerge.report.handlers
        .filter((outcome: { handler: string; updated: number }) => !SOURCE_ACCOUNT_HANDLERS.includes(outcome.handler) && outcome.updated > 0);
      expect(reachedOutside).toEqual([]);
    });

    it('should carry the coverage in the report of every execution', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId, options: { dryRun: true } },
      });
      const { data: standalone } = await queryAsAdminWithSuccess({ query: USER_MERGE_COVERAGE_QUERY, variables: {} });
      expect(data.userMerge.report.merge_id).toEqual(data.userMerge.id);
      expect(data.userMerge.report.total_updated).toEqual(0);
      // Handlers succeeding reads as a complete merge unless the report also says what the
      // register still holds. Compared with the dedicated query rather than to a written-down
      // verdict: the point is that a run reports the register, not a summary of itself.
      expect(data.userMerge.report.coverage.total).toEqual(REGISTER_SIZE);
      expect(data.userMerge.report.coverage.covered_count).toEqual(standalone.userMergeCoverage.covered_count);
      expect(data.userMerge.report.coverage.is_complete).toBe(standalone.userMergeCoverage.is_complete);
    });

    it('should carry the requested rights strategy', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId, options: { rightsStrategy: 'UNION' } },
      });
      expect(data.userMerge.rights_strategy).toBe('UNION');
    });

    it('should leave the profile of both accounts untouched', async () => {
      const sourceBefore = await readUser(mergeSourceId);
      const targetBefore = await readUser(mergeTargetId);
      await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId, options: { dryRun: false } },
      });
      // The source is compared on its profile only: a merge closes that account, so comparing the
      // whole entity would either hide the one write it is supposed to make or contradict it. The
      // status is asserted by the next case rather than left out of both.
      expect(profileOf(await readUser(mergeSourceId))).toEqual(profileOf(sourceBefore));
      expect(await readUser(mergeTargetId)).toEqual(targetBefore);
    });

    it('should close the source account and leave the target open', async () => {
      await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId, options: { dryRun: false } },
      });
      // Asserted as an end state, not as a transition: earlier cases in this file already run real
      // merges on the same pair, so a handler that only worked on a still-active source would pass
      // a before/after check by doing nothing at all.
      expect((await readUser(mergeSourceId)).account_status).toEqual(ACCOUNT_STATUS_EXPIRED);
      expect((await readUser(mergeTargetId)).account_status).toEqual(ACCOUNT_STATUS_ACTIVE);
    });

    // The dedicated deletion path is what an operator is meant to use, but nothing removes the
    // ordinary delete button from the user administration screen. That button runs cascades which
    // select by a reference to the account being deleted, so on a merged source a reference the
    // merge missed gets its Trigger or its Workspace deleted rather than skipped — and those now
    // belong to the target. This asserts the ordinary path stops, and that it can be re-opened.
    it('should refuse the ordinary deletion of a merged source until its mark is cleared', async () => {
      // Its own source: this case ends by deleting it, and the shared one is still needed after.
      const disposable = await addUser(testContext, SYSTEM_USER, {
        name: `${SUFFIX}-disposable`,
        password: SUFFIX,
        user_email: `${SUFFIX}-disposable@opencti.invalid`,
        prevent_default_groups: true,
      });
      resetCacheForEntity(ENTITY_TYPE_USER);
      await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: disposable.id, targetId: mergeTargetId, options: { dryRun: false } },
      });

      await expect(userDelete(testContext, ADMIN_USER, disposable.id)).rejects.toThrow();
      expect((await readUser(disposable.id)).id).toEqual(disposable.id);

      await userEditField(testContext, ADMIN_USER, disposable.id, [{ key: USER_MERGED_INTO_FIELD, value: [null] }]);
      await expect(userDelete(testContext, ADMIN_USER, disposable.id)).resolves.toBeDefined();
    });
  });

  describe('Coverage query', () => {
    it('should name what no handler covers', async () => {
      const { data } = await queryAsAdminWithSuccess({ query: USER_MERGE_COVERAGE_QUERY, variables: {} });
      expect(data.userMergeCoverage.total).toEqual(REGISTER_SIZE);
      expect(data.userMergeCoverage.rows.length).toEqual(REGISTER_SIZE);
      // The register is what says what is left, whatever the handlers claim. An uncovered row
      // has to be listed and named as uncovered rather than dropped from the answer.
      expect(data.userMergeCoverage.covered_count).toBeGreaterThan(0);
      expect(data.userMergeCoverage.uncovered_count).toEqual(REGISTER_SIZE - data.userMergeCoverage.covered_count);
      const uncovered = data.userMergeCoverage.rows.filter((row: { covered: boolean }) => !row.covered);
      expect(uncovered.length).toEqual(data.userMergeCoverage.uncovered_count);
      uncovered.forEach((row: { handler: string | null }) => expect(row.handler).toBeFalsy());
    });

    it('should keep the counts on the whole register when filtering', async () => {
      const { data: whole } = await queryAsAdminWithSuccess({ query: USER_MERGE_COVERAGE_QUERY, variables: {} });
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_COVERAGE_QUERY,
        variables: { disposition: 'TRANSFER' },
      });
      expect(data.userMergeCoverage.rows.length).toEqual(TRANSFER_ROWS);
      expect(data.userMergeCoverage.rows.length).toBeLessThan(REGISTER_SIZE);
      // Narrowing the question must not be able to narrow the answer: the counts and the
      // verdict stay those of the whole register.
      expect(data.userMergeCoverage.total).toEqual(REGISTER_SIZE);
      expect(data.userMergeCoverage.covered_count).toEqual(whole.userMergeCoverage.covered_count);
      expect(data.userMergeCoverage.is_complete).toBe(whole.userMergeCoverage.is_complete);
    });

    it('should be refused without BYPASS', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: USER_MERGE_COVERAGE_QUERY, variables: {} });
    });
  });

  describe('Journal query', () => {
    it('should be readable without a merge id', async () => {
      const { data } = await queryAsAdminWithSuccess({ query: USER_MERGE_JOURNAL_QUERY, variables: {} });
      expect(Array.isArray(data.userMergeJournal)).toBe(true);
    });

    it('should return nothing for a merge id that never ran', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_JOURNAL_QUERY,
        variables: { mergeId: 'never-ran-merge-id', first: 10 },
      });
      expect(data.userMergeJournal).toEqual([]);
    });
  });

  describe('Source deletion readiness query', () => {
    it('should refuse the deletion while the register is not covered whole', async () => {
      const { data: coverage } = await queryAsAdminWithSuccess({ query: USER_MERGE_COVERAGE_QUERY, variables: {} });
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_READINESS_QUERY,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId },
      });
      const readiness = data.userMergeSourceDeletionReadiness;
      // Compared with the coverage query rather than with a written-down verdict: what this states
      // is that the gate answers from the register, not how covered the register is today.
      expect(readiness.coverage_complete).toBe(coverage.userMergeCoverage.is_complete);
      expect(readiness.allowed).toBe(readiness.coverage_complete && readiness.pending_change_count === 0);
      expect(readiness.blockers.length === 0).toBe(readiness.allowed);
    });

    it('should refuse an unknown user before answering', async () => {
      await queryAsAdminWithError({
        query: USER_MERGE_READINESS_QUERY,
        variables: { sourceId: 'unknown-source-id', targetId: mergeTargetId },
      }, 'Unknown source user');
    });

    it('should be refused without BYPASS', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
        query: USER_MERGE_READINESS_QUERY,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId },
      });
    });
  });
});
