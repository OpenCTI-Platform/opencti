import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_EDITOR, USER_PARTICIPATE } from '../../../utils/testQuery';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
import { resetCacheForEntity } from '../../../../src/database/cache';
import { addUser, userDelete } from '../../../../src/domain/user';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { SYSTEM_USER } from '../../../../src/utils/access';

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

const readUser = async (userId: string) => {
  const { data } = await queryAsAdminWithSuccess({
    query: gql`query ReadUser($id: String!) { user(id: $id) { id name user_email } }`,
    variables: { id: userId },
  });
  return data.user;
};

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
    await userDelete(testContext, ADMIN_USER, mergeSourceId);
    await userDelete(testContext, ADMIN_USER, mergeTargetId);
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
      // The two accounts are created empty by this file, so a real merge that writes anything
      // is a handler reaching outside what the source actually owns.
      expect(real.data.userMerge.report.total_updated).toEqual(0);
    });

    it('should carry the coverage in the report of every execution', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId, options: { dryRun: true } },
      });
      expect(data.userMerge.report.merge_id).toEqual(data.userMerge.id);
      expect(data.userMerge.report.total_updated).toEqual(0);
      // Three handlers succeeding reads as a complete merge unless the report also says
      // what the register still holds.
      expect(data.userMerge.report.coverage.is_complete).toBe(false);
      expect(data.userMerge.report.coverage.total).toEqual(101);
    });

    it('should carry the requested rights strategy', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId, options: { rightsStrategy: 'UNION' } },
      });
      expect(data.userMerge.rights_strategy).toBe('UNION');
    });

    it('should leave the user entities themselves untouched', async () => {
      const sourceBefore = await readUser(mergeSourceId);
      const targetBefore = await readUser(mergeTargetId);
      await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: mergeSourceId, targetId: mergeTargetId, options: { dryRun: false } },
      });
      expect(await readUser(mergeSourceId)).toEqual(sourceBefore);
      expect(await readUser(mergeTargetId)).toEqual(targetBefore);
    });
  });

  describe('Coverage query', () => {
    it('should name what no handler covers', async () => {
      const { data } = await queryAsAdminWithSuccess({ query: USER_MERGE_COVERAGE_QUERY, variables: {} });
      expect(data.userMergeCoverage.total).toEqual(101);
      expect(data.userMergeCoverage.rows.length).toEqual(101);
      // The register is what says the merge is incomplete, whatever the handlers claim.
      expect(data.userMergeCoverage.covered_count).toBeGreaterThan(0);
      expect(data.userMergeCoverage.uncovered_count).toEqual(101 - data.userMergeCoverage.covered_count);
      expect(data.userMergeCoverage.is_complete).toBe(false);
    });

    it('should keep the counts on the whole register when filtering', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_COVERAGE_QUERY,
        variables: { disposition: 'TRANSFER' },
      });
      expect(data.userMergeCoverage.rows.length).toEqual(40);
      expect(data.userMergeCoverage.total).toEqual(101);
      expect(data.userMergeCoverage.is_complete).toBe(false);
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
});
