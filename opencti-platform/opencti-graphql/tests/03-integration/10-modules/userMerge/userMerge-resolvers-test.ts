import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { USER_EDITOR, USER_PARTICIPATE } from '../../../utils/testQuery';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';

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
        registry_version
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
      registry_version
      total
      covered_count
      uncovered_count
      is_complete
      rows {
        row_id
        entity
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

describe('User merge resolvers', () => {
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
        variables: { sourceId: USER_PARTICIPATE.id, targetId: USER_EDITOR.id },
      });
      expect(data.userMerge.dry_run).toBe(true);
      expect(data.userMerge.rights_strategy).toBe('STRICT');
    });

    it('should return the same shape in dry and in real mode', async () => {
      const dry = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: USER_PARTICIPATE.id, targetId: USER_EDITOR.id, options: { dryRun: true } },
      });
      const real = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: USER_PARTICIPATE.id, targetId: USER_EDITOR.id, options: { dryRun: false } },
      });
      expect(Object.keys(real.data.userMerge).sort()).toEqual(Object.keys(dry.data.userMerge).sort());
      expect(real.data.userMerge.dry_run).toBe(false);
      expect(dry.data.userMerge.dry_run).toBe(true);
      // These two accounts own nothing in the test dataset; asserting it keeps a real merge
      // from quietly rewriting shared fixtures if that ever stops being true.
      expect(real.data.userMerge.report.total_updated).toEqual(0);
    });

    it('should carry the coverage in the report of every execution', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: USER_PARTICIPATE.id, targetId: USER_EDITOR.id, options: { dryRun: true } },
      });
      expect(data.userMerge.report.merge_id).toEqual(data.userMerge.id);
      expect(data.userMerge.report.total_updated).toEqual(0);
      // Three handlers succeeding reads as a complete merge unless the report also says
      // what the register still holds.
      expect(data.userMerge.report.coverage.is_complete).toBe(false);
      expect(data.userMerge.report.coverage.total).toEqual(100);
    });

    it('should carry the requested rights strategy', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: USER_PARTICIPATE.id, targetId: USER_EDITOR.id, options: { rightsStrategy: 'UNION' } },
      });
      expect(data.userMerge.rights_strategy).toBe('UNION');
    });

    it('should leave the user entities themselves untouched', async () => {
      const sourceBefore = await readUser(USER_PARTICIPATE.id);
      const targetBefore = await readUser(USER_EDITOR.id);
      await queryAsAdminWithSuccess({
        query: USER_MERGE_MUTATION,
        variables: { sourceId: USER_PARTICIPATE.id, targetId: USER_EDITOR.id, options: { dryRun: false } },
      });
      expect(await readUser(USER_PARTICIPATE.id)).toEqual(sourceBefore);
      expect(await readUser(USER_EDITOR.id)).toEqual(targetBefore);
    });
  });

  describe('Coverage query', () => {
    it('should name what no handler covers', async () => {
      const { data } = await queryAsAdminWithSuccess({ query: USER_MERGE_COVERAGE_QUERY, variables: {} });
      expect(data.userMergeCoverage.total).toEqual(100);
      expect(data.userMergeCoverage.rows.length).toEqual(100);
      // The register is what says the merge is incomplete, whatever the handlers claim.
      expect(data.userMergeCoverage.covered_count).toBeGreaterThan(0);
      expect(data.userMergeCoverage.uncovered_count).toEqual(100 - data.userMergeCoverage.covered_count);
      expect(data.userMergeCoverage.is_complete).toBe(false);
    });

    it('should keep the counts on the whole register when filtering', async () => {
      const { data } = await queryAsAdminWithSuccess({
        query: USER_MERGE_COVERAGE_QUERY,
        variables: { disposition: 'TRANSFER' },
      });
      expect(data.userMergeCoverage.rows.length).toEqual(39);
      expect(data.userMergeCoverage.total).toEqual(100);
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
