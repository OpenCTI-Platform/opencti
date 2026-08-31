import { DatabaseError } from '../../config/errors';
import { elBulk, elRawSearch, elRawUpdateByQuery } from '../../database/engine';
import { logApp } from '../../config/conf';
import type { AuthContext } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';

/** What an update actually did. All four counters are surfaced, none is swallowed. */
export interface UserMergeBulkResult {
  updated: number;
  total: number;
  failures: unknown[];
  version_conflicts: number;
}

/**
 * Bulk update primitive for the merge engine.
 *
 * None of the platform's existing paths is usable here, and this is what the coverage
 * manifest's real counts depend on:
 *
 * - `elOperationForMigration` polls the task until `completed` and logs the duration, but
 *   never inspects `failures` or `version_conflicts`, and returns nothing. A task that
 *   updates 3 000 documents out of 10 000 and conflicts on the rest is reported as a success.
 * - The other bulk paths run with `conflicts: 'proceed'`, silently skipping conflicting
 *   documents; one of them is fire-and-forget, with no task follow-up at all.
 *
 * This wrapper surfaces the counters and fails on any non-empty failure or conflict. The
 * platform is supposed to be at rest during a merge, so a conflict means the execution
 * precondition was violated — precisely when to stop rather than carry on.
 */
export const userMergeBulkUpdate = async (
  label: string,
  indices: string[],
  body: Record<string, unknown>,
): Promise<UserMergeBulkResult> => {
  const response = await elRawUpdateByQuery({
    index: indices,
    refresh: true,
    // Deliberately not 'proceed': a conflict is a violated precondition, not something to skip.
    conflicts: 'abort',
    wait_for_completion: true,
    body,
  }).catch((err) => {
    throw DatabaseError('User merge bulk update failed', { label, cause: err });
  });
  const result: UserMergeBulkResult = {
    updated: response.updated ?? 0,
    total: response.total ?? 0,
    failures: response.failures ?? [],
    version_conflicts: response.version_conflicts ?? 0,
  };
  if (result.failures.length > 0 || result.version_conflicts > 0) {
    throw DatabaseError('User merge bulk update reported failures or version conflicts', {
      label,
      updated: result.updated,
      total: result.total,
      failure_count: result.failures.length,
      version_conflicts: result.version_conflicts,
    });
  }
  logApp.info('[MERGE_USERS] bulk update done', { label, updated: result.updated, total: result.total });
  return result;
};

/** Page size of the rewrite scan. The entities carrying filters are configuration objects. */
const USER_MERGE_REWRITE_PAGE_SIZE = 500;

/** Documents selected for a rewrite the engine cannot express as a script. */
export interface UserMergeRewriteCandidate {
  id: string;
  index: string;
  source: Record<string, any>;
}

/**
 * Reads the documents a query selects, across every merge index.
 *
 * `_update_by_query` covers the rewrites a painless script can express. A filter field holds a
 * serialized filter group, which has to be parsed, walked and re-serialized — so these targets
 * are read into memory, rewritten there, and written back. The volumes are those of the
 * configuration entities that carry filters, orders of magnitude below the data indices.
 *
 * Paged with `search_after`, so the scan does not depend on `from`/`size` staying under the
 * result window. `internal_id` alone would not do as a sort key here: the merge scope spans the
 * live indices, the trash and the drafts, and a draft copy is a reindex that renames `_id` while
 * keeping the `internal_id` of the document it copies. Two copies then share a sort value, and
 * `search_after` being strictly greater would drop whichever falls after a page boundary — the
 * document would be skipped with no error and no trace. `_index` breaks the tie, and it is the
 * concrete index name even when the search goes through an alias, which is what the candidate
 * carries anyway.
 */
export const userMergeScanForRewrite = async (
  context: AuthContext,
  indices: string[],
  query: Record<string, unknown>,
): Promise<UserMergeRewriteCandidate[]> => {
  const candidates: UserMergeRewriteCandidate[] = [];
  let searchAfter: unknown[] | undefined;
  for (;;) {
    const body: Record<string, unknown> = {
      query,
      sort: [{ 'internal_id.keyword': 'asc' }, { _index: 'asc' }],
      ...(searchAfter ? { search_after: searchAfter } : {}),
    };

    const page = await elRawSearch(context, SYSTEM_USER, 'None', {
      index: indices,
      size: USER_MERGE_REWRITE_PAGE_SIZE,
      track_total_hits: false,
      body,
    }).catch((err: unknown) => {
      throw DatabaseError('User merge rewrite scan failed', { cause: err });
    });
    const hits = page.hits?.hits ?? [];
    hits.forEach((hit: any) => {
      candidates.push({ id: hit._id, index: hit._index, source: hit._source });
    });
    if (hits.length < USER_MERGE_REWRITE_PAGE_SIZE) {
      return candidates;
    }
    searchAfter = hits[hits.length - 1].sort;
  }
};

/**
 * Writes back the documents the caller rewrote, each in the index it was read from.
 *
 * Partial documents rather than whole ones: a merge rewrites one field and must not resurrect
 * the rest of a document read a moment earlier.
 */
export const userMergeBulkRewrite = async (
  context: AuthContext,
  label: string,
  updates: { id: string; index: string; doc: Record<string, unknown> }[],
): Promise<number> => {
  if (updates.length === 0) {
    return 0;
  }
  const body = updates.flatMap((update) => [
    { update: { _index: update.index, _id: update.id } },
    { doc: update.doc },
  ]);
  await elBulk(context, { refresh: true, timeout: '60m', body }).catch((err: unknown) => {
    throw DatabaseError('User merge bulk rewrite failed', { label, cause: err });
  });
  logApp.info('[MERGE_USERS] bulk rewrite done', { label, updated: updates.length });
  return updates.length;
};
