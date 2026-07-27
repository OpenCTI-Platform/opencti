import { useEffect } from 'react';

/**
 * List of sort fields that rely on ElasticSearch runtime mappings.
 * These fields are NOT supported by OpenSearch, which does not implement runtime mappings.
 *
 * ⚠️ MAINTENANCE: This list MUST be kept in sync with `RUNTIME_ATTRIBUTES` defined in the back-end:
 * opencti-platform/opencti-graphql/src/database/engine.ts
 *
 * If you add a new runtime attribute in `RUNTIME_ATTRIBUTES` AND expose it as a sortable column
 * in the front-end (isSortable: true), you MUST add its field name here too.
 * Failing to do so will cause an UnsupportedError on OpenSearch instances.
 */
export const RUNTIME_ONLY_SORT_FIELDS = ['createdBy', 'objectAssignee', 'objectParticipant', 'objectMarking'];
export const FALLBACK_SORT_FIELD = 'created_at';

/**
 * Resets the active sort field to a safe default when runtime sorting is disabled
 * and the persisted sort field (from localStorage/URL) is a runtime-only field.
 *
 * This guards against stale sort values that would trigger an UnsupportedError
 * on OpenSearch, which does not support Elasticsearch runtime mappings.
 *
 * Returns the safe sort field synchronously (computed during render) so callers can
 * use it immediately in query variables — preventing the initial Relay query from
 * being fired with an unsupported orderBy before the effect has a chance to run.
 * The useEffect still runs to repair the persisted localStorage/URL value.
 *
 * @param isRuntimeSort - Whether runtime sorting is supported by the current search engine.
 * @param sortBy - The currently active sort field (may come from localStorage/URL).
 * @param handleSort - Callback to update the sort field.
 * @returns The safe sort field to use for the current query.
 */
const useRuntimeSortGuard = (
  isRuntimeSort: boolean,
  sortBy: string | undefined,
  handleSort: (field: string, orderAsc: boolean) => void,
): string => {
  const isUnsafe = !isRuntimeSort && RUNTIME_ONLY_SORT_FIELDS.includes(sortBy ?? '');
  const safeSortBy = isUnsafe ? FALLBACK_SORT_FIELD : (sortBy ?? FALLBACK_SORT_FIELD);

  useEffect(() => {
    if (isUnsafe) {
      handleSort(FALLBACK_SORT_FIELD, false);
    }
  }, [isRuntimeSort, sortBy]);

  return safeSortBy;
};

export default useRuntimeSortGuard;
