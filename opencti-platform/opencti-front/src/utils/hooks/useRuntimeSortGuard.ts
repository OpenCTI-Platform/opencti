import { useEffect } from 'react';

export const RUNTIME_ONLY_SORT_FIELDS = ['createdBy', 'objectAssignee', 'objectParticipant'];
export const FALLBACK_SORT_FIELD = 'created_at';

/**
 * Resets the active sort field to a safe default when runtime sorting is disabled
 * and the persisted sort field (from localStorage/URL) is a runtime-only field.
 *
 * This guards against stale sort values that would trigger an UnsupportedError
 * on OpenSearch, which does not support Elasticsearch runtime mappings.
 *
 * @param isRuntimeSort - Whether runtime sorting is supported by the current search engine.
 * @param sortBy - The currently active sort field (may come from localStorage/URL).
 * @param handleSort - Callback to update the sort field.
 */
const useRuntimeSortGuard = (
  isRuntimeSort: boolean,
  sortBy: string | undefined,
  handleSort: (field: string, orderAsc: boolean) => void,
): void => {
  useEffect(() => {
    if (!isRuntimeSort && RUNTIME_ONLY_SORT_FIELDS.includes(sortBy ?? '')) {
      handleSort(FALLBACK_SORT_FIELD, false);
    }
  }, [isRuntimeSort]);
};

export default useRuntimeSortGuard;
