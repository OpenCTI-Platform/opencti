import { PreloadedQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import { useCallback, useEffect } from 'react';
import { FragmentType, GraphQLTaggedNode, OperationType } from 'relay-runtime';
import { UseLocalStorageHelpers } from './useLocalStorage';
import { numberFormat } from '../Number';

type KeyType<TData = unknown> = Readonly<{
  ' $data'?: TData | undefined;
  ' $fragmentSpreads': FragmentType;
}>;

export interface UsePreloadedPaginationFragment<QueryType extends OperationType> {
  queryRef: PreloadedQuery<QueryType>;
  linesQuery: GraphQLTaggedNode;
  linesFragment: GraphQLTaggedNode;
  nodePath?: string[];
  setNumberOfElements?: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

const usePreloadedPaginationFragment = <QueryType extends OperationType, FragmentKey extends KeyType>({
  queryRef,
  linesQuery,
  linesFragment,
  nodePath,
  setNumberOfElements,
}: UsePreloadedPaginationFragment<QueryType>) => {
  const queryData = usePreloadedQuery(linesQuery, queryRef) as FragmentKey;
  const { data, hasNext, loadNext, isLoadingNext } = usePaginationFragment<QueryType, FragmentKey>(linesFragment, queryData);
  useEffect(() => {
    const deep_value = (nodePath ?? []).reduce(
      (a, v) => a[v as keyof object],
      data,
    ) as number;
    if (setNumberOfElements && Number.isInteger(deep_value)) {
      setNumberOfElements(numberFormat(deep_value));
    }
  }, [data]);

  // Wrap loadNext to accept either a direct callback as second argument
  // (used by ListLinesContent / ListCardsContent: loadMore(count, callback))
  // or a Relay options object (used by DataTableBody: loadMore(count)).
  // Relay's loadNext expects (count, { onComplete }), so without this
  // wrapper a direct callback is silently dropped, leaving the loading
  // state stale and preventing further pagination.
  const loadMore = useCallback(
    (count: number, callbackOrOptions?: (() => void) | { onComplete?: (err: Error | null) => void }) => {
      if (typeof callbackOrOptions === 'function') {
        loadNext(count, { onComplete: callbackOrOptions });
      } else {
        loadNext(count, callbackOrOptions);
      }
    },
    [loadNext],
  );

  return {
    data,
    hasMore: () => hasNext,
    isLoadingMore: () => isLoadingNext,
    isLoading: isLoadingNext,
    loadMore,
  };
};

export default usePreloadedPaginationFragment;
