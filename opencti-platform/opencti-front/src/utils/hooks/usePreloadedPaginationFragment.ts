import { PreloadedQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import { useEffect } from 'react';
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

  return {
    data,
    hasMore: () => hasNext,
    isLoadingMore: () => isLoadingNext,
    isLoading: isLoadingNext,
    loadMore: loadNext,
  };
};

export default usePreloadedPaginationFragment;
