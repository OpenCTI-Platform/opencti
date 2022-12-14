import { useFragment, usePreloadedQuery } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import { KeyType } from 'react-relay/relay-hooks/helpers';

interface UsePreloadedPaginationFragment<QueryType extends OperationType> {
  queryRef: PreloadedQuery<QueryType>
  linesQuery: GraphQLTaggedNode
  linesFragment: GraphQLTaggedNode
}

const usePreloadedFragment = <QueryType extends OperationType, FragmentKey extends KeyType>({
  queryRef,
  linesQuery,
  linesFragment,
}: UsePreloadedPaginationFragment<QueryType>) => {
  const queryData = usePreloadedQuery(linesQuery, queryRef) as FragmentKey;
  return useFragment(linesFragment, queryData);
};

export default usePreloadedFragment;
