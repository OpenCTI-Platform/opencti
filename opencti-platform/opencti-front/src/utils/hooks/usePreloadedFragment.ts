import { useFragment, usePreloadedQuery } from 'react-relay';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import { KeyType } from 'react-relay/relay-hooks/helpers';

interface UsePreloadedPaginationFragment<QueryType extends OperationType> {
  queryRef: PreloadedQuery<QueryType>
  linesQuery: GraphQLTaggedNode
  linesFragment: GraphQLTaggedNode
  nodePath?: string
}

const usePreloadedFragment = <QueryType extends OperationType, FragmentKey extends KeyType>({
  queryRef,
  linesQuery,
  linesFragment,
  nodePath,
}: UsePreloadedPaginationFragment<QueryType>) => {
  const queryData = usePreloadedQuery(linesQuery, queryRef);
  if (nodePath) {
    return useFragment(linesFragment, (queryData)[nodePath as keyof typeof queryData] as FragmentKey);
  }
  return useFragment(linesFragment, queryData as FragmentKey);
};

export default usePreloadedFragment;
