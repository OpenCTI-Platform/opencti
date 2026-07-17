import { useFragment, usePreloadedQuery } from 'react-relay';
import type { PreloadedQuery } from 'react-relay';
import type { KeyType } from 'react-relay/ReactRelayTypes';
import { GraphQLTaggedNode, OperationType } from 'relay-runtime';

interface UsePreloadedPaginationFragment<QueryType extends OperationType> {
  queryRef: PreloadedQuery<QueryType>;
  queryDef: GraphQLTaggedNode;
  fragmentDef: GraphQLTaggedNode;
  nodePath?: string;
}

const usePreloadedFragment = <QueryType extends OperationType, FragmentKey extends KeyType>({
  queryRef,
  queryDef,
  fragmentDef,
  nodePath,
}: UsePreloadedPaginationFragment<QueryType>) => {
  const queryData = usePreloadedQuery(queryDef, queryRef);
  if (nodePath) {
    return useFragment(
      fragmentDef,
      queryData[nodePath as keyof typeof queryData] as FragmentKey,
    );
  }
  return useFragment(fragmentDef, queryData as FragmentKey);
};

export default usePreloadedFragment;
