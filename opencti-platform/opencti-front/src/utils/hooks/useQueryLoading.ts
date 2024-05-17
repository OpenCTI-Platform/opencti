import { GraphQLTaggedNode, useQueryLoader, UseQueryLoaderLoadQueryOptions, VariablesOf } from 'react-relay';
import { OperationType, PreloadableConcreteRequest } from 'relay-runtime';
import { useEffect, useRef } from 'react';
import { equals } from 'ramda';

const useQueryLoading = <T extends OperationType>(
  query: GraphQLTaggedNode | PreloadableConcreteRequest<T>,
  variables: VariablesOf<T> = {},
  opts?: UseQueryLoaderLoadQueryOptions,
) => {
  const [queryRef, loadQuery] = useQueryLoader<T>(query);
  const varRef = useRef(variables);
  if (!equals(variables, varRef.current)) {
    varRef.current = variables;
  }
  // refetch when variables change
  useEffect(() => {
    loadQuery(variables, { ...opts, fetchPolicy: 'store-and-network' });
  }, [varRef.current]);

  return queryRef;
};

export default useQueryLoading;
