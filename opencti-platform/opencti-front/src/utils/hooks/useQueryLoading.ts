import { GraphQLTaggedNode, useQueryLoader, UseQueryLoaderLoadQueryOptions, VariablesOf } from 'react-relay';
import { OperationType, PreloadableConcreteRequest } from 'relay-runtime';
import { useEffect, useRef } from 'react';
import { equals } from 'ramda';
import { useQueryLoaderHookType } from 'react-relay/relay-hooks/useQueryLoader';

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

export const useQueryLoadingWithLoadQuery = <T extends OperationType>(
  query: GraphQLTaggedNode | PreloadableConcreteRequest<T>,
  variables: VariablesOf<T> = {},
  opts?: UseQueryLoaderLoadQueryOptions,
): [useQueryLoaderHookType<T>[0], useQueryLoaderHookType<T>[1]] => {
  const [queryRef, loadQuery] = useQueryLoader<T>(query);
  const varRef = useRef(variables);
  if (!equals(variables, varRef.current)) {
    varRef.current = variables;
  }
  // refetch when variables change
  useEffect(() => {
    loadQuery(variables, { ...opts, fetchPolicy: 'store-and-network' });
  }, [varRef.current]);

  return [queryRef, loadQuery];
};

export default useQueryLoading;
