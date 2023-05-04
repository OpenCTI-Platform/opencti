import { equals } from 'ramda';
import React, { useEffect, useRef } from 'react';
import { GraphQLTaggedNode, PreloadableConcreteRequest, PreloadedQuery, useQueryLoader, UseQueryLoaderLoadQueryOptions, VariablesOf } from 'react-relay';
import { OperationType } from 'relay-runtime';
import { useVocabularyCategoryQuery } from './__generated__/useVocabularyCategoryQuery.graphql';

interface QueryContextType {
  vocabularyCategoriesQueryRef?: PreloadedQuery<useVocabularyCategoryQuery>
}

export const QueryContext = React.createContext<QueryContextType>({
  vocabularyCategoriesQueryRef: undefined,
});

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
    loadQuery(variables, { fetchPolicy: 'store-and-network', ...opts });
  }, [varRef.current]);

  return queryRef;
};

export default useQueryLoading;
