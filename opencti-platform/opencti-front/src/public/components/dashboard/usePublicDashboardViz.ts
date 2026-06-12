import { useEffect, useRef, useTransition } from 'react';
import { GraphQLTaggedNode, UseQueryLoaderLoadQueryOptions, VariablesOf, useQueryLoader } from 'react-relay';
import { useQueryLoaderHookType } from 'react-relay/relay-hooks/useQueryLoader';
import { OperationType, PreloadableConcreteRequest } from 'relay-runtime';
import { equals } from 'ramda';
import { useDashboardRefreshToken } from '../../../components/dashboard/DashboardRefreshContext';

const usePublicDashboardViz = <T extends OperationType>(
  query: GraphQLTaggedNode | PreloadableConcreteRequest<T>,
  variables: VariablesOf<T> = {},
  opts?: UseQueryLoaderLoadQueryOptions,
) => {
  const [queryRef, loadQuery] = useQueryLoader<T>(query);
  const [, startTransition] = useTransition();
  const refreshToken = useDashboardRefreshToken();
  const varRef = useRef(variables);

  if (!equals(variables, varRef.current)) {
    varRef.current = variables;
  }

  useEffect(() => {
    startTransition(() => {
      loadQuery(varRef.current, { ...opts, fetchPolicy: 'store-and-network' });
    });
  }, [varRef.current, refreshToken]);

  return queryRef;
};

export default usePublicDashboardViz;
