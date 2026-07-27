import { useEffect, useRef, useTransition } from 'react';
import { GraphQLTaggedNode, UseQueryLoaderLoadQueryOptions, VariablesOf, useQueryLoader } from 'react-relay';
import { OperationType, PreloadableConcreteRequest } from 'relay-runtime';
import { equals } from 'ramda';
import { useDashboardRefreshToken, useDashboardSetQueryPending } from '../../../components/dashboard/DashboardRefreshContext';

const usePublicDashboardViz = <T extends OperationType>(
  query: GraphQLTaggedNode | PreloadableConcreteRequest<T>,
  variables: VariablesOf<T> = {},
  opts?: UseQueryLoaderLoadQueryOptions,
) => {
  const [queryRef, loadQuery] = useQueryLoader<T>(query);
  const [isPending, startTransition] = useTransition();
  const refreshToken = useDashboardRefreshToken();
  const setQueryPending = useDashboardSetQueryPending();
  const queryIdRef = useRef(`public-dashboard-viz-${Math.random().toString(36).slice(2)}`);
  const varRef = useRef(variables);

  if (!equals(variables, varRef.current)) {
    varRef.current = variables;
  }

  useEffect(() => {
    startTransition(() => {
      loadQuery(varRef.current, { ...opts, fetchPolicy: 'store-and-network' });
    });
  }, [varRef.current, refreshToken]);

  // Expose this widget's in-flight status so the dashboard can lock the manual
  // refresh button until every widget has finished refreshing.
  useEffect(() => {
    const queryId = queryIdRef.current;
    setQueryPending(queryId, isPending);
    return () => setQueryPending(queryId, false);
  }, [isPending, setQueryPending]);

  return queryRef;
};

export default usePublicDashboardViz;
