import type { WidgetHost, WidgetDataSelection, WidgetPerspective, WidgetParameters } from '../../utils/widget/widget';
import useAuth from '../../utils/hooks/useAuth';
import { resolveDataSelection } from './dashboard-viz-utils';
import { useCallback, useEffect, useMemo, useRef, useTransition } from 'react';
import { useDashboardRefreshToken, useDashboardSetQueryPending } from './DashboardRefreshContext';
import { DashboardConfig } from './dashboard-types';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { useQueryLoader } from 'react-relay';
import { OperationType } from 'relay-runtime';

const useDashboardViz = <TQuery extends OperationType>({
  dataSelection,
  perspective,
  host,
  query,
  buildQueryVariables,
  parameters,
  config,
}: {
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  host?: WidgetHost;
  // Accepted for backward compatibility with widget props; no longer used for
  // scheduling (refresh is driven centrally by the refreshToken context).
  refreshRate?: number | null;
  query?: GraphQLTaggedNode;
  config?: DashboardConfig;
  parameters?: WidgetParameters;
  buildQueryVariables?: (resolvedDataSelection: WidgetDataSelection[], config: DashboardConfig, parameters?: WidgetParameters) => TQuery['variables'];
}) => {
  const [queryRef, load, disposeQuery] = useQueryLoader<TQuery>(query as GraphQLTaggedNode);
  const [isPending, startTransition] = useTransition();
  const lastLoadedVariablesSignatureRef = useRef<string | null>(null);
  const setQueryPending = useDashboardSetQueryPending();
  const queryIdRef = useRef(`dashboard-viz-${Math.random().toString(36).slice(2)}`);
  const { filterKeysSchema } = useAuth().schema;
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode } = useMemo(() => resolveDataSelection({
    filterKeysSchema,
    dataSelection,
    perspective,
    host,
  }), [filterKeysSchema, dataSelection, perspective, host]);

  const queryVariables = useMemo(
    () => (buildQueryVariables && config
      ? buildQueryVariables(resolvedDataSelection, config, parameters)
      : null),
    [buildQueryVariables, resolvedDataSelection, config, parameters],
  );

  const queryVariablesSignature = useMemo(
    () => (queryVariables ? JSON.stringify(queryVariables) : null),
    [queryVariables],
  );

  const loadAndTrackSignature = useCallback((variables: TQuery['variables'], signature: string) => {
    lastLoadedVariablesSignatureRef.current = signature;
    startTransition(() => {
      load(variables, {
        fetchPolicy: 'store-and-network',
      });
    });
  }, [load, startTransition]);

  const reloadData = useCallback((force = false) => {
    if (isMissingHostEntity) {
      return;
    }

    if (!queryVariables || !queryVariablesSignature) {
      return;
    }

    if (!force && queryVariablesSignature === lastLoadedVariablesSignatureRef.current) {
      return;
    }

    loadAndTrackSignature(queryVariables, queryVariablesSignature);
  }, [isMissingHostEntity, queryVariables, queryVariablesSignature, loadAndTrackSignature]);

  useEffect(() => {
    if (!isMissingHostEntity) {
      return;
    }
    lastLoadedVariablesSignatureRef.current = null;
    disposeQuery();
  }, [disposeQuery, isMissingHostEntity]);

  useEffect(() => {
    reloadData(false);
  }, [reloadData]);

  // Expose this widget's in-flight status so the dashboard can lock the manual
  // refresh button until every widget has finished refreshing.
  useEffect(() => {
    const queryId = queryIdRef.current;
    setQueryPending(queryId, isPending);
    return () => setQueryPending(queryId, false);
  }, [isPending, setQueryPending]);

  // Used by dashboard token refresh to rebuild variables from latest inputs
  // before forcing the load.
  const forceReloadWithFreshVariables = useCallback(() => {
    if (!buildQueryVariables || !config) {
      reloadData(true);
      return;
    }

    const refreshedVariables = buildQueryVariables(resolvedDataSelection, config, parameters);
    const refreshedSignature = JSON.stringify(refreshedVariables);
    loadAndTrackSignature(refreshedVariables, refreshedSignature);
  }, [buildQueryVariables, config, resolvedDataSelection, parameters, reloadData, loadAndTrackSignature]);

  // refreshToken is an integer provided via context by DashboardContent and incremented
  // by CustomDashboard on manual or auto refresh. When it changes, we force-reload
  // regardless of whether query variables changed, so fresh data is always fetched.
  // prevRefreshTokenRef guards against triggering on the initial mount.
  const refreshToken = useDashboardRefreshToken();
  const prevRefreshTokenRef = useRef(refreshToken);

  useEffect(() => {
    if (prevRefreshTokenRef.current === refreshToken) return;
    prevRefreshTokenRef.current = refreshToken;

    if (isMissingHostEntity) {
      return;
    }

    forceReloadWithFreshVariables();
  }, [refreshToken, isMissingHostEntity, forceReloadWithFreshVariables]);

  return {
    queryRef,
    isPreviewMode,
    resolvedDataSelection,
    isMissingHostEntity,
  };
};

export default useDashboardViz;
