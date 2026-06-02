import type { WidgetHost, WidgetDataSelection, WidgetPerspective, WidgetParameters } from '../../utils/widget/widget';
import useAuth from '../../utils/hooks/useAuth';
import { resolveDataSelection } from './dashboard-viz-utils';
import { useCallback, useEffect, useMemo, useRef, useTransition } from 'react';
import { useDashboardRefreshToken } from './DashboardRefreshContext';
import { DashboardConfig } from './dashboard-types';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { useQueryLoader } from 'react-relay';
import { OperationType } from 'relay-runtime';

const useWidgetAutoRefresh = (reloadData: () => void, refreshInterval?: number | null) => {
  useEffect(() => {
    if (typeof refreshInterval !== 'number' || refreshInterval <= 0) {
      return () => {};
    }

    let interval: ReturnType<typeof setInterval> | null = null;
    const msUntilNextTick = refreshInterval - (Date.now() % refreshInterval);
    const timeout = setTimeout(() => {
      reloadData();
      interval = setInterval(() => {
        reloadData();
      }, refreshInterval);
    }, msUntilNextTick);

    return () => {
      clearTimeout(timeout);
      if (interval !== null) {
        clearInterval(interval);
      }
    };
  }, [reloadData, refreshInterval]);
};

const useDashboardViz = <TQuery extends OperationType>({
  dataSelection,
  perspective,
  host,
  refreshRate,
  query,
  buildQueryVariables,
  parameters,
  config,
}: {
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  host?: WidgetHost;
  refreshRate?: number | null;
  query?: GraphQLTaggedNode;
  config?: DashboardConfig;
  parameters?: WidgetParameters;
  buildQueryVariables?: (resolvedDataSelection: WidgetDataSelection[], config: DashboardConfig, parameters?: WidgetParameters) => TQuery['variables'];
}) => {
  const [queryRef, load] = useQueryLoader<TQuery>(query as GraphQLTaggedNode);
  const [, startTransition] = useTransition();
  const lastLoadedVariablesSignatureRef = useRef<string | null>(null);
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

  const reloadData = useCallback((force = false) => {
    if (!queryVariables || !queryVariablesSignature) {
      return;
    }

    if (!force && queryVariablesSignature === lastLoadedVariablesSignatureRef.current) {
      return;
    }

    lastLoadedVariablesSignatureRef.current = queryVariablesSignature;
    startTransition(() => {
      load(queryVariables, {
        fetchPolicy: 'store-and-network',
      });
    });
  }, [load, startTransition, queryVariables, queryVariablesSignature]);

  useEffect(() => {
    reloadData(false);
  }, [reloadData]);

  // Wraps reloadData(true) for use in auto-refresh interval, always bypasses signature cache.
  const forceReloadData = useCallback(() => {
    reloadData(true);
  }, [reloadData]);

  // Keeps a stable ref to the latest reloadData so the token effect below can call it
  // without adding reloadData as a dependency (which would re-run the effect on every
  // variable change and cause unwanted refetches).
  const reloadDataRef = useRef(reloadData);
  useEffect(() => {
    reloadDataRef.current = reloadData;
  }, [reloadData]);

  // refreshToken is an integer provided via context by DashboardContent and incremented
  // by CustomDashboard on manual or auto refresh. When it changes, we force-reload
  // regardless of whether query variables changed, so fresh data is always fetched.
  // prevRefreshTokenRef guards against triggering on the initial mount (token === 0).
  const refreshToken = useDashboardRefreshToken();
  const prevRefreshTokenRef = useRef(refreshToken);
  useEffect(() => {
    if (prevRefreshTokenRef.current === refreshToken) return;
    prevRefreshTokenRef.current = refreshToken;
    reloadDataRef.current(true);
  }, [refreshToken]);

  useWidgetAutoRefresh(forceReloadData, refreshRate);

  return {
    queryRef,
    isPreviewMode,
    resolvedDataSelection,
    isMissingHostEntity,
  };
};

export default useDashboardViz;
