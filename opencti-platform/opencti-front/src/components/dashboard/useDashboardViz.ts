import type { WidgetHost, WidgetDataSelection, WidgetPerspective, WidgetParameters } from '../../utils/widget/widget';
import useAuth from '../../utils/hooks/useAuth';
import { resolveDataSelection } from './dashboard-viz-utils';
import { useCallback, useEffect, useMemo, useRef } from 'react';
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
    load(queryVariables, {
      fetchPolicy: 'store-and-network',
    });
  }, [load, queryVariables, queryVariablesSignature]);

  useEffect(() => {
    reloadData(false);
  }, [reloadData]);

  const forceReloadData = useCallback(() => {
    reloadData(true);
  }, [reloadData]);

  useWidgetAutoRefresh(forceReloadData, refreshRate);

  return {
    queryRef,
    isPreviewMode,
    resolvedDataSelection,
    isMissingHostEntity,
  };
};

export default useDashboardViz;
