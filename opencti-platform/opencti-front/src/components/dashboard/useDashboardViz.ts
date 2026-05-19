import type { WidgetHost, WidgetDataSelection, WidgetPerspective } from '../../utils/widget/widget';
import useAuth from '../../utils/hooks/useAuth';
import { resolveDataSelection } from './dashboard-viz-utils';
import { useCallback, useEffect, useMemo } from 'react';
import { DashboardConfig } from './dashboard-types';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { useQueryLoader } from 'react-relay';
import { OperationType } from 'relay-runtime';

const useWidgetAutoRefresh = (reloadData: () => void, refreshInterval?: number | null) => {
  useEffect(() => {
    const interval = refreshInterval !== null ? setInterval(() => {
      reloadData();
    }, refreshInterval) : null;
    reloadData();
    return () => {
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
  config,
}: {
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  host?: WidgetHost;
  refreshRate?: number | null;
  query?: GraphQLTaggedNode;
  config?: DashboardConfig;
  buildQueryVariables?: (resolvedDataSelection: WidgetDataSelection[], config: DashboardConfig) => TQuery['variables'];
}) => {
  const [queryRef, load] = useQueryLoader<TQuery>(query as GraphQLTaggedNode);
  const { filterKeysSchema } = useAuth().schema;
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode } = useMemo(() => resolveDataSelection({
    filterKeysSchema,
    dataSelection,
    perspective,
    host,
  }), [filterKeysSchema, dataSelection, perspective, host]);
  const reloadData = useCallback(() => {
    if (buildQueryVariables && config) {
      load(buildQueryVariables(resolvedDataSelection, config), {
        fetchPolicy: 'store-and-network',
      });
    }
  }, [load, buildQueryVariables, resolvedDataSelection, config]);
  useWidgetAutoRefresh(reloadData, refreshRate);
  return {
    queryRef,
    isPreviewMode,
    resolvedDataSelection,
    isMissingHostEntity,
  };
};

export default useDashboardViz;
