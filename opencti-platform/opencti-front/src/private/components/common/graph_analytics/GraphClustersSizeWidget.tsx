import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { getWidgetInterval } from '../../../../utils/widget/widgetUtils';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import type { GraphClustersSizeWidgetQuery } from './__generated__/GraphClustersSizeWidgetQuery.graphql';

const graphClustersSizeWidgetQuery = graphql`
  query GraphClustersSizeWidgetQuery($startDate: DateTime, $endDate: DateTime, $interval: String!, $limit: Int, $filters: FilterGroup) {
    graphClustersSizeTimeSeries(startDate: $startDate, endDate: $endDate, interval: $interval, limit: $limit, filters: $filters) {
      cluster {
        id
        name
        members_count
      }
      data {
        date
        value
      }
    }
  }
`;

const DEFAULT_CLUSTERS = 5;
const MAX_CLUSTERS = 20;

/** Size over time of the largest clusters, members filtered by the data selection; the member filters scope each series. */
export const buildGraphClustersSizeVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): GraphClustersSizeWidgetQuery['variables'] => {
  const [selection] = resolvedDataSelection;
  const { startDate, endDate } = computeStartEndDates(config, true);
  // Member creation dates draw the curve, so the dashboard period must not filter members out of the baseline
  const { filters } = buildFiltersAndOptionsForWidgets(selection?.filters);
  return {
    startDate,
    endDate,
    interval: getWidgetInterval(parameters),
    limit: Math.min(MAX_CLUSTERS, Math.max(1, selection?.number ?? DEFAULT_CLUSTERS)),
    filters: normalizeFilterGroupForBackend(filters),
  };
};

interface GraphClustersSizeComponentProps {
  queryRef: PreloadedQuery<GraphClustersSizeWidgetQuery>;
  parameters: WidgetParameters;
}

const GraphClustersSizeComponent = ({ queryRef, parameters }: GraphClustersSizeComponentProps) => {
  const { graphClustersSizeTimeSeries } = usePreloadedQuery(graphClustersSizeWidgetQuery, queryRef);
  if (graphClustersSizeTimeSeries.length === 0) {
    return <WidgetNoData />;
  }
  return (
    <WidgetMultiAreas
      series={graphClustersSizeTimeSeries.map((serie) => ({
        name: serie.cluster.name,
        data: serie.data.map((entry) => ({ x: new Date(entry.date), y: entry.value })),
      }))}
      interval={getWidgetInterval(parameters)}
      hasLegend={parameters.legend ?? true}
    />
  );
};

interface GraphClustersSizeWidgetProps {
  variant?: string;
  height?: number;
  dataSelection: Widget['dataSelection'];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

/** Dashboard widget: growth of the largest graph clusters (cumulative number of members). */
const GraphClustersSizeWidget = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  config,
  refreshRate = null,
  host,
}: GraphClustersSizeWidgetProps) => {
  const { t_i18n } = useFormatter();
  const { isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<GraphClustersSizeWidgetQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: graphClustersSizeWidgetQuery,
    config,
    parameters,
    buildQueryVariables: buildGraphClustersSizeVariables,
  });
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Cluster size over time')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <GraphClustersSizeComponent queryRef={queryRef!} parameters={parameters} />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default GraphClustersSizeWidget;
