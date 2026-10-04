import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import useGraphMetricsPlatformView from './useGraphMetricsPlatformView';
import { buildGraphTopHubsChart, GRAPH_TOP_HUBS_DEFAULT, GRAPH_TOP_HUBS_MAX } from './graphAnalyticsUtils';
import type { GraphTopHubsWidgetQuery } from './__generated__/GraphTopHubsWidgetQuery.graphql';

const graphTopHubsWidgetQuery = graphql`
  query GraphTopHubsWidgetQuery($types: [String], $first: Int!, $filters: FilterGroup) {
    stixCoreObjects(types: $types, first: $first, orderBy: graph_degree, orderMode: desc, filters: $filters) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
          x_opencti_graph_metrics {
            degree
          }
        }
      }
    }
  }
`;

/** The most connected entities of the data selection, in the dashboard period. */
export const buildGraphTopHubsVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): GraphTopHubsWidgetQuery['variables'] => {
  const [selection] = resolvedDataSelection;
  const { filters } = computeWidgetFiltersForSelection(selection, config);
  return {
    types: ['Stix-Core-Object'],
    first: Math.min(GRAPH_TOP_HUBS_MAX, selection?.number || GRAPH_TOP_HUBS_DEFAULT),
    filters,
  };
};

interface GraphTopHubsComponentProps {
  queryRef: PreloadedQuery<GraphTopHubsWidgetQuery>;
  parameters: WidgetParameters;
}

const GraphTopHubsComponent = ({ queryRef, parameters }: GraphTopHubsComponentProps) => {
  const { t_i18n } = useFormatter();
  const { stixCoreObjects } = usePreloadedQuery(graphTopHubsWidgetQuery, queryRef);
  const { series, redirectionUtils } = buildGraphTopHubsChart((stixCoreObjects?.edges ?? []).map((edge) => edge.node), t_i18n('Graph degree'));
  if (redirectionUtils.length === 0) {
    return <WidgetNoData />;
  }
  return <WidgetHorizontalBars series={series} distributed={parameters.distributed ?? undefined} redirectionUtils={redirectionUtils} />;
};

interface GraphTopHubsWidgetProps {
  variant?: string;
  height?: number;
  dataSelection: Widget['dataSelection'];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const GraphTopHubsChart = ({ variant, height, dataSelection, parameters = {}, popover, host, refreshRate = null, config }: GraphTopHubsWidgetProps) => {
  const { t_i18n } = useFormatter();
  const { isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<GraphTopHubsWidgetQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: graphTopHubsWidgetQuery,
    config,
    buildQueryVariables: buildGraphTopHubsVariables,
  });
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Top hubs - by degree')}
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
        <GraphTopHubsComponent queryRef={queryRef!} parameters={parameters} />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

/**
 * Dashboard widget: the hubs of the data selection, ranked by graph degree. The stored degree counts every
 * relationship of the platform, so the ranking is reserved to users reading all relationships.
 */
const GraphTopHubsWidget = (props: GraphTopHubsWidgetProps) => {
  const { t_i18n } = useFormatter();
  const hasGraphMetricsPlatformView = useGraphMetricsPlatformView();
  if (hasGraphMetricsPlatformView) {
    return <GraphTopHubsChart {...props} />;
  }
  const { variant, height, parameters = {}, popover } = props;
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Top hubs - by degree')}
      variant={variant}
      action={popover}
    >
      <WidgetNoData message={t_i18n('This widget is ranked by graph metrics, which require access to every relationship of the platform.')} />
    </WidgetContainer>
  );
};

export default GraphTopHubsWidget;
