import React, { ReactNode, useState } from 'react';
import ApexCharts from 'apexcharts';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import useDistributionGraphData from '../../../../utils/hooks/useDistributionGraphData';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DraftsHorizontalBarsDistributionQuery } from './__generated__/DraftsHorizontalBarsDistributionQuery.graphql';

const draftsHorizontalBarsDistributionQuery = graphql`
  query DraftsHorizontalBarsDistributionQuery(
    $field: String!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $operation: StatsOperation!
    $limit: Int
    $order: String
    $filters: FilterGroup
    $search: String
  ) {
    draftWorkspacesDistribution(
      field: $field
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      operation: $operation
      limit: $limit
      order: $order
      filters: $filters
      search: $search
    ) {
      label
      value
      entity {
        ... on BasicObject {
          id
          entity_type
        }
        ... on StixObject {
          representative {
            main
          }
        }
        ... on Creator {
          id
          name
        }
        ... on Group {
          id
          name
        }
      }
    }
  }
`;

interface DraftsHorizontalBarsComponentProps {
  queryRef: PreloadedQuery<DraftsHorizontalBarsDistributionQuery>;
  dataSelection: Widget['dataSelection'];
  parameters: {
    distributed?: boolean | null;
  };
  setChart: (chart: ApexCharts) => void;
}

const DraftsHorizontalBarsComponent = ({
  queryRef,
  dataSelection,
  parameters,
  setChart,
}: DraftsHorizontalBarsComponentProps) => {
  const { t_i18n } = useFormatter();
  const { buildWidgetProps } = useDistributionGraphData();
  const data = usePreloadedQuery(
    draftsHorizontalBarsDistributionQuery,
    queryRef,
  );
  const selection = dataSelection[0];
  const distribution = data?.draftWorkspacesDistribution ?? [];

  if (distribution.length === 0) {
    return <WidgetNoData />;
  }
  const { series, redirectionUtils } = buildWidgetProps(
    distribution,
    selection,
    t_i18n('Number of draft workspaces'),
  );

  return (
    <WidgetHorizontalBars
      series={series}
      distributed={parameters.distributed ?? undefined}
      redirectionUtils={redirectionUtils}
      onMounted={setChart}
    />
  );
};

interface DraftsHorizontalBarsProps {
  dataSelection: Widget['dataSelection'];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  variant?: string;
  height?: number;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): DraftsHorizontalBarsDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const { dateAttribute, startDate, endDate, filters } = computeWidgetFiltersForSelection(selection, config);
  return {
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    startDate,
    endDate,
    dateAttribute,
    filters,
    limit: selection.number ?? 10,
  };
};

const DraftsHorizontalBars = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  config,
  refreshRate = null,
  host,
}: DraftsHorizontalBarsProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<DraftsHorizontalBarsDistributionQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: draftsHorizontalBarsDistributionQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Distribution of draft workspaces')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <DraftsHorizontalBarsComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          parameters={parameters}
          setChart={setChart}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default DraftsHorizontalBars;
