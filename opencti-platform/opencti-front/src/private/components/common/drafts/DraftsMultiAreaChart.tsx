import React, { ReactNode, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import { monthsAgo, now } from '../../../../utils/Time';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DraftsMultiAreaChartTimeSeriesQuery } from './__generated__/DraftsMultiAreaChartTimeSeriesQuery.graphql';
import { getWidgetInterval } from '../../../../utils/widget/widgetUtils';

const draftsMultiAreaChartTimeSeriesQuery = graphql`
  query DraftsMultiAreaChartTimeSeriesQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $filters: FilterGroup
    $search: String
  ) {
    draftWorkspacesTimeSeries(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      filters: $filters
      search: $search
    ) {
      date
      value
    }
  }
`;

interface DraftsMultiAreaChartComponentProps {
  queryRef: PreloadedQuery<DraftsMultiAreaChartTimeSeriesQuery>;
  dataSelection: Widget['dataSelection'];
  parameters: WidgetParameters;
  setChart: (chart: ApexCharts) => void;
}

const DraftsMultiAreaChartComponent = ({
  queryRef,
  dataSelection,
  parameters,
  setChart,
}: DraftsMultiAreaChartComponentProps) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(draftsMultiAreaChartTimeSeriesQuery, queryRef);
  const selection = dataSelection[0];

  if (!data.draftWorkspacesTimeSeries) {
    return <WidgetNoData />;
  }

  return (
    <WidgetMultiAreas
      series={[{
        name: selection?.label || t_i18n('Number of draft workspaces'),
        data: data.draftWorkspacesTimeSeries.map((entry) => ({
          x: new Date(entry?.date),
          y: entry?.value,
        })),
      }]}
      interval={parameters.interval}
      isStacked={parameters.stacked ?? undefined}
      hasLegend={parameters.legend ?? undefined}
      onMounted={setChart}
    />
  );
};

interface DraftsMultiAreaChartProps {
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
  parameters?: WidgetParameters,
): DraftsMultiAreaChartTimeSeriesQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'created_at';
  const { startDate: rawStartDate, endDate: rawEndDate } = computeStartEndDates(config);
  const startDate = rawStartDate ?? monthsAgo(12);
  const endDate = rawEndDate ?? now();
  const { filters } = buildFiltersAndOptionsForWidgets(selection.filters);
  return {
    field: dateAttribute,
    operation: 'count',
    startDate,
    endDate,
    interval: getWidgetInterval(parameters),
    filters: normalizeFilterGroupForBackend(filters),
  };
};

const DraftsMultiAreaChart = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  config,
  refreshRate = null,
  host,
}: DraftsMultiAreaChartProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<DraftsMultiAreaChartTimeSeriesQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: draftsMultiAreaChartTimeSeriesQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Draft workspaces history')}
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
        <DraftsMultiAreaChartComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          parameters={parameters}
          setChart={setChart}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default DraftsMultiAreaChart;
