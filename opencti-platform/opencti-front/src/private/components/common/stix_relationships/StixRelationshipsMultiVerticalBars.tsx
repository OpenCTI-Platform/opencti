import React, { ReactNode, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { StixRelationshipsMultiVerticalBarsTimeSeriesQuery } from './__generated__/StixRelationshipsMultiVerticalBarsTimeSeriesQuery.graphql';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import ApexCharts from 'apexcharts';

const stixRelationshipsMultiVerticalBarsTimeSeriesQuery = graphql`
  query StixRelationshipsMultiVerticalBarsTimeSeriesQuery(
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $timeSeriesParameters: [StixRelationshipsTimeSeriesParameters]
  ) {
    stixRelationshipsMultiTimeSeries(
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      timeSeriesParameters: $timeSeriesParameters
    ) {
      data {
        date
        value
      }
    }
  }
`;

interface StixRelationshipsMultiVerticalBarsComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsMultiVerticalBarsTimeSeriesQuery>;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  onMounted: (chart: unknown) => void;
}

const StixRelationshipsMultiVerticalBarsComponent = ({
  queryRef,
  dataSelection,
  parameters,
  onMounted,
}: StixRelationshipsMultiVerticalBarsComponentProps) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(
    stixRelationshipsMultiVerticalBarsTimeSeriesQuery,
    queryRef,
  );

  if (!data?.stixRelationshipsMultiTimeSeries) {
    return <WidgetNoData />;
  }
  return (
    <WidgetVerticalBars
      series={dataSelection.map((selection, i) => {
        const serie = data.stixRelationshipsMultiTimeSeries?.[i];
        return {
          name: selection.label || t_i18n('Number of entities'),
          data: serie?.data?.flatMap((entry) => {
            if (!entry) {
              return [];
            }
            return [{
              x: new Date(entry.date),
              y: entry.value,
            }];
          }) ?? [],
        };
      })}
      interval={parameters?.interval}
      isStacked={parameters?.stacked ?? false}
      hasLegend={parameters?.legend ?? false}
      onMounted={onMounted}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsMultiVerticalBarsTimeSeriesQuery['variables'] => {
  const fallbackStart = monthsAgo(12);
  const fallbackEnd = now();
  const startDate = config.startDate ?? fallbackStart;
  const endDate = config.endDate ?? fallbackEnd;
  const timeSeriesParameters = resolvedDataSelection.map((selection) => {
    const dateAttribute
      = selection.date_attribute?.length ? selection.date_attribute : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(
      selection.filters,
      { startDate, endDate, isKnowledgeRelationshipWidget: true },
    );
    type TimeSeriesParam = NonNullable<NonNullable<StixRelationshipsMultiVerticalBarsTimeSeriesQuery['variables']['timeSeriesParameters']>[number]>;

    return {
      field: dateAttribute,
      filters: filters as unknown as TimeSeriesParam['filters'],
      dynamicFrom: selection.dynamicFrom as unknown as TimeSeriesParam['dynamicFrom'],
      dynamicTo: selection.dynamicTo as unknown as TimeSeriesParam['dynamicTo'],
    };
  });
  return {
    operation: 'count',
    startDate,
    endDate,
    interval: 'day',
    timeSeriesParameters,
  };
};

interface StixRelationshipsMultiVerticalBarsProps {
  variant?: string;
  height?: number;
  startDate?: string;
  endDate?: string;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsMultiVerticalBars = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsMultiVerticalBarsProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsMultiVerticalBarsTimeSeriesQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsMultiVerticalBarsTimeSeriesQuery,
    config,
    buildQueryVariables,
  });

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (!queryRef) {
      return <Loader variant={LoaderVariant.inElement} />;
    }

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixRelationshipsMultiVerticalBarsComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
          parameters={parameters}
          onMounted={(chart) => setChart(chart as ApexCharts)}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters?.title ?? t_i18n('Entities history')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsMultiVerticalBars;
