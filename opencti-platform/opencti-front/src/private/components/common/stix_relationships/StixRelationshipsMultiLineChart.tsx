import React, { ReactNode, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { StixRelationshipsMultiLineChartTimeSeriesQuery } from '@components/common/stix_relationships/__generated__/StixRelationshipsMultiLineChartTimeSeriesQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import ApexCharts from 'apexcharts';

const stixRelationshipsMultiLineChartTimeSeriesQuery = graphql`
  query StixRelationshipsMultiLineChartTimeSeriesQuery(
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

interface StixRelationshipsMultiLineChartComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsMultiLineChartTimeSeriesQuery>;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  onMounted: (chart: unknown) => void;
}

const StixRelationshipsMultiLineChartComponent = ({
  queryRef,
  dataSelection,
  parameters,
  onMounted,
}: StixRelationshipsMultiLineChartComponentProps) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(
    stixRelationshipsMultiLineChartTimeSeriesQuery,
    queryRef,
  );

  if (!data?.stixRelationshipsMultiTimeSeries) {
    return <WidgetNoData />;
  }
  return (
    <WidgetMultiLines
      series={dataSelection.map((selection, i) => {
        const serie = data.stixRelationshipsMultiTimeSeries?.[i];

        return {
          name: selection.label || t_i18n('Number of entities'),
          data:
            serie?.data?.flatMap((entry) => {
              if (!entry) return [];
              return [
                {
                  x: new Date(entry.date),
                  y: entry.value,
                },
              ];
            }) ?? [],
        };
      })}
      interval={parameters?.interval}
      hasLegend={parameters?.legend ?? false}
      onMounted={onMounted}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsMultiLineChartTimeSeriesQuery['variables'] => {
  const fallbackStart = monthsAgo(12);
  const fallbackEnd = now();
  const startDate = config.startDate ?? fallbackStart;
  const endDate = config.endDate ?? fallbackEnd;
  const timeSeriesParameters = resolvedDataSelection.map((selection) => {
    const dateAttribute
      = selection.date_attribute?.length ? selection.date_attribute : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, {
      startDate,
      endDate,
      isKnowledgeRelationshipWidget: true,
    });
    type TimeSeriesParam
      = NonNullable<
        NonNullable<
          StixRelationshipsMultiLineChartTimeSeriesQuery['variables']['timeSeriesParameters']
        >[number]
      >;

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

interface StixRelationshipsMultiLineChartProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsMultiLineChart = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsMultiLineChartProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsMultiLineChartTimeSeriesQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsMultiLineChartTimeSeriesQuery,
    config,
    buildQueryVariables,
  });

  if (isMissingHostEntity) {
    return <WidgetNoHostEntity host={host} />;
  }

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
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixRelationshipsMultiLineChartComponent
            queryRef={queryRef}
            dataSelection={resolvedDataSelection}
            parameters={parameters}
            onMounted={(c) => setChart(c as ApexCharts)}
          />
        </Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default StixRelationshipsMultiLineChart;
