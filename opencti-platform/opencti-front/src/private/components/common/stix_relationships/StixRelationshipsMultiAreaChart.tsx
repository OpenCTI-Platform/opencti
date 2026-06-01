import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { ReactNode, Suspense, useState } from 'react';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { StixRelationshipsMultiAreaChartTimeSeriesQuery } from '@components/common/stix_relationships/__generated__/StixRelationshipsMultiAreaChartTimeSeriesQuery.graphql';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';

const stixRelationshipsMultiAreaChartTimeSeriesQuery = graphql`
  query StixRelationshipsMultiAreaChartTimeSeriesQuery(
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $relationship_type: [String!]
    $timeSeriesParameters: [StixRelationshipsTimeSeriesParameters]
  ) {
    stixRelationshipsMultiTimeSeries(
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      relationship_type: $relationship_type
      timeSeriesParameters: $timeSeriesParameters
    ) {
      data {
        date
        value
      }
    }
  }
`;

interface StixRelationshipsMultiAreaChartComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsMultiAreaChartTimeSeriesQuery>;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  onMounted: (chart: unknown) => void;
}

const StixRelationshipsMultiAreaChartComponent = ({
  queryRef,
  dataSelection,
  parameters,
  onMounted,
}: StixRelationshipsMultiAreaChartComponentProps) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(
    stixRelationshipsMultiAreaChartTimeSeriesQuery,
    queryRef,
  );
  console.log('parametre', parameters);
  if (!data?.stixRelationshipsMultiTimeSeries) {
    return <WidgetNoData />;
  }

  return (
    <WidgetMultiAreas
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
      isStacked={parameters?.stacked ?? false}
      hasLegend={parameters?.legend ?? false}
      onMounted={onMounted}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): StixRelationshipsMultiAreaChartTimeSeriesQuery['variables'] => {
  const fallbackStart = monthsAgo(12);
  const fallbackEnd = now();
  const startDate = config.startDate ?? fallbackStart;
  const endDate = config.endDate ?? fallbackEnd;
  type TimeSeriesParam = NonNullable<NonNullable<StixRelationshipsMultiAreaChartTimeSeriesQuery['variables']['timeSeriesParameters']>[number]>;

  const timeSeriesParameters = resolvedDataSelection.map((selection) => {
    const dateAttribute
      = selection.date_attribute?.length ? selection.date_attribute : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(
      selection.filters,
      { startDate, endDate, isKnowledgeRelationshipWidget: true },
    );

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
    interval: parameters?.interval ?? 'day',
    timeSeriesParameters,
  };
};

interface StixRelationshipsMultiAreaChartProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsMultiAreaChart = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsMultiAreaChartProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsMultiAreaChartTimeSeriesQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsMultiAreaChartTimeSeriesQuery,
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
          <StixRelationshipsMultiAreaChartComponent
            queryRef={queryRef}
            dataSelection={resolvedDataSelection}
            parameters={parameters}
            onMounted={(chart) => setChart(chart as ApexCharts)}
          />
        </Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default StixRelationshipsMultiAreaChart;
