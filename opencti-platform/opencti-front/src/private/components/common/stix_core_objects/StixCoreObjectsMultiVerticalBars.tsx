import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets, sanitizeFilterGroupKeysForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { StixCoreObjectsMultiVerticalBarsTimeSeriesQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsMultiVerticalBarsTimeSeriesQuery.graphql';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';
import { monthsAgo, now } from '../../../../utils/Time';

const stixCoreObjectsMultiVerticalBarsTimeSeriesQuery = graphql`
  query StixCoreObjectsMultiVerticalBarsTimeSeriesQuery(
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $timeSeriesParameters: [StixCoreObjectsTimeSeriesParameters]
  ) {
    stixCoreObjectsMultiTimeSeries(
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

interface StixCoreObjectsMultiVerticalBarsComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsMultiVerticalBarsTimeSeriesQuery>;
  dataSelection: Widget['dataSelection'];
  parameters: {
    title?: string;
    interval?: string;
    stacked?: boolean;
    legend?: boolean;
  };
}

const StixCoreObjectsMultiVerticalBarsComponent = ({
  queryRef,
  dataSelection,
  parameters,
}: StixCoreObjectsMultiVerticalBarsComponentProps) => {
  const { t_i18n } = useFormatter();
  const { stixCoreObjectsMultiTimeSeries } = usePreloadedQuery(
    stixCoreObjectsMultiVerticalBarsTimeSeriesQuery,
    queryRef,
  );

  if (stixCoreObjectsMultiTimeSeries) {
    return (
      <WidgetVerticalBars
        series={stixCoreObjectsMultiTimeSeries.map((serie, i) => ({
          name: dataSelection[i]?.label ?? t_i18n('Number of entities'),
          data: (serie?.data ?? []).map((entry) => ({
            x: new Date(entry?.date),
            y: entry?.value,
          })),
        }))}
        interval={parameters.interval}
        isStacked={parameters.stacked}
        hasLegend={parameters.legend}
      />
    );
  }

  return <WidgetNoData />;
};

interface StixCoreObjectsMultiVerticalBarsProps {
  variant?: string;
  height?: number;
  dataSelection: Widget['dataSelection'];
  parameters?: {
    title?: string;
    interval?: string;
    stacked?: boolean;
    legend?: boolean;
  };
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixCoreObjectsMultiVerticalBarsTimeSeriesQuery['variables'] => {
  const computed = computeStartEndDates(config);
  const startDate = computed.startDate ?? monthsAgo(12);
  const endDate = computed.endDate ?? now();
  const timeSeriesParameters = resolvedDataSelection.map((selection) => {
    const dateAttribute
      = selection.date_attribute && selection.date_attribute.length > 0
        ? selection.date_attribute
        : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(
      selection.filters,
      { startDate, endDate, dateAttribute },
    );
    return {
      field: dateAttribute,
      types: DATA_SELECTION_TYPES,
      filters: filters ? sanitizeFilterGroupKeysForBackend(filters) : undefined,
    };
  });
  return {
    startDate,
    endDate,
    interval: 'day',
    timeSeriesParameters,
  };
};

const StixCoreObjectsMultiVerticalBars = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  config,
  refreshRate = null,
  host,
}: StixCoreObjectsMultiVerticalBarsProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsMultiVerticalBarsTimeSeriesQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsMultiVerticalBarsTimeSeriesQuery,
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
      title={parameters.title ?? t_i18n('Entities history')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixCoreObjectsMultiVerticalBarsComponent
            queryRef={queryRef}
            dataSelection={resolvedDataSelection}
            parameters={parameters}
          />
        </Suspense>
      )}
    </WidgetContainer>
  );
};

export default StixCoreObjectsMultiVerticalBars;
