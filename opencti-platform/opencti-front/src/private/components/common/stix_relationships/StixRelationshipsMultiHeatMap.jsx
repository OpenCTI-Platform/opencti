import React, { useState, useMemo } from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiHeatMap from '../../../../components/dashboard/WidgetMultiHeatMap';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';

const stixRelationshipsMultiHeatMapTimeSeriesQuery = graphql`
  query StixRelationshipsMultiHeatMapTimeSeriesQuery(
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

const StixRelationshipsMultiHeatMap = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  popover,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode } = useDashboardViz({
    perspective: 'relationships',
    dataSelection,
    host,
  });

  const timeSeriesParameters = useMemo(() => {
    return resolvedDataSelection.map((selection) => {
      const dataSelectionDateAttribute = selection.date_attribute && selection.date_attribute.length > 0
        ? selection.date_attribute
        : 'created_at';
      const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, { isKnowledgeRelationshipWidget: true });
      return {
        field: dataSelectionDateAttribute,
        filters,
        dynamicFrom: selection.dynamicFrom,
        dynamicTo: selection.dynamicTo,
      };
    });
  }, [resolvedDataSelection]);

  const fallbackDates = useMemo(() => ({
    start: monthsAgo(12),
    end: now(),
  }), []);

  const variables = useMemo(() => ({
    operation: 'count',
    startDate: startDate ?? fallbackDates.start,
    endDate: endDate ?? fallbackDates.end,
    interval: parameters.interval ?? 'day',
    timeSeriesParameters,
  }), [startDate, endDate, fallbackDates, parameters.interval, timeSeriesParameters]);

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }
    return (
      <QueryRenderer
        query={stixRelationshipsMultiHeatMapTimeSeriesQuery}
        variables={variables}
        render={({ props }) => {
          if (props && props.stixRelationshipsMultiTimeSeries) {
            const chartData = resolvedDataSelection
              .map((selection, i) => ({
                name: selection.label || t_i18n('Number of relationships'),
                data: props.stixRelationshipsMultiTimeSeries[i].data.map(
                  (entry) => ({
                    x: new Date(entry.date),
                    y: entry.value,
                  }),
                ),
              }))
              .sort((a, b) => b.name.localeCompare(a.name));
            const allValues = props.stixRelationshipsMultiTimeSeries
              .map((n) => n.data.map((o) => o.value))
              .flat();
            const maxValue = Math.max(...allValues);
            const minValue = Math.min(...allValues);

            return (
              <WidgetMultiHeatMap
                data={chartData}
                minValue={minValue}
                maxValue={maxValue}
                isStacked={parameters.stacked}
                onMounted={setChart}
              />
            );
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    );
  };
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Entities history')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsMultiHeatMap;
