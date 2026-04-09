import React, { useState, useMemo } from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const stixCoreObjectsMultiAreaChartTimeSeriesQuery = graphql`
  query StixCoreObjectsMultiAreaChartTimeSeriesQuery(
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

const StixCoreObjectsMultiAreaChart = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  popover,
}) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState();

  const timeSeriesParameters = useMemo(() => {
    return dataSelection.map((selection) => {
      const dataSelectionTypes = ['Stix-Core-Object'];
      const { filters } = buildFiltersAndOptionsForWidgets(selection.filters);
      return {
        field:
          selection.date_attribute && selection.date_attribute.length > 0
            ? selection.date_attribute
            : 'created_at',
        types: dataSelectionTypes,
        filters,
      };
    });
  }, [dataSelection]);

  // Compute fallback dates once per component mount to prevent now() recalculations
  // from busting the variables memoization on every render.
  const fallbackDates = useMemo(() => ({
    start: monthsAgo(12),
    end: now(),
  }), []);

  const variables = useMemo(() => ({
    startDate: startDate ?? fallbackDates.start,
    endDate: endDate ?? fallbackDates.end,
    interval: parameters.interval ?? 'day',
    timeSeriesParameters,
  }), [startDate, endDate, fallbackDates, parameters.interval, timeSeriesParameters]);

  const renderContent = () => {
    return (
      <QueryRenderer
        query={stixCoreObjectsMultiAreaChartTimeSeriesQuery}
        variables={variables}
        render={({ props }) => {
          if (props && props.stixCoreObjectsMultiTimeSeries) {
            return (
              <WidgetMultiAreas
                series={dataSelection.map((selection, i) => ({
                  name: selection.label || t_i18n('Number of entities'),
                  data: props.stixCoreObjectsMultiTimeSeries[i].data.map(
                    (entry) => ({
                      x: new Date(entry.date),
                      y: entry.value,
                    }),
                  ),
                }))}
                interval={parameters.interval}
                isStacked={parameters.stacked}
                hasLegend={parameters.legend}
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
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsMultiAreaChart;
