import React, { useState, useMemo } from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const stixCoreObjectsMultiLineChartTimeSeriesQuery = graphql`
  query StixCoreObjectsMultiLineChartTimeSeriesQuery(
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

const StixCoreObjectsMultiLineChart = ({
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
        query={stixCoreObjectsMultiLineChartTimeSeriesQuery}
        variables={variables}
        render={({ props }) => {
          if (props && props.stixCoreObjectsMultiTimeSeries) {
            return (
              <WidgetMultiLines
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

export default StixCoreObjectsMultiLineChart;
