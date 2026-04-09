import React, { useState, useMemo } from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { removeEntityTypeAllFromFilterGroup } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetMultiHeatMap from '../../../../components/dashboard/WidgetMultiHeatMap';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const stixCoreObjectsMultiHeatMapTimeSeriesQuery = graphql`
  query StixCoreObjectsMultiHeatMapTimeSeriesQuery(
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

const StixCoreObjectsMultiHeatMap = ({
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
      return {
        field:
          selection.date_attribute && selection.date_attribute.length > 0
            ? selection.date_attribute
            : 'created_at',
        types: ['Stix-Core-Object'],
        filters: removeEntityTypeAllFromFilterGroup(selection.filters),
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
        query={stixCoreObjectsMultiHeatMapTimeSeriesQuery}
        variables={variables}
        render={({ props }) => {
          if (props && props.stixCoreObjectsMultiTimeSeries) {
            const chartData = dataSelection
              .map((selection, i) => ({
                name: selection.label || t_i18n('Number of entities'),
                data: props.stixCoreObjectsMultiTimeSeries[i].data.map(
                  (entry) => ({
                    x: new Date(entry.date),
                    y: entry.value,
                  }),
                ),
              }))
              .sort((a, b) => b.name.localeCompare(a.name));
            const allValues = props.stixCoreObjectsMultiTimeSeries
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
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsMultiHeatMap;
