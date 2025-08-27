import React from 'react';
import { graphql } from 'react-relay';
import { PirRelationshipsMultiAreaChartTimeSeriesQuery$data } from '@components/pir/__generated__/PirRelationshipsMultiAreaChartTimeSeriesQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import { useFormatter } from '../../../components/i18n';
import { monthsAgo, now } from '../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import WidgetMultiAreas from '../../../components/dashboard/WidgetMultiAreas';
import Loader, { LoaderVariant } from '../../../components/Loader';
import type { WidgetDataSelection, WidgetParameters } from '../../../utils/widget/widget';

const pirRelationshipsMultiAreaChartTimeSeriesQuery = graphql`
  query PirRelationshipsMultiAreaChartTimeSeriesQuery(
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $relationship_type: [String!]
    $timeSeriesParameters: [StixRelationshipsTimeSeriesParameters]
  ) {
    pirRelationshipsMultiTimeSeries(
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

interface PirRelationshipsMultiAreaChartProps {
  dataSelection: WidgetDataSelection[],
  parameters: WidgetParameters,
  relationshipTypes: string[],
  variant?: string,
  title?: string,
  height?: number,
  startDate?: string | null,
  endDate?: string | null,
  withExportPopover?: boolean,
  isReadOnly?: boolean,
  withoutTitle?: boolean,
}

const PirRelationshipsMultiAreaChart = ({
  dataSelection,
  parameters,
  relationshipTypes,
  variant,
  title = undefined,
  height,
  startDate,
  endDate,
  withExportPopover = false,
  isReadOnly = false,
  withoutTitle = false,
}: PirRelationshipsMultiAreaChartProps) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    const timeSeriesParameters = dataSelection.map((selection) => {
      const dataSelectionDateAttribute = selection.date_attribute && selection.date_attribute.length > 0
        ? selection.date_attribute
        : 'created_at';
      const { filters } = buildFiltersAndOptionsForWidgets(selection.filters);
      return {
        field: dataSelectionDateAttribute,
        filters,
        dynamicFrom: selection.dynamicFrom,
        dynamicTo: selection.dynamicTo,
      };
    });

    return (
      <QueryRenderer
        query={pirRelationshipsMultiAreaChartTimeSeriesQuery}
        variables={{
          operation: 'count',
          startDate: startDate ?? monthsAgo(12),
          endDate: endDate ?? now(),
          interval: parameters.interval ?? 'day',
          relationship_type: relationshipTypes,
          timeSeriesParameters,
        }}
        render={({ props }: { props: PirRelationshipsMultiAreaChartTimeSeriesQuery$data }) => {
          if (props && props.pirRelationshipsMultiTimeSeries) {
            return (
              <WidgetMultiAreas
                series={dataSelection.map((selection, i) => ({
                  name: selection.label || t_i18n('Number of entities'),
                  data: props.pirRelationshipsMultiTimeSeries?.[i]?.data?.map(
                    (entry) => ({
                      x: new Date(entry?.date),
                      y: entry?.value,
                    }),
                  ),
                })) as ApexAxisChartSeries}
                interval={parameters.interval}
                isStacked={parameters.stacked ?? undefined}
                hasLegend={parameters.legend ?? undefined}
                withExport={withExportPopover}
                readonly={isReadOnly}
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
      height={height}
      title={parameters.title ?? title ?? t_i18n('Entities history')}
      variant={variant}
      withoutTitle={withoutTitle}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default PirRelationshipsMultiAreaChart;
