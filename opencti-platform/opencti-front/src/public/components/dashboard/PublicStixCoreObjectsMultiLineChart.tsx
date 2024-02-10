import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import type { PublicManifestWidget } from './PublicManifest';
import { useFormatter } from '../../../components/i18n';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import WidgetMultiLines from '../../../components/dashboard/WidgetMultiLines';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import { PublicStixCoreObjectsMultiLineChartQuery } from './__generated__/PublicStixCoreObjectsMultiLineChartQuery.graphql';

const publicStixCoreObjectsMultiLineChartQuery = graphql`
  query PublicStixCoreObjectsMultiLineChartQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixCoreObjectsMultiTimeSeries(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      data {
        date
        value
      }
    }
  }
`;

interface PublicStixCoreObjectsMultiLineChartComponentProps {
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixCoreObjectsMultiLineChartQuery>
}

const PublicStixCoreObjectsMultiLineChartComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixCoreObjectsMultiLineChartComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixCoreObjectsMultiTimeSeries } = usePreloadedQuery(
    publicStixCoreObjectsMultiLineChartQuery,
    queryRef,
  );

  if (publicStixCoreObjectsMultiTimeSeries) {
    return (
      <WidgetMultiLines
        series={publicStixCoreObjectsMultiTimeSeries.map((serie, i) => ({
          name: dataSelection[i].label ?? t_i18n('Number of entities'),
          data: (serie?.data ?? []).map((entry) => ({
            x: new Date(entry?.date),
            y: entry?.value,
          })),
        }))}
        interval={parameters.interval}
        hasLegend={parameters.legend}
        withExport={false}
        readonly={true}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsMultiLineChart = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsMultiLineChartQuery>(
    publicStixCoreObjectsMultiLineChartQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <PublicStixCoreObjectsMultiLineChartComponent
            queryRef={queryRef}
            parameters={parameters}
            dataSelection={dataSelection}
          />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsMultiLineChart;
