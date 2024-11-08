import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixCoreObjectsMultiAreaChartQuery } from './__generated__/PublicStixCoreObjectsMultiAreaChartQuery.graphql';
import { monthsAgo, now } from '../../../../utils/Time';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Widget } from '../../../../utils/widget/widget';

const publicStixCoreObjectsMultiAreaChartQuery = graphql`
  query PublicStixCoreObjectsMultiAreaChartQuery(
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

interface PublicStixCoreObjectsMultiAreaChartComponentProps {
  parameters: Widget['parameters']
  dataSelection: Widget['dataSelection']
  queryRef: PreloadedQuery<PublicStixCoreObjectsMultiAreaChartQuery>
}

const PublicStixCoreObjectsMultiAreaChartComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixCoreObjectsMultiAreaChartComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixCoreObjectsMultiTimeSeries } = usePreloadedQuery(
    publicStixCoreObjectsMultiAreaChartQuery,
    queryRef,
  );

  if (publicStixCoreObjectsMultiTimeSeries) {
    return (
      <WidgetMultiAreas
        series={publicStixCoreObjectsMultiTimeSeries.map((serie, i) => ({
          name: dataSelection[i].label ?? t_i18n('Number of entities'),
          data: (serie?.data ?? []).map((entry) => ({
            x: new Date(entry?.date),
            y: entry?.value,
          })),
        }))}
        interval={parameters?.interval}
        isStacked={!!parameters?.stacked}
        hasLegend={!!parameters?.legend}
        withExport={false}
        readonly={true}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsMultiAreaChart = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsMultiAreaChartQuery>(
    publicStixCoreObjectsMultiAreaChartQuery,
    {
      uriKey,
      widgetId: id,
      startDate: startDate ?? monthsAgo(12),
      endDate: endDate ?? now(),
    },
  );

  return (
    <WidgetContainer
      title={parameters?.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicStixCoreObjectsMultiAreaChartComponent
            queryRef={queryRef}
            parameters={parameters}
            dataSelection={dataSelection}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsMultiAreaChart;
