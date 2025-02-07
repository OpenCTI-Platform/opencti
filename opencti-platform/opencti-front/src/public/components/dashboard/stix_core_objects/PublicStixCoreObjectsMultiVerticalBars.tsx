import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import { PublicStixCoreObjectsMultiVerticalBarsQuery } from './__generated__/PublicStixCoreObjectsMultiVerticalBarsQuery.graphql';
import { monthsAgo, now } from '../../../../utils/Time';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Widget } from '../../../../utils/widget/widget';

const publicStixCoreObjectsMultiVerticalBarsQuery = graphql`
  query PublicStixCoreObjectsMultiVerticalBarsQuery(
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

interface PublicStixCoreObjectsMultiVerticalBarsComponentProps {
  _parameters: Widget['parameters']
  _dataSelection: Widget['dataSelection']
  queryRef: PreloadedQuery<PublicStixCoreObjectsMultiVerticalBarsQuery>
}

const PublicStixCoreObjectsMultiVerticalBarsComponent = ({
  _parameters,
  _dataSelection,
  queryRef,
}: PublicStixCoreObjectsMultiVerticalBarsComponentProps) => {
  const { publicStixCoreObjectsMultiTimeSeries } = usePreloadedQuery(
    publicStixCoreObjectsMultiVerticalBarsQuery,
    queryRef,
  );
  if (publicStixCoreObjectsMultiTimeSeries) {
    return <div style={{ width: '100%', height: '100%' }}>
      <img src='http://localhost:4000/chart?uriKey=test&widgetId=df1c2c4a-d68b-47c9-ba27-2709095e745c&startDate=2024-02-06T00:00:00&endDate=2025-02-06T21:31:47' />
    </div>;
    // return (
    //   <WidgetVerticalBars
    //     series={publicStixCoreObjectsMultiTimeSeries.map((serie, i) => ({
    //       name: dataSelection[i].label ?? t_i18n('Number of entities'),
    //       data: (serie?.data ?? []).map((entry) => ({
    //         x: new Date(entry?.date),
    //         y: entry?.value,
    //       })),
    //     }))}
    //     interval={parameters?.interval}
    //     isStacked={!!parameters?.stacked}
    //     hasLegend={!!parameters?.legend}
    //     withExport={false}
    //     readonly={true}
    //   />
    // );
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsMultiVerticalBars = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsMultiVerticalBarsQuery>(
    publicStixCoreObjectsMultiVerticalBarsQuery,
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
          <PublicStixCoreObjectsMultiVerticalBarsComponent
            queryRef={queryRef}
            _parameters={parameters}
            _dataSelection={dataSelection}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsMultiVerticalBars;
