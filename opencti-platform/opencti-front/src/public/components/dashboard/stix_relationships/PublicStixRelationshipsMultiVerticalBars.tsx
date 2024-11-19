import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixRelationshipsMultiVerticalBarsQuery } from './__generated__/PublicStixRelationshipsMultiVerticalBarsQuery.graphql';
import { monthsAgo, now } from '../../../../utils/Time';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Widget } from '../../../../utils/widget/widget';

const publicStixRelationshipsMultiVerticalBarsQuery = graphql`
  query PublicStixRelationshipsMultiVerticalBarsQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixRelationshipsMultiTimeSeries(
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

interface PublicStixRelationshipsMultiVerticalBarsComponentProps {
  parameters: Widget['parameters']
  dataSelection: Widget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsMultiVerticalBarsQuery>
}

const PublicStixRelationshipsMultiVerticalBarsComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixRelationshipsMultiVerticalBarsComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixRelationshipsMultiTimeSeries } = usePreloadedQuery(
    publicStixRelationshipsMultiVerticalBarsQuery,
    queryRef,
  );

  if (publicStixRelationshipsMultiTimeSeries) {
    return (
      <WidgetVerticalBars
        series={publicStixRelationshipsMultiTimeSeries.map((serie, i) => ({
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

const PublicStixRelationshipsMultiVerticalBars = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsMultiVerticalBarsQuery>(
    publicStixRelationshipsMultiVerticalBarsQuery,
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
          <PublicStixRelationshipsMultiVerticalBarsComponent
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

export default PublicStixRelationshipsMultiVerticalBars;
