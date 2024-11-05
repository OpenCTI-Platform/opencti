import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import type { PublicManifestWidget } from '../PublicManifest';
import { useFormatter } from '../../../../components/i18n';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixRelationshipsMultiLineChartQuery } from './__generated__/PublicStixRelationshipsMultiLineChartQuery.graphql';
import { monthsAgo, now } from '../../../../utils/Time';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const publicStixRelationshipsMultiLineChartQuery = graphql`
  query PublicStixRelationshipsMultiLineChartQuery(
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

interface PublicStixRelationshipsMultiLineChartComponentProps {
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsMultiLineChartQuery>
}

const PublicStixRelationshipsMultiLineChartComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixRelationshipsMultiLineChartComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixRelationshipsMultiTimeSeries } = usePreloadedQuery(
    publicStixRelationshipsMultiLineChartQuery,
    queryRef,
  );

  if (publicStixRelationshipsMultiTimeSeries) {
    return (
      <WidgetMultiLines
        series={publicStixRelationshipsMultiTimeSeries.map((serie, i) => ({
          name: dataSelection[i].label || t_i18n('Number of entities'),
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

const PublicStixRelationshipsMultiLineChart = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsMultiLineChartQuery>(
    publicStixRelationshipsMultiLineChartQuery,
    {
      uriKey,
      widgetId: id,
      startDate: startDate ?? monthsAgo(12),
      endDate: endDate ?? now(),
    },
  );

  return (
    <WidgetContainer
      title={parameters.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicStixRelationshipsMultiLineChartComponent
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

export default PublicStixRelationshipsMultiLineChart;
