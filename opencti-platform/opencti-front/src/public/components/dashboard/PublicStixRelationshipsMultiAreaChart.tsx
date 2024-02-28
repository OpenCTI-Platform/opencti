import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import type { PublicManifestWidget } from './PublicManifest';
import { useFormatter } from '../../../components/i18n';
import WidgetMultiAreas from '../../../components/dashboard/WidgetMultiAreas';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import { PublicStixRelationshipsMultiAreaChartQuery } from './__generated__/PublicStixRelationshipsMultiAreaChartQuery.graphql';
import { monthsAgo, now } from '../../../utils/Time';

const publicStixRelationshipsMultiAreaChartQuery = graphql`
  query PublicStixRelationshipsMultiAreaChartQuery(
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

interface PublicStixRelationshipsMultiAreaChartComponentProps {
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsMultiAreaChartQuery>
}

const PublicStixRelationshipsMultiAreaChartComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixRelationshipsMultiAreaChartComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixRelationshipsMultiTimeSeries } = usePreloadedQuery(
    publicStixRelationshipsMultiAreaChartQuery,
    queryRef,
  );

  if (publicStixRelationshipsMultiTimeSeries) {
    return (
      <WidgetMultiAreas
        series={publicStixRelationshipsMultiTimeSeries.map((serie, i) => ({
          name: dataSelection[i].label || t_i18n('Number of entities'),
          data: (serie?.data ?? []).map((entry) => ({
            x: new Date(entry?.date),
            y: entry?.value,
          })),
        }))}
        interval={parameters.interval}
        isStacked={parameters.stacked}
        hasLegend={parameters.legend}
        withExport={false}
        readonly={true}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsMultiAreaChart = ({
  uriKey,
  widget,
  startDate = monthsAgo(12),
  endDate = now(),
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsMultiAreaChartQuery>(
    publicStixRelationshipsMultiAreaChartQuery,
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
          <PublicStixRelationshipsMultiAreaChartComponent
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

export default PublicStixRelationshipsMultiAreaChart;
