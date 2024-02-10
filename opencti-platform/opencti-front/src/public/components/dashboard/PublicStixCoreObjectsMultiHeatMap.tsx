import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import { useFormatter } from '../../../components/i18n';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import { PublicStixCoreObjectsMultiHeatMapQuery } from './__generated__/PublicStixCoreObjectsMultiHeatMapQuery.graphql';
import WidgetMultiHeatMap from '../../../components/dashboard/WidgetMultiHeatMap';
import type { PublicManifestWidget } from './PublicManifest';
import { monthsAgo, now } from '../../../utils/Time';

const publicStixCoreObjectsMultiHeatMapQuery = graphql`
  query PublicStixCoreObjectsMultiHeatMapQuery(
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

interface PublicStixCoreObjectsMultiHeatMapComponentProps {
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixCoreObjectsMultiHeatMapQuery>
}

const PublicStixCoreObjectsMultiHeatMapComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixCoreObjectsMultiHeatMapComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixCoreObjectsMultiTimeSeries } = usePreloadedQuery(
    publicStixCoreObjectsMultiHeatMapQuery,
    queryRef,
  );

  if (publicStixCoreObjectsMultiTimeSeries) {
    const allValues = publicStixCoreObjectsMultiTimeSeries
      .map((serie) => (serie?.data ?? []).flatMap((o) => o?.value ?? []))
      .flat();
    const maxValue = Math.max(...allValues);
    const minValue = Math.min(...allValues);

    return (
      <WidgetMultiHeatMap
        data={publicStixCoreObjectsMultiTimeSeries.map((serie, i) => ({
          name: dataSelection[i].label ?? t_i18n('Number of entities'),
          data: (serie?.data ?? []).map((entry) => ({
            x: new Date(entry?.date),
            y: entry?.value,
          })),
        })).sort((a, b) => b.name.localeCompare(a.name))}
        minValue={minValue}
        maxValue={maxValue}
        isStacked={parameters.stacked}
        withExport={false}
        readonly={true}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsMultiHeatMap = ({
  uriKey,
  widget,
  startDate = monthsAgo(12),
  endDate = now(),
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsMultiHeatMapQuery>(
    publicStixCoreObjectsMultiHeatMapQuery,
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
          <PublicStixCoreObjectsMultiHeatMapComponent
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

export default PublicStixCoreObjectsMultiHeatMap;
