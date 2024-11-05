import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import type { PublicManifestWidget } from '../PublicManifest';
import { useFormatter } from '../../../../components/i18n';
import WidgetMultiHeatMap from '../../../../components/dashboard/WidgetMultiHeatMap';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixRelationshipsMultiHeatMapQuery } from './__generated__/PublicStixRelationshipsMultiHeatMapQuery.graphql';
import { monthsAgo, now } from '../../../../utils/Time';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const publicStixRelationshipsMultiHeatMapQuery = graphql`
  query PublicStixRelationshipsMultiHeatMapQuery(
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

interface PublicStixRelationshipsMultiHeatMapComponentProps {
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsMultiHeatMapQuery>
}

const PublicStixRelationshipsMultiHeatMapComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixRelationshipsMultiHeatMapComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixRelationshipsMultiTimeSeries } = usePreloadedQuery(
    publicStixRelationshipsMultiHeatMapQuery,
    queryRef,
  );

  if (publicStixRelationshipsMultiTimeSeries) {
    const allValues = publicStixRelationshipsMultiTimeSeries
      .map((serie) => (serie?.data ?? []).flatMap((o) => o?.value ?? []))
      .flat();
    const maxValue = Math.max(...allValues);
    const minValue = Math.min(...allValues);

    return (
      <WidgetMultiHeatMap
        data={publicStixRelationshipsMultiTimeSeries.map((serie, i) => ({
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

const PublicStixRelationshipsMultiHeatMap = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsMultiHeatMapQuery>(
    publicStixRelationshipsMultiHeatMapQuery,
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
          <PublicStixRelationshipsMultiHeatMapComponent
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

export default PublicStixRelationshipsMultiHeatMap;
