import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import { useFormatter } from '../../../components/i18n';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../components/dashboard/WidgetVerticalBars';
import { PublicStixCoreObjectsMultiVerticalBarsQuery } from './__generated__/PublicStixCoreObjectsMultiVerticalBarsQuery.graphql';
import type { PublicManifestWidget } from './PublicManifest';

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
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixCoreObjectsMultiVerticalBarsQuery>
}

const PublicStixCoreObjectsMultiVerticalBarsComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixCoreObjectsMultiVerticalBarsComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixCoreObjectsMultiTimeSeries } = usePreloadedQuery(
    publicStixCoreObjectsMultiVerticalBarsQuery,
    queryRef,
  );

  if (publicStixCoreObjectsMultiTimeSeries) {
    return (
      <WidgetVerticalBars
        series={publicStixCoreObjectsMultiTimeSeries.map((serie, i) => ({
          name: dataSelection[i].label ?? t_i18n('Number of entities'),
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
          <PublicStixCoreObjectsMultiVerticalBarsComponent
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

export default PublicStixCoreObjectsMultiVerticalBars;
