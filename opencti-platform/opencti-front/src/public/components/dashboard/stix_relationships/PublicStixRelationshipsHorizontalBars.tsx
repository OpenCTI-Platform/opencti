import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixRelationshipsHorizontalBarsQuery } from './__generated__/PublicStixRelationshipsHorizontalBarsQuery.graphql';
import useDistributionGraphData from '../../../../utils/hooks/useDistributionGraphData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Widget } from '../../../../utils/widget/widget';

const publicStixRelationshipsHorizontalBarsQuery = graphql`
  query PublicStixRelationshipsHorizontalBarsQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixRelationshipsDistribution(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      label
      value
      entity {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
        }
        ... on StixObject {
          representative {
            main
          }
        }
        ... on StixRelationship {
          representative {
            main
          }
        }
        # internal objects
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
        # need colors when available
        ... on Label {
          color
        }
        ... on MarkingDefinition {
          x_opencti_color
        }
        ... on Status {
          template {
            name
            color
          }
        }
      }
    }
  }
`;

interface PublicStixRelationshipsHorizontalBarsComponentProps {
  parameters: Widget['parameters']
  dataSelection: Widget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsHorizontalBarsQuery>
}

const PublicStixRelationshipsHorizontalBarsComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixRelationshipsHorizontalBarsComponentProps) => {
  const { buildWidgetProps } = useDistributionGraphData();
  const { publicStixRelationshipsDistribution } = usePreloadedQuery(
    publicStixRelationshipsHorizontalBarsQuery,
    queryRef,
  );

  if (
    publicStixRelationshipsDistribution
    && publicStixRelationshipsDistribution.length > 0
  ) {
    const selection = dataSelection[0];
    const { series, redirectionUtils } = buildWidgetProps(publicStixRelationshipsDistribution, selection, 'Number of relationships');
    return (
      <WidgetHorizontalBars
        series={series}
        distributed={!!parameters?.distributed}
        withExport={false}
        readonly={true}
        redirectionUtils={redirectionUtils}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsHorizontalBars = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsHorizontalBarsQuery>(
    publicStixRelationshipsHorizontalBarsQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters?.title ?? title ?? t_i18n('Distribution of entities')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicStixRelationshipsHorizontalBarsComponent
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

export default PublicStixRelationshipsHorizontalBars;
