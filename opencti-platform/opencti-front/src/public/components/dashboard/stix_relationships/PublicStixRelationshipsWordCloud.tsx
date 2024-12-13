import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetWordCloud from '../../../../components/dashboard/WidgetWordCloud';
import type { Widget } from '../../../../utils/widget/widget';
import { PublicStixRelationshipsWordCloudQuery } from './__generated__/PublicStixRelationshipsWordCloudQuery.graphql';

const publicStixRelationshipsWordCloudQuery = graphql`
  query PublicStixRelationshipsWordCloudQuery(
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

interface PublicStixRelationshipsWordCloudComponentProps {
  queryRef: PreloadedQuery<PublicStixRelationshipsWordCloudQuery>
  dataSelection: Widget['dataSelection']
}

const PublicStixCoreObjectsWordCloudComponent = ({
  queryRef,
  dataSelection,
}: PublicStixRelationshipsWordCloudComponentProps) => {
  const { publicStixRelationshipsDistribution } = usePreloadedQuery(
    publicStixRelationshipsWordCloudQuery,
    queryRef,
  );
  if (
    publicStixRelationshipsDistribution
    && publicStixRelationshipsDistribution.length > 0
  ) {
    return (
      <WidgetWordCloud
        data={[...publicStixRelationshipsDistribution]}
        groupBy={dataSelection[0].attribute ?? 'entity_type'}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsWordCloud = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsWordCloudQuery>(
    publicStixRelationshipsWordCloudQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters?.title ?? title ?? t_i18n('Relationships distribution')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicStixCoreObjectsWordCloudComponent
            queryRef={queryRef}
            dataSelection={dataSelection}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};
export default PublicStixRelationshipsWordCloud;
