import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixCoreObjectsTimelineQuery } from './__generated__/PublicStixCoreObjectsTimelineQuery.graphql';
import WidgetTimeline from '../../../../components/dashboard/WidgetTimeline';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const publicStixCoreObjectsTimelineQuery = graphql`
  query PublicStixCoreObjectsTimelineQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixCoreObjects(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      edges {
        node {
          id
          entity_type
          created_at
          updated_at
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ... on BasicObject {
            id
            entity_type
          }
          ... on StixObject {
            representative {
              main
              secondary
            }
          }
          ... on StixDomainObject {
            created
            modified
          }
          ... on Event {
            start_time
            stop_time
          }
          ... on StixCyberObservable {
            observable_value
          }
        }
      }
    }
  }
`;

interface PublicStixCoreObjectsTimelineComponentProps {
  queryRef: PreloadedQuery<PublicStixCoreObjectsTimelineQuery>
  dateAttribute?: string
}

const PublicStixCoreObjectsTimelineComponent = ({
  queryRef,
  dateAttribute,
}: PublicStixCoreObjectsTimelineComponentProps) => {
  const { publicStixCoreObjects } = usePreloadedQuery(
    publicStixCoreObjectsTimelineQuery,
    queryRef,
  );

  if (
    publicStixCoreObjects
    && publicStixCoreObjects?.edges
    && publicStixCoreObjects.edges.length > 0
  ) {
    const stixCoreObjectsEdges = publicStixCoreObjects.edges;
    const data = stixCoreObjectsEdges.flatMap((stixCoreObjectEdge) => {
      const stixCoreObject = stixCoreObjectEdge?.node;
      if (!stixCoreObject) return [];
      return {
        value: stixCoreObject,
      };
    });
    return <WidgetTimeline data={data} dateAttribute={dateAttribute} />;
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsTimeline = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsTimelineQuery>(
    publicStixCoreObjectsTimelineQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );
  const selection = dataSelection[0];
  const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'created_at';

  return (
    <WidgetContainer
      title={parameters?.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicStixCoreObjectsTimelineComponent queryRef={queryRef} dateAttribute={dateAttribute} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsTimeline;
