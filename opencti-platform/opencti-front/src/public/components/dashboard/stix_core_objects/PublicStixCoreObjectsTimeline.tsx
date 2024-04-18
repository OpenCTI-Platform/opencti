import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import { PublicStixCoreObjectsTimelineQuery } from './__generated__/PublicStixCoreObjectsTimelineQuery.graphql';
import WidgetTimeline from '../../../../components/dashboard/WidgetTimeline';

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
}

const PublicStixCoreObjectsTimelineComponent = ({
  queryRef,
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
    return <WidgetTimeline data={data} />;
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
  const { id, parameters } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsTimelineQuery>(
    publicStixCoreObjectsTimelineQuery,
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
          <PublicStixCoreObjectsTimelineComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsTimeline;
