import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { AuditsListContentQuery } from '@components/common/audits/__generated__/AuditsListContentQuery.graphql';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetListAudits from '../../../../components/dashboard/WidgetListAudits';

export const auditsListComponentQuery = graphql`
  query AuditsListComponentQuery(
    $types: [String!]
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    audits(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          event_status
          event_type
          event_scope
          timestamp
          user {
            id
            entity_type
            name
          }
          context_data {
            entity_id
            entity_type
            entity_name
            message
            workspace_type
          }
        }
      }
    }
  }
`;

interface AuditsListComponentProps {
  queryRef: PreloadedQuery<AuditsListContentQuery>,
}

const AuditsListComponent: FunctionComponent<AuditsListComponentProps> = ({
  queryRef,
}) => {
  const queryData = usePreloadedQuery<AuditsListContentQuery>(auditsListComponentQuery, queryRef);

  if (queryData && queryData.audits?.edges && queryData.audits.edges.length > 0) {
    const data = queryData.audits.edges;
    return (
      <WidgetListAudits data={data} />
    );
  }
  return <WidgetNoData />;
};

export default AuditsListComponent;
