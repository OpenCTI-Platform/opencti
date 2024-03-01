import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { EventsLinesPaginationQuery, EventsLinesPaginationQuery$variables } from '@components/entities/events/__generated__/EventsLinesPaginationQuery.graphql';
import { EventsLines_data$key } from '@components/entities/events/__generated__/EventsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { EventLine, EventLineDummy } from './EventLine';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

interface EventsLinesProps {
  queryRef: PreloadedQuery<EventsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: EventsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const eventsLinesQuery = graphql`
    query EventsLinesPaginationQuery(
        $search: String
        $count: Int
        $cursor: ID
        $orderBy: EventsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...EventsLines_data
        @arguments(
            search: $search
            count: $count
            cursor: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        )
    }
`;

const eventsLinesFragment = graphql`
    fragment EventsLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "EventsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "EventsLinesRefetchQuery") {
        events(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_events") {
            edges {
                node {
                    id
                    name
                    description
                    ...EventLine_node
                }
            }
            pageInfo {
                endCursor
                hasNextPage
                globalCount
            }
        }
    }
`;

const EventsLines: FunctionComponent<EventsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment <
  EventsLinesPaginationQuery,
  EventsLines_data$key
  >({
    linesQuery: eventsLinesQuery,
    linesFragment: eventsLinesFragment,
    queryRef,
    nodePath: ['events', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.events?.edges ?? []}
      globalCount={
          data?.events?.pageInfo?.globalCount ?? nbOfRowsToLoad
        }
      LineComponent={EventLine}
      DummyLineComponent={EventLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default EventsLines;
