import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { IncidentCard, IncidentCardDummy } from './IncidentCard';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { IncidentsCardsAndLines_data$key } from './__generated__/IncidentsCardsAndLines_data.graphql';
import { IncidentsCardsAndLinesPaginationQuery } from './__generated__/IncidentsCardsAndLinesPaginationQuery.graphql';

const nbOfCardsToLoad = 50;

export const incidentsCardsAndLinesPaginationQuery = graphql`
    query IncidentsCardsAndLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: IncidentsOrdering
        $orderMode: OrderingMode
        $filters: [IncidentsFiltering]
    ) {
        ...IncidentsCardsAndLines_data
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

export const IncidentsCardsAndLinesFragment = graphql`
    fragment IncidentsCardsAndLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "IncidentsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[IncidentsFiltering]" }
    ) @refetchable(queryName: "IncidentsCardsRefetchQuery") {
        incidents(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_incidents") {
            edges {
                node {
                    id
                    name
                    description
                    ...IncidentCard_node
                    ...IncidentLine_node
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

interface IncidentsCardsProps {
  queryRef: PreloadedQuery<IncidentsCardsAndLinesPaginationQuery>,
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'],
  onLabelClick: HandleAddFilter
}

const IncidentsCards: FunctionComponent<IncidentsCardsProps> = ({ setNumberOfElements, queryRef, onLabelClick }) => {
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<
  IncidentsCardsAndLinesPaginationQuery,
  IncidentsCardsAndLines_data$key
  >({
    linesQuery: incidentsCardsAndLinesPaginationQuery,
    linesFragment: IncidentsCardsAndLinesFragment,
    queryRef,
    setNumberOfElements,
  });
  return (
    <ListCardsContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.incidents?.edges ?? []}
      globalCount={data?.incidents?.pageInfo?.globalCount ?? nbOfCardsToLoad}
      CardComponent={IncidentCard}
      DummyCardComponent={IncidentCardDummy}
      nbOfCardsToLoad={nbOfCardsToLoad}
      onLabelClick={onLabelClick}
    />
  );
};

export default IncidentsCards;
