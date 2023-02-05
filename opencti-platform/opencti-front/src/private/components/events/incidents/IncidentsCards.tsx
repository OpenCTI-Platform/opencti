import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { IncidentCard, IncidentCardDummy } from './IncidentCard';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { IncidentsCards_data$key } from './__generated__/IncidentsCards_data.graphql';
import { IncidentsCardsPaginationQuery } from './__generated__/IncidentsCardsPaginationQuery.graphql';

const nbOfCardsToLoad = 50;

export const incidentsCardsQuery = graphql`
    query IncidentsCardsPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: IncidentsOrdering
        $orderMode: OrderingMode
        $filters: [IncidentsFiltering]
    ) {
        ...IncidentsCards_data
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

const IncidentsCardsFragment = graphql`
    fragment IncidentsCards_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "IncidentsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[IncidentsFiltering]" }
    ) {
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
  queryRef: PreloadedQuery<IncidentsCardsPaginationQuery>,
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'],
  onLabelClick: () => void
}

const IncidentsCards: FunctionComponent<IncidentsCardsProps> = ({ setNumberOfElements, queryRef, onLabelClick }) => {
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<
  IncidentsCardsPaginationQuery,
  IncidentsCards_data$key
  >({
    linesQuery: incidentsCardsQuery,
    linesFragment: IncidentsCardsFragment,
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
