import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { IntrusionSetsCardsPaginationQuery } from '@components/threats/intrusion_sets/__generated__/IntrusionSetsCardsPaginationQuery.graphql';
import { IntrusionSetsCards_data$key } from '@components/threats/intrusion_sets/__generated__/IntrusionSetsCards_data.graphql';
import { StixDomainObjectBookmarksQuery$data } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectBookmarksQuery.graphql';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import IntrusionSetCard from './IntrusionSetCard';
import { GenericAttackCardDummy } from '../../common/cards/GenericAttackCard';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectBookmarks, { stixDomainObjectBookmarksQuery } from '../../common/stix_domain_objects/StixDomainObjectBookmarks';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfCardsToLoad = 20;

export const intrusionSetsCardsQuery = graphql`
  query IntrusionSetsCardsPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: IntrusionSetsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IntrusionSetsCards_data
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

export const intrusionSetsCardsFragment = graphql`
  fragment IntrusionSetsCards_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IntrusionSetsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IntrusionSetsRefetchQuery") {
    intrusionSets(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_intrusionSets") {
      edges {
        node {
          id
          name
          description
          ...IntrusionSetCard_node
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

interface IntrusionSetsCardsProps {
  queryRef: PreloadedQuery<IntrusionSetsCardsPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

const IntrusionSetsCards: FunctionComponent<IntrusionSetsCardsProps> = ({
  setNumberOfElements,
  queryRef,
  onLabelClick,
}) => {
  const [bookmarks, setBookmarks] = useState([]);
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  IntrusionSetsCardsPaginationQuery,
  IntrusionSetsCards_data$key
  >({
    linesQuery: intrusionSetsCardsQuery,
    linesFragment: intrusionSetsCardsFragment,
    queryRef,
    nodePath: ['intrusionSets', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  const handleSetBookmarkList = (newBookmarks: []) => {
    setBookmarks(newBookmarks);
  };
  return (
    <QueryRenderer
      query={stixDomainObjectBookmarksQuery}
      variables={{ types: ['Intrusion-Set'] }}
      render={({ props }: { props: StixDomainObjectBookmarksQuery$data }) => (
        <>
          <StixDomainObjectBookmarks
            data={props}
            onLabelClick={onLabelClick}
            setBookmarkList={handleSetBookmarkList}
          />
          <ListCardsContent
            initialLoading={!data}
            loadMore={loadMore}
            hasMore={hasMore}
            isLoading={isLoadingMore}
            DummyCardComponent={GenericAttackCardDummy}
            dataList={data?.intrusionSets?.edges ?? []}
            globalCount={
              data?.intrusionSets?.pageInfo?.globalCount ?? nbOfCardsToLoad
            }
            CardComponent={IntrusionSetCard}
            nbOfCardsToLoad={nbOfCardsToLoad}
            onLabelClick={onLabelClick}
            bookmarkList={bookmarks}
            rowHeight={350}
          />
        </>
      )}
    />
  );
};

export default IntrusionSetsCards;
