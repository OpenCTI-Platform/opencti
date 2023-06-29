import { graphql, PreloadedQuery } from 'react-relay';
import { FunctionComponent, useState } from 'react';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { ThreatActorIndividualCard, ThreatActorIndividualCardDummy } from './ThreatActorIndividualCard';
import StixDomainObjectBookmarks, {
  stixDomainObjectBookmarksQuery,
} from '../../common/stix_domain_objects/StixDomainObjectBookmarks';
import {
  ThreatActorsIndividualCardsPaginationQuery,
} from './__generated__/ThreatActorsIndividualCardsPaginationQuery.graphql';
import { ThreatActorsIndividualCards_data$key } from './__generated__/ThreatActorsIndividualCards_data.graphql';
import { StixDomainObjectBookmarksQuery$data,
} from '../../common/stix_domain_objects/__generated__/StixDomainObjectBookmarksQuery.graphql';
import { QueryRenderer } from '../../../../relay/environment';

const nbOfCardsToLoad = 12;

export const threatActorsIndividualCardsPaginationQuery = graphql`
  query ThreatActorsIndividualCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ThreatActorsIndividualOrdering
    $orderMode: OrderingMode
    $filters: [ThreatActorsIndividualFiltering]
  ) {
    ...ThreatActorsIndividualCards_data
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

export const ThreatActorsIndividualCardsFragment = graphql`
  fragment ThreatActorsIndividualCards_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ThreatActorsIndividualOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "[ThreatActorsIndividualFiltering]" }
  ) 
  @refetchable(queryName: "ThreatActorsIndividualRefetchQuery") {
    bookmarks(
      types: ["Threat-Actor-Individual"]
    ) {
      edges {
        node {
          ...StixDomainObjectBookmark_node
        }
      }
    }
    threatActorsIndividuals(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_threatActorsIndividuals") {
      edges {
        node {
          id
          name
          description
          ...ThreatActorIndividualCard_node
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

interface ThreatActorsIndividualCardsProps {
  queryRef: PreloadedQuery<ThreatActorsIndividualCardsPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

const ThreatActorsIndividualCards: FunctionComponent<ThreatActorsIndividualCardsProps> = ({
  setNumberOfElements,
  queryRef,
  onLabelClick,
}) => {
  const [bookmarks, setBookmarks] = useState([]);
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ThreatActorsIndividualCardsPaginationQuery,
  ThreatActorsIndividualCards_data$key
  >({
    linesQuery: threatActorsIndividualCardsPaginationQuery,
    linesFragment: ThreatActorsIndividualCardsFragment,
    queryRef,
    nodePath: ['threatActorsIndividuals', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const handleSetBookmarkList = () => {
    setBookmarks(bookmarks);
  };

  return (
    <div>
      <StixDomainObjectBookmarks
        data={data}
        onLabelClick={onLabelClick}
        setBookmarkList={handleSetBookmarkList}
      />
      <ListCardsContent
        initialLoading={!data}
        loadMore={loadMore}
        hasMore={hasMore}
        isLoading={isLoadingMore}
        dataList={data?.threatActorsIndividuals?.edges ?? []}
        globalCount={data?.threatActorsIndividuals?.pageInfo?.globalCount ?? nbOfCardsToLoad}
        CardComponent={ThreatActorIndividualCard}
        DummyCardComponent={ThreatActorIndividualCardDummy}
        nbOfCardsToLoad={nbOfCardsToLoad}
        onLabelClick={onLabelClick}
        bookmarkList={bookmarks}
        rowHeight={340}
      />
    </div>
  );
};

export default ThreatActorsIndividualCards;
