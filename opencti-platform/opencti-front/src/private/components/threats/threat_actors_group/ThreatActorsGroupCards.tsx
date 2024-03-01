import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { StixDomainObjectBookmarksQuery$data } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectBookmarksQuery.graphql';
import { ThreatActorsGroupCardsPaginationQuery } from '@components/threats/threat_actors_group/__generated__/ThreatActorsGroupCardsPaginationQuery.graphql';
import { ThreatActorsGroupCards_data$key } from '@components/threats/threat_actors_group/__generated__/ThreatActorsGroupCards_data.graphql';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import ThreatActorGroupCard from './ThreatActorGroupCard';
import { GenericAttackCardDummy } from '../../common/cards/GenericAttackCard';
import StixDomainObjectBookmarks, { stixDomainObjectBookmarksQuery } from '../../common/stix_domain_objects/StixDomainObjectBookmarks';
import { QueryRenderer } from '../../../../relay/environment';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfCardsToLoad = 20;
export const threatActorsGroupCardsQuery = graphql`
  query ThreatActorsGroupCardsPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: ThreatActorsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ThreatActorsGroupCards_data
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

export const ThreatActorsGroupCardsFragment = graphql`
  fragment ThreatActorsGroupCards_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ThreatActorsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ThreatActorsGroupRefetchQuery") {
    threatActorsGroup(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_threatActorsGroup") {
      edges {
        node {
          id
          name
          description
          ...ThreatActorGroupCard_node
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

interface ThreatActorsGroupCardsProps {
  queryRef: PreloadedQuery<ThreatActorsGroupCardsPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

const ThreatActorsGroupCards: FunctionComponent<
ThreatActorsGroupCardsProps
> = ({ setNumberOfElements, queryRef, onLabelClick }) => {
  const [bookmarks, setBookmarks] = useState([]);
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ThreatActorsGroupCardsPaginationQuery,
  ThreatActorsGroupCards_data$key
  >({
    linesQuery: threatActorsGroupCardsQuery,
    linesFragment: ThreatActorsGroupCardsFragment,
    queryRef,
    nodePath: ['threatActorsGroup', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const handleSetBookmarkList = (newBookmarks: []) => {
    setBookmarks(newBookmarks);
  };
  return (
    <QueryRenderer
      query={stixDomainObjectBookmarksQuery}
      variables={{ types: ['Threat-Actor-Group'] }}
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
            dataList={data?.threatActorsGroup?.edges ?? []}
            globalCount={
              data?.threatActorsGroup?.pageInfo?.globalCount ?? nbOfCardsToLoad
            }
            CardComponent={ThreatActorGroupCard}
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

export default ThreatActorsGroupCards;
