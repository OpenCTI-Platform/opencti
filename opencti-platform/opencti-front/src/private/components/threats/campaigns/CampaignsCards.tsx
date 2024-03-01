import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { StixDomainObjectBookmarksQuery$data } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectBookmarksQuery.graphql';
import { CampaignsCardsPaginationQuery } from '@components/threats/campaigns/__generated__/CampaignsCardsPaginationQuery.graphql';
import { CampaignsCards_data$key } from '@components/threats/campaigns/__generated__/CampaignsCards_data.graphql';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import CampaignCard from './CampaignCard';
import { GenericAttackCardDummy } from '../../common/cards/GenericAttackCard';
import { QueryRenderer } from '../../../../relay/environment';
import StixDomainObjectBookmarks, { stixDomainObjectBookmarksQuery } from '../../common/stix_domain_objects/StixDomainObjectBookmarks';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfCardsToLoad = 20;

export const campaignsCardsQuery = graphql`
  query CampaignsCardsPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CampaignsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CampaignsCards_data
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

export const campaignsCardsFragment = graphql`
  fragment CampaignsCards_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "CampaignsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CampaignsRefetchQuery") {
    campaigns(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_campaigns") {
      edges {
        node {
          id
          name
          description
          ...CampaignCard_node
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

interface CampaignsCardsProps {
  queryRef: PreloadedQuery<CampaignsCardsPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

const CampaignsCards: FunctionComponent<CampaignsCardsProps> = ({
  setNumberOfElements,
  queryRef,
  onLabelClick,
}) => {
  const [bookmarks, setBookmarks] = useState([]);
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  CampaignsCardsPaginationQuery,
  CampaignsCards_data$key
  >({
    linesQuery: campaignsCardsQuery,
    linesFragment: campaignsCardsFragment,
    queryRef,
    nodePath: ['campaigns', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const handleSetBookmarkList = (newBookmarks: []) => {
    setBookmarks(newBookmarks);
  };

  return (
    <QueryRenderer
      query={stixDomainObjectBookmarksQuery}
      variables={{ types: ['Campaign'] }}
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
            dataList={data?.campaigns?.edges ?? []}
            globalCount={
              data?.campaigns?.pageInfo?.globalCount ?? nbOfCardsToLoad
            }
            CardComponent={CampaignCard}
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

export default CampaignsCards;
