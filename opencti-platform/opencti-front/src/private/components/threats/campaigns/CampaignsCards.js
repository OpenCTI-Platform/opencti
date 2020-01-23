import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { CampaignCard, CampaignCardDummy } from './CampaignCard';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfCardsToLoad = 25;

class CampaignsCards extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'campaigns',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const { initialLoading, relay, onTagClick } = this.props;
    return (
      <ListCardsContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['campaigns', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['campaigns', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        CardComponent={<CampaignCard />}
        DummyCardComponent={<CampaignCardDummy />}
        nbOfCardsToLoad={nbOfCardsToLoad}
        onTagClick={onTagClick.bind(this)}
      />
    );
  }
}

CampaignsCards.propTypes = {
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onTagClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const campaignsCardsQuery = graphql`
  query CampaignsCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: CampaignsOrdering
    $orderMode: OrderingMode
    $filters: [CampaignsFiltering]
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

export default createPaginationContainer(
  CampaignsCards,
  {
    data: graphql`
      fragment CampaignsCards_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "CampaignsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[CampaignsFiltering]" }
        ) {
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
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.campaigns;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: campaignsCardsQuery,
  },
);
