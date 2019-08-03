import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { SectorCard, SectorCardDummy } from './SectorCard';

const nbOfCardsToLoad = 25;

class SectorsCards extends Component {
  render() {
    const { initialLoading, relay } = this.props;
    return (
      <ListCardsContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['sectors', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['sectors', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        CardComponent={<SectorCard />}
        DummyCardComponent={<SectorCardDummy />}
        nbOfCardsToLoad={nbOfCardsToLoad}
      />
    );
  }
}

SectorsCards.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  sectors: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const sectorsCardsQuery = graphql`
  query SectorsCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: SectorsOrdering
    $orderMode: OrderingMode
  ) {
    ...SectorsCards_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  SectorsCards,
  {
    data: graphql`
      fragment SectorsCards_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "SectorsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        sectors(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_sectors") {
          edges {
            node {
              id
              name
              description
              ...SectorCard_node
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
      return props.data && props.data.sectors;
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
      };
    },
    query: sectorsCardsQuery,
  },
);
