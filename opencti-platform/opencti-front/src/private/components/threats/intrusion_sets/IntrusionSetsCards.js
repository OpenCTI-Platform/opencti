import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { IntrusionSetCard, IntrusionSetCardDummy } from './IntrusionSetCard';

const nbOfCardsToLoad = 25;

class IntrusionSetsCards extends Component {
  render() {
    const { initialLoading, relay } = this.props;
    return (
      <ListCardsContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['intrusionSets', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['intrusionSets', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        CardComponent={<IntrusionSetCard />}
        DummyCardComponent={<IntrusionSetCardDummy />}
        nbOfCardsToLoad={nbOfCardsToLoad}
      />
    );
  }
}

IntrusionSetsCards.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  intrusionSets: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const intrusionSetsCardsQuery = graphql`
  query IntrusionSetsCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IntrusionSetsOrdering
    $orderMode: OrderingMode
  ) {
    ...IntrusionSetsCards_data
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
  IntrusionSetsCards,
  {
    data: graphql`
      fragment IntrusionSetsCards_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "IntrusionSetsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        intrusionSets(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
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
            globalCount
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.intrusionSets;
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
    query: intrusionSetsCardsQuery,
  },
);
