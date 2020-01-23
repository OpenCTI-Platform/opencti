import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { IntrusionSetCard, IntrusionSetCardDummy } from './IntrusionSetCard';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfCardsToLoad = 25;

class IntrusionSetsCards extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'intrusionSets',
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
        dataList={pathOr([], ['intrusionSets', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['intrusionSets', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        CardComponent={<IntrusionSetCard />}
        DummyCardComponent={<IntrusionSetCardDummy />}
        nbOfCardsToLoad={nbOfCardsToLoad}
        onTagClick={onTagClick.bind(this)}
      />
    );
  }
}

IntrusionSetsCards.propTypes = {
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onTagClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const intrusionSetsCardsQuery = graphql`
  query IntrusionSetsCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IntrusionSetsOrdering
    $orderMode: OrderingMode
    $filters: [IntrusionSetsFiltering]
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
          filters: { type: "[IntrusionSetsFiltering]" }
        ) {
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
        filters: fragmentVariables.filters,
      };
    },
    query: intrusionSetsCardsQuery,
  },
);
