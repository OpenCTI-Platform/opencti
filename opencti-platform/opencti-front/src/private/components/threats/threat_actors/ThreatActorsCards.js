import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import { ThreatActorCard, ThreatActorCardDummy } from './ThreatActorCard';

const nbOfCardsToLoad = 25;

class ThreatActorsCards extends Component {
  render() {
    const { initialLoading, relay, onTagClick } = this.props;
    return (
      <ListCardsContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['threatActors', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['threatActors', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        CardComponent={<ThreatActorCard />}
        DummyCardComponent={<ThreatActorCardDummy />}
        nbOfCardsToLoad={nbOfCardsToLoad}
        onTagClick={onTagClick.bind(this)}
      />
    );
  }
}

ThreatActorsCards.propTypes = {
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  onTagClick: PropTypes.func,
};

export const threatActorsCardsQuery = graphql`
  query ThreatActorsCardsPaginationQuery(
    $search: String
    $filters: ThreatActorsFiltering
    $count: Int!
    $cursor: ID
    $orderBy: ThreatActorsOrdering
    $orderMode: OrderingMode
  ) {
    ...ThreatActorsCards_data
      @arguments(
        search: $search
        filters: $filters
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  ThreatActorsCards,
  {
    data: graphql`
      fragment ThreatActorsCards_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          filters: { type: "ThreatActorsFiltering" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "ThreatActorsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        threatActors(
          search: $search
          filters: $filters
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_threatActors") {
          edges {
            node {
              id
              name
              description
              ...ThreatActorCard_node
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
      return props.data && props.data.threatActors;
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
        filters: fragmentVariables.filters,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: threatActorsCardsQuery,
  },
);
