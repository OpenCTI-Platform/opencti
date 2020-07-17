import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import {
  XOpenctiXOpenctiIncidentCard,
  XOpenctiIncidentCardDummy,
} from './XOpenctiXOpenctiIncidentCard';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfCardsToLoad = 50;

class XOpenctiXOpenctiIncidentsCards extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'xOpenctiIncidents',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const { initialLoading, relay, onLabelClick } = this.props;
    return (
      <ListCardsContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['xOpenctiIncidents', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['xOpenctiIncidents', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        CardComponent={<XOpenctiXOpenctiIncidentCard />}
        DummyCardComponent={<XOpenctiIncidentCardDummy />}
        nbOfCardsToLoad={nbOfCardsToLoad}
        onLabelClick={onLabelClick.bind(this)}
      />
    );
  }
}

XOpenctiXOpenctiIncidentsCards.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  xOpenctiIncidents: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const xOpenctiIncidentsCardsQuery = graphql`
  query XOpenctiIncidentsCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: XOpenctiIncidentsOrdering
    $orderMode: OrderingMode
    $filters: [XOpenctiIncidentsFiltering]
  ) {
    ...XOpenctiIncidentsCards_data
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
  XOpenctiXOpenctiIncidentsCards,
  {
    data: graphql`
      fragment XOpenctiIncidentsCards_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "XOpenctiIncidentsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[XOpenctiIncidentsFiltering]" }
        ) {
        xOpenctiIncidents(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_xOpenctiIncidents") {
          edges {
            node {
              id
              name
              description
              ...XOpenctiIncidentCard_node
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
      return props.data && props.data.xOpenctiIncidents;
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
    query: xOpenctiIncidentsCardsQuery,
  },
);
