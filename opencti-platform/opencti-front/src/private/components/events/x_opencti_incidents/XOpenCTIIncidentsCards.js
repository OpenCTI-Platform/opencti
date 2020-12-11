import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';
import {
  XOpenCTIXOpenCTIIncidentCard,
  XOpenCTIIncidentCardDummy,
} from './XOpenCTIIncidentCard';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfCardsToLoad = 50;

class XOpenCTIXOpenCTIIncidentsCards extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'XOpenCTIIncidents',
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
        dataList={pathOr([], ['xOpenCTIIncidents', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfCardsToLoad,
          ['xOpenCTIIncidents', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        CardComponent={<XOpenCTIXOpenCTIIncidentCard />}
        DummyCardComponent={<XOpenCTIIncidentCardDummy />}
        nbOfCardsToLoad={nbOfCardsToLoad}
        onLabelClick={onLabelClick.bind(this)}
      />
    );
  }
}

XOpenCTIXOpenCTIIncidentsCards.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  relay: PropTypes.object,
  XOpenCTIIncidents: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const XOpenCTIIncidentsCardsQuery = graphql`
  query XOpenCTIIncidentsCardsPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: XOpenCTIIncidentsOrdering
    $orderMode: OrderingMode
    $filters: [XOpenCTIIncidentsFiltering]
  ) {
    ...XOpenCTIIncidentsCards_data
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
  XOpenCTIXOpenCTIIncidentsCards,
  {
    data: graphql`
      fragment XOpenCTIIncidentsCards_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "XOpenCTIIncidentsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[XOpenCTIIncidentsFiltering]" }
      ) {
        xOpenCTIIncidents(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_xOpenCTIIncidents") {
          edges {
            node {
              id
              name
              description
              ...XOpenCTIIncidentCard_node
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
      return props.data && props.data.XOpenCTIIncidents;
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
    query: XOpenCTIIncidentsCardsQuery,
  },
);
