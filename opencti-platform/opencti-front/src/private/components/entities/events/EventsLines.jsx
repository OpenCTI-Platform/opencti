import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { EventLine, EventLineDummy } from './EventLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class EventsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'events',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const { initialLoading, dataColumns, relay, paginationOptions } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['events', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['events', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<EventLine />}
        DummyLineComponent={<EventLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

EventsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  setNumberOfElements: PropTypes.func,
};

export const eventsLinesQuery = graphql`
  query EventsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: EventsOrdering
    $orderMode: OrderingMode
    $filters: [EventsFiltering!]
  ) {
    ...EventsLines_data
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
  EventsLines,
  {
    data: graphql`
      fragment EventsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "EventsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[EventsFiltering!]" }
      ) {
        events(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_events") {
          edges {
            node {
              id
              name
              description
              ...EventLine_node
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
      return props.data && props.data.events;
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
    query: eventsLinesQuery,
  },
);
