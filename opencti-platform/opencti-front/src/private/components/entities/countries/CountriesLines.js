import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { CountryLine, CountryLineDummy } from './CountryLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 25;

class CountriesLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'countries',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      paginationOptions,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['countries', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['countries', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<CountryLine />}
        DummyLineComponent={<CountryLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

CountriesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  setNumberOfElements: PropTypes.func,
};

export const countriesLinesQuery = graphql`
  query CountriesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: CountriesOrdering
    $orderMode: OrderingMode
    $filters: [CountriesFiltering]
  ) {
    ...CountriesLines_data
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
  CountriesLines,
  {
    data: graphql`
      fragment CountriesLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "CountriesOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[CountriesFiltering]" }
        ) {
        countries(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_countries") {
          edges {
            node {
              id
              name
              description
              ...CountryLine_node
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
      return props.data && props.data.countries;
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
    query: countriesLinesQuery,
  },
);
