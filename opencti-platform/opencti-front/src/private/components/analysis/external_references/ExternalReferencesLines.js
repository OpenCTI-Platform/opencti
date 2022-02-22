import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  ExternalReferenceLine,
  ExternalReferenceLineDummy,
} from './ExternalReferenceLine';

const nbOfRowsToLoad = 50;

class ExternalReferencesLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay, paginationOptions } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['externalReferences', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['externalReferences', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<ExternalReferenceLine />}
        DummyLineComponent={<ExternalReferenceLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
      />
    );
  }
}

ExternalReferencesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  externalReferences: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const externalReferencesLinesQuery = graphql`
  query ExternalReferencesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ExternalReferencesOrdering
    $orderMode: OrderingMode
  ) {
    ...ExternalReferencesLines_data
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
  ExternalReferencesLines,
  {
    data: graphql`
      fragment ExternalReferencesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
          type: "ExternalReferencesOrdering"
          defaultValue: source_name
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        externalReferences(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_externalReferences") {
          edges {
            node {
              ...ExternalReferenceLine_node
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
      return props.data && props.data.externalReferences;
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
    query: externalReferencesLinesQuery,
  },
);
