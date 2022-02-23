import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { AttributeLine, AttributeLineDummy } from './AttributeLine';

const nbOfRowsToLoad = 200;

const AttributesLines = (props) => {
  const { data, initialLoading, dataColumns, relay, paginationOptions } = props;
  const attributes = data?.runtimeAttributes?.edges ?? [];
  const globalCount = data?.runtimeAttributes?.pageInfo?.globalCount ?? nbOfRowsToLoad;
  const refetch = () => relay.refetchConnection(nbOfRowsToLoad);
  return (
    <ListLinesContent
      initialLoading={initialLoading}
      loadMore={relay.loadMore}
      hasMore={relay.hasMore}
      refetch={refetch}
      isLoading={relay.isLoading}
      dataList={attributes}
      globalCount={globalCount}
      LineComponent={<AttributeLine />}
      DummyLineComponent={<AttributeLineDummy />}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

AttributesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  attributes: PropTypes.object,
  initialLoading: PropTypes.bool,
};

export const attributesQuery = graphql`
  query AttributesLinesAttributesQuery($key: String!) {
    runtimeAttributes(attributeName: $key) {
      edges {
        node {
          id
          key
          value
        }
      }
    }
  }
`;

export const attributesLinesQuery = graphql`
  query AttributesLinesPaginationQuery(
    $attributeName: String!
    $search: String
    $count: Int
    $orderMode: OrderingMode
  ) {
    ...AttributesLines_data
      @arguments(
        attributeName: $attributeName
        search: $search
        count: $count
        orderMode: $orderMode
      )
  }
`;

export default createPaginationContainer(
  AttributesLines,
  {
    data: graphql`
      fragment AttributesLines_data on Query
      @argumentDefinitions(
        attributeName: { type: "String!" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 200 }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        runtimeAttributes(
          attributeName: $attributeName
          search: $search
          first: $count
          orderMode: $orderMode
        ) @connection(key: "Pagination_runtimeAttributes") {
          edges {
            node {
              ...AttributeLine_node
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
      return props.data && props.data.runtimeAttributes;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count }, fragmentVariables) {
      return {
        count,
        attributeName: fragmentVariables.attributeName,
        search: fragmentVariables.search,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: attributesLinesQuery,
  },
);
