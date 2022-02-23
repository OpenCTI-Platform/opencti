import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr, propOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  ContainerStixObjectOrStixRelationshipLine,
  ContainerStixObjectOrStixRelationshipLineDummy,
} from './ContainerStixObjectOrStixRelationshipLine';

const nbOfRowsToLoad = 8;

class ContainerStixObjectsOrStixRelationshipsLines extends Component {
  render() {
    const { initialLoading, dataColumns, relay, container, paginationOptions } = this.props;
    return (
      <div>
        <ListLinesContent
          initialLoading={initialLoading}
          loadMore={relay.loadMore.bind(this)}
          hasMore={relay.hasMore.bind(this)}
          isLoading={relay.isLoading.bind(this)}
          dataList={pathOr([], ['objects', 'edges'], container)}
          paginationOptions={paginationOptions}
          globalCount={pathOr(
            nbOfRowsToLoad,
            ['objects', 'pageInfo', 'globalCount'],
            container,
          )}
          LineComponent={
            <ContainerStixObjectOrStixRelationshipLine
              containerId={propOr(null, 'id', container)}
            />
          }
          DummyLineComponent={
            <ContainerStixObjectOrStixRelationshipLineDummy />
          }
          dataColumns={dataColumns}
          nbOfRowsToLoad={nbOfRowsToLoad}
        />
      </div>
    );
  }
}

ContainerStixObjectsOrStixRelationshipsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  container: PropTypes.object,
  relay: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  setNumberOfElements: PropTypes.func,
};

export const ContainerStixObjectsOrStixRelationshipsLinesQuery = graphql`
  query ContainerStixObjectsOrStixRelationshipsLinesQuery(
    $id: String!
    $count: Int!
    $orderBy: StixObjectOrStixRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    container(id: $id) {
      id
      objects(first: $count, orderBy: $orderBy, orderMode: $orderMode)
        @connection(key: "Pagination_objects") {
        edges {
          node {
            ... on BasicObject {
              id
            }
          }
        }
      }
      ...ContainerStixObjectsOrStixRelationshipsLines_container
        @arguments(count: $count, orderBy: $orderBy, orderMode: $orderMode)
    }
  }
`;

export default createPaginationContainer(
  ContainerStixObjectsOrStixRelationshipsLines,
  {
    container: graphql`
      fragment ContainerStixObjectsOrStixRelationshipsLines_container on Container
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        orderBy: {
          type: "StixObjectOrStixRelationshipsOrdering"
          defaultValue: name
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        id
        objects(first: $count, orderBy: $orderBy, orderMode: $orderMode)
          @connection(key: "Pagination_objects") {
          edges {
            node {
              ... on BasicObject {
                id
              }
              ...ContainerStixObjectOrStixRelationshipLine_node
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
      return props.container && props.container.objects;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count }, fragmentVariables) {
      return {
        id: fragmentVariables.id,
        count,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: ContainerStixObjectsOrStixRelationshipsLinesQuery,
  },
);
