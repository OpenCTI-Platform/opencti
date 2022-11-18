import React, { FunctionComponent } from 'react';
import { createPaginationContainer, graphql, RelayPaginationProp } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  ContainerStixObjectOrStixRelationshipLine,
  ContainerStixObjectOrStixRelationshipLineDummy,
} from './ContainerStixObjectOrStixRelationshipLine';
import { DataColumns } from '../../../../components/list_lines';
import {
  ContainerStixObjectsOrStixRelationshipsLines_container$data,
} from './__generated__/ContainerStixObjectsOrStixRelationshipsLines_container.graphql';
import {
  ContainerStixObjectsOrStixRelationshipsLinesQuery$variables,
} from './__generated__/ContainerStixObjectsOrStixRelationshipsLinesQuery.graphql';

const nbOfRowsToLoad = 8;

interface ContainerStixObjectsOrStixRelationshipsLinesProps {
  initialLoading: boolean,
  dataColumns: DataColumns,
  relay: RelayPaginationProp,
  container: ContainerStixObjectsOrStixRelationshipsLines_container$data,
  paginationOptions?: ContainerStixObjectsOrStixRelationshipsLinesQuery$variables,
}

const ContainerStixObjectsOrStixRelationshipsLines: FunctionComponent<ContainerStixObjectsOrStixRelationshipsLinesProps> = ({
  initialLoading,
  dataColumns,
  relay,
  container,
  paginationOptions }) => {
  return (
    <div>
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore}
        hasMore={relay.hasMore}
        isLoading={relay.isLoading}
        dataList={container?.objects?.edges ?? []}
        paginationOptions={paginationOptions}
        globalCount={container?.objects?.pageInfo?.globalCount ?? nbOfRowsToLoad}
        LineComponent={
          <ContainerStixObjectOrStixRelationshipLine
            containerId={container?.id ?? null}
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
            types
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
