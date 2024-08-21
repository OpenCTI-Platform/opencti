import React, { FunctionComponent } from 'react';
import { createPaginationContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import { ContainerStixObjectOrStixRelationshipLine } from './ContainerStixObjectOrStixRelationshipLine';
import { DataColumns } from '../../../../components/list_lines';
import { ContainerStixObjectsOrStixRelationshipsLines_container$data } from './__generated__/ContainerStixObjectsOrStixRelationshipsLines_container.graphql';
import { ContainerStixObjectsOrStixRelationshipsLinesQuery$variables } from './__generated__/ContainerStixObjectsOrStixRelationshipsLinesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

interface ContainerStixObjectsOrStixRelationshipsLinesProps {
  dataColumns: DataColumns;
  container: ContainerStixObjectsOrStixRelationshipsLines_container$data;
  paginationOptions?: ContainerStixObjectsOrStixRelationshipsLinesQuery$variables;
  enableReferences: boolean;
}

const ContainerStixObjectsOrStixRelationshipsLines: FunctionComponent<
ContainerStixObjectsOrStixRelationshipsLinesProps
> = ({ dataColumns, container, paginationOptions, enableReferences }) => {
  const { t_i18n } = useFormatter();
  return (
    <div style={{ height: '100%' }}>
      {(container.objects?.edges ?? []).length > 0 ? (
        <List>
          {(container.objects?.edges ?? []).map((objectEdge) => {
            const object = objectEdge?.node;
            return (
              <ContainerStixObjectOrStixRelationshipLine
                key={object?.id ?? null}
                containerId={container?.id ?? null}
                node={object}
                dataColumns={dataColumns}
                paginationOptions={paginationOptions}
                enableReferences={enableReferences}
              />
            );
          })}
        </List>
      ) : (
        <div
          style={{
            display: 'table',
            height: '100%',
            width: '100%',
            paddingTop: 15,
            paddingBottom: 15,
          }}
        >
          <span
            style={{
              display: 'table-cell',
              verticalAlign: 'middle',
              textAlign: 'center',
            }}
          >
            {t_i18n('No entities of this type has been found.')}
          </span>
        </div>
      )}
    </div>
  );
};

export const ContainerStixObjectsOrStixRelationshipsLinesQuery = graphql`
  query ContainerStixObjectsOrStixRelationshipsLinesQuery(
    $id: String!
    $types: [String]
    $count: Int!
    $orderBy: StixObjectOrStixRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    container(id: $id) {
      id
      objects(
        types: $types
        first: $count
        orderBy: $orderBy
        orderMode: $orderMode
      ) @connection(key: "Pagination_objects") {
        edges {
          node {
            ... on BasicObject {
              id
            }
          }
        }
      }
      ...ContainerStixObjectsOrStixRelationshipsLines_container
        @arguments(
          types: $types
          count: $count
          orderBy: $orderBy
          orderMode: $orderMode
        )
    }
  }
`;

export default createPaginationContainer(
  ContainerStixObjectsOrStixRelationshipsLines,
  {
    container: graphql`
      fragment ContainerStixObjectsOrStixRelationshipsLines_container on Container
      @argumentDefinitions(
        types: { type: "[String]" }
        count: { type: "Int", defaultValue: 25 }
        orderBy: {
          type: "StixObjectOrStixRelationshipsOrdering"
          defaultValue: name
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
        id
        objects(
          types: $types
          first: $count
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_objects") {
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
        types: fragmentVariables.types,
        id: fragmentVariables.id,
        count,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: ContainerStixObjectsOrStixRelationshipsLinesQuery,
  },
);
