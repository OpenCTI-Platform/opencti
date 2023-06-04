import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createPaginationContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import {
  reportKnowledgeGraphMutationRelationDeleteMutation,
  reportKnowledgeGraphtMutationRelationAddMutation,
} from '../../analysis/reports/ReportKnowledgeGraphQuery';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  ContainerAddStixCoreObjectsLine,
  ContainerAddStixCoreObjecstLineDummy,
} from './ContainerAddStixCoreObjectsLine';

const nbOfRowsToLoad = 50;

const styles = (theme) => ({
  container: {
    padding: '20px 0 20px 0',
  },
  heading: {
    fontSize: theme.typography.pxToRem(15),
    flexBasis: '33.33%',
    flexShrink: 0,
  },
  secondaryHeading: {
    fontSize: theme.typography.pxToRem(15),
    color: theme.palette.text.secondary,
  },
  expansionPanelContent: {
    padding: 0,
  },
  list: {
    width: '100%',
  },
  listItem: {
    width: '100%',
  },
  icon: {
    color: theme.palette.primary.main,
  },
  tooltip: {
    maxWidth: '80%',
    lineHeight: 2,
    padding: 10,
    backgroundColor: '#323232',
  },
});

export const containerAddStixCoreObjectsLinesRelationAddMutation = graphql`
  mutation ContainerAddStixCoreObjectsLinesRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    containerEdit(id: $id) {
      relationAdd(input: $input) {
        id
        to {
          ... on StixDomainObject {
            ...ContainerStixDomainObjectLine_node
          }
          ... on StixCyberObservable {
            ...ContainerStixCyberObservableLine_node
          }
          ... on StixFile {
            observableName: name
          }
        }
      }
    }
  }
`;

export const containerAddStixCoreObjectsLinesRelationDeleteMutation = graphql`
  mutation ContainerAddStixCoreObjectsLinesRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    containerEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

class ContainerAddStixCoreObjectsLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      expandedPanels: {},
      addedStixCoreObjects: R.indexBy(
        R.prop('id'),
        (props.containerStixCoreObjects || []).map((n) => n.node),
      ),
    };
  }

  toggleStixCoreObject(stixCoreObject) {
    const { containerId, paginationOptions, knowledgeGraph, onAdd, onDelete } = this.props;
    const { addedStixCoreObjects } = this.state;
    const alreadyAdded = stixCoreObject.id in addedStixCoreObjects;
    if (alreadyAdded) {
      if (knowledgeGraph) {
        commitMutation({
          mutation: reportKnowledgeGraphMutationRelationDeleteMutation,
          variables: {
            id: containerId,
            toId: stixCoreObject.id,
            relationship_type: 'object',
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: R.dissoc(
                stixCoreObject.id,
                this.state.addedStixCoreObjects,
              ),
            });
            if (typeof onDelete === 'function') {
              onDelete(stixCoreObject);
            }
          },
        });
      } else {
        commitMutation({
          mutation: containerAddStixCoreObjectsLinesRelationDeleteMutation,
          variables: {
            id: containerId,
            toId: stixCoreObject.id,
            relationship_type: 'object',
          },
          updater: (store) => {
            // ID is not valid pagination options, will be handled better when hooked
            const options = { ...paginationOptions };
            delete options.id;
            delete options.count;
            const conn = ConnectionHandler.getConnection(
              store.get(containerId),
              'Pagination_objects',
              options,
            );
            ConnectionHandler.deleteNode(conn, stixCoreObject.id);
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: R.dissoc(
                stixCoreObject.id,
                this.state.addedStixCoreObjects,
              ),
            });
          },
        });
      }
    } else {
      const input = {
        toId: stixCoreObject.id,
        relationship_type: 'object',
      };
      if (knowledgeGraph) {
        commitMutation({
          mutation: reportKnowledgeGraphtMutationRelationAddMutation,
          variables: {
            id: containerId,
            input,
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: {
                ...this.state.addedStixCoreObjects,
                [stixCoreObject.id]: stixCoreObject,
              },
            });
            if (typeof onAdd === 'function') {
              onAdd(stixCoreObject);
            }
          },
        });
      } else {
        commitMutation({
          mutation: containerAddStixCoreObjectsLinesRelationAddMutation,
          variables: {
            id: containerId,
            input,
          },
          updater: (store) => {
            // ID is not valid pagination options, will be handled better when hooked
            const options = { ...paginationOptions };
            delete options.id;
            delete options.count;

            const payload = store
              .getRootField('containerEdit')
              .getLinkedRecord('relationAdd', { input })
              .getLinkedRecord('to');
            const newEdge = payload.setLinkedRecord(payload, 'node');
            const conn = ConnectionHandler.getConnection(
              store.get(containerId),
              'Pagination_objects',
              options,
            );
            ConnectionHandler.insertEdgeBefore(conn, newEdge);
          },
          onCompleted: () => {
            this.setState({
              addedStixCoreObjects: {
                ...this.state.addedStixCoreObjects,
                [stixCoreObject.id]: stixCoreObject,
              },
            });
          },
        });
      }
    }
  }

  render() {
    const { initialLoading, dataColumns, relay } = this.props;
    const { addedStixCoreObjects } = this.state;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={R.pathOr([], ['stixCoreObjects', 'edges'], this.props.data)}
        globalCount={R.pathOr(
          nbOfRowsToLoad,
          ['stixCoreObjects', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<ContainerAddStixCoreObjectsLine />}
        DummyLineComponent={<ContainerAddStixCoreObjecstLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        selectedElements={addedStixCoreObjects}
        onToggleEntity={this.toggleStixCoreObject.bind(this)}
      />
    );
  }
}

ContainerAddStixCoreObjectsLinesContainer.propTypes = {
  containerId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  knowledgeGraph: PropTypes.bool,
  containerStixCoreObjects: PropTypes.array,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
};

export const containerAddStixCoreObjectsLinesQuery = graphql`
  query ContainerAddStixCoreObjectsLinesQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreObjectsFiltering]
    $filterMode: FilterMode
  ) {
    ...ContainerAddStixCoreObjectsLines_data
      @arguments(
        types: $types
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
        filterMode: $filterMode
      )
  }
`;

const ContainerAddStixCoreObjectsLines = createPaginationContainer(
  ContainerAddStixCoreObjectsLinesContainer,
  {
    data: graphql`
      fragment ContainerAddStixCoreObjectsLines_data on Query
      @argumentDefinitions(
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[StixCoreObjectsFiltering]" }
        filterMode: { type: "FilterMode" }
      ) {
        stixCoreObjects(
          types: $types
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
          filterMode: $filterMode
        ) @connection(key: "Pagination_stixCoreObjects") {
          edges {
            node {
              id
              entity_type
              created_at
              createdBy {
                ... on Identity {
                  name
                }
              }
              creators {
                id
                name
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                  }
                }
              }
              ...ContainerAddStixCoreObjectsLine_node
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
      return props.data && props.data.stixCoreObjects;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        types: fragmentVariables.types,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: containerAddStixCoreObjectsLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(ContainerAddStixCoreObjectsLines);
