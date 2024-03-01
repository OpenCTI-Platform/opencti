import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, filter, head, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircle, DocumentScannerOutlined } from '@mui/icons-material';
import { ConnectionHandler } from 'relay-runtime';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import ExternalReferenceCreation from './ExternalReferenceCreation';
import { isNotEmptyField } from '../../../../utils/utils';
import ItemIcon from '../../../../components/ItemIcon';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

export const externalReferenceLinesMutationRelationAdd = graphql`
  mutation AddExternalReferencesLinesRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    externalReferenceEdit(id: $id) {
      relationAdd(input: $input) {
        id
        to {
          ... on ExternalReference {
            id
            source_name
            description
            url
            hash
            external_id
            jobs(first: 100) {
              id
              timestamp
              connector {
                id
                name
              }
              messages {
                timestamp
                message
              }
              errors {
                timestamp
                message
              }
              status
            }
            connectors(onlyAlive: false) {
              id
              connector_type
              name
              active
              updated_at
            }
            importFiles(first: 500) {
              edges {
                node {
                  id
                  lastModified
                  ...FileLine_file
                  metaData {
                    mimetype
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

export const externalReferenceMutationRelationDelete = graphql`
  mutation AddExternalReferencesLinesRelationDeleteMutation(
    $id: ID!
    $fromId: StixRef!
    $relationship_type: String!
  ) {
    externalReferenceEdit(id: $id) {
      relationDelete(fromId: $fromId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

const sharedUpdater = (store, stixCoreObjectId, newEdge) => {
  const entity = store.get(stixCoreObjectId);
  const conn = ConnectionHandler.getConnection(
    entity,
    'Pagination_externalReferences',
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddExternalReferencesLinesContainer extends Component {
  toggleExternalReference(externalReference, onlyCreate = false) {
    const {
      stixCoreObjectOrStixCoreRelationshipId,
      stixCoreObjectOrStixCoreRelationshipReferences,
    } = this.props;
    const stixCoreObjectOrStixCoreRelationshipReferencesIds = map(
      (n) => n.node.id,
      stixCoreObjectOrStixCoreRelationshipReferences,
    );
    const alreadyAdded = stixCoreObjectOrStixCoreRelationshipReferencesIds.includes(
      externalReference.id,
    );
    if (alreadyAdded && !onlyCreate) {
      const existingExternalReference = head(
        filter(
          (n) => n.node.id === externalReference.id,
          stixCoreObjectOrStixCoreRelationshipReferences,
        ),
      );
      commitMutation({
        mutation: externalReferenceMutationRelationDelete,
        variables: {
          id: existingExternalReference.node.id,
          fromId: stixCoreObjectOrStixCoreRelationshipId,
          relationship_type: 'external-reference',
        },
        updater: (store) => {
          const entity = store.get(stixCoreObjectOrStixCoreRelationshipId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_externalReferences',
          );
          ConnectionHandler.deleteNode(conn, externalReference.id);
        },
      });
    } else if (!alreadyAdded) {
      const input = {
        fromId: stixCoreObjectOrStixCoreRelationshipId,
        relationship_type: 'external-reference',
      };
      commitMutation({
        mutation: externalReferenceLinesMutationRelationAdd,
        variables: { id: externalReference.id, input },
        updater: (store) => {
          const payload = store
            .getRootField('externalReferenceEdit')
            .getLinkedRecord('relationAdd', { input });
          const relationId = payload.getValue('id');
          const node = payload.getLinkedRecord('to');
          const relation = store.get(relationId);
          payload.setLinkedRecord(node, 'node');
          payload.setLinkedRecord(relation, 'relation');
          sharedUpdater(store, stixCoreObjectOrStixCoreRelationshipId, payload);
        },
      });
    }
  }

  render() {
    const {
      classes,
      data,
      stixCoreObjectOrStixCoreRelationshipReferences,
      open,
      search,
      paginationOptions,
    } = this.props;
    const stixCoreObjectOrStixCoreRelationshipReferencesIds = map(
      (n) => n.node.id,
      stixCoreObjectOrStixCoreRelationshipReferences,
    );
    const computeTextItem = (externalReferenceNode) => {
      const externalReference = externalReferenceNode.node;
      const externalReferenceId = externalReference.external_id
        ? `(${externalReference.external_id})`
        : '';
      return (
        <ListItemText
          primary={`${externalReference.source_name} ${externalReferenceId}`}
          secondary={truncate(
            externalReference.description !== null
              && externalReference.description.length > 0
              ? externalReference.description
              : externalReference.url,
            120,
          )}
        />
      );
    };
    return (
      <div>
        <List>
          {data.externalReferences.edges.map((externalReferenceNode) => {
            const externalReference = externalReferenceNode.node;
            const alreadyAdded = stixCoreObjectOrStixCoreRelationshipReferencesIds.includes(
              externalReference.id,
            );
            const isLinkedRef = isNotEmptyField(externalReference.fileId);
            if (isLinkedRef) {
              return (
                <ListItem
                  key={externalReference.id}
                  classes={{ root: classes.menuItem }}
                  divider={true}
                >
                  <ListItemIcon>
                    <DocumentScannerOutlined />
                  </ListItemIcon>
                  {computeTextItem(externalReferenceNode)}
                </ListItem>
              );
            }
            return (
              <ListItem
                key={externalReference.id}
                classes={{ root: classes.menuItem }}
                divider={true}
                button={true}
                onClick={this.toggleExternalReference.bind(
                  this,
                  externalReference,
                  false,
                )}
              >
                <ListItemIcon>
                  {alreadyAdded ? (
                    <CheckCircle classes={{ root: classes.icon }} />
                  ) : (
                    <ItemIcon type="External-Reference" />
                  )}
                </ListItemIcon>
                {computeTextItem(externalReferenceNode)}
              </ListItem>
            );
          })}
        </List>
        <ExternalReferenceCreation
          display={open}
          contextual={true}
          inputValue={search}
          paginationOptions={paginationOptions}
          onCreate={this.toggleExternalReference.bind(this)}
        />
      </div>
    );
  }
}

AddExternalReferencesLinesContainer.propTypes = {
  stixCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  stixCoreObjectOrStixCoreRelationshipReferences: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  open: PropTypes.bool,
  search: PropTypes.string,
};

export const addExternalReferencesLinesQuery = graphql`
  query AddExternalReferencesLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...AddExternalReferencesLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddExternalReferencesLines = createPaginationContainer(
  AddExternalReferencesLinesContainer,
  {
    data: graphql`
      fragment AddExternalReferencesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        externalReferences(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_externalReferences") {
          edges {
            node {
              id
              source_name
              description
              url
              external_id
              fileId
              connectors(onlyAlive: false) {
                id
                connector_type
                name
                active
                updated_at
              }
              importFiles(first: 500) {
                edges {
                  node {
                    id
                    lastModified
                    ...FileLine_file
                    metaData {
                      mimetype
                    }
                  }
                }
              }
            }
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
    getVariables(props, { count, cursor }) {
      return {
        count,
        cursor,
      };
    },
    query: addExternalReferencesLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(AddExternalReferencesLines);
