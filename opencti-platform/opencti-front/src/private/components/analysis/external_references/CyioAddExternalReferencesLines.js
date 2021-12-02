import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import {
  map, filter, head, compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Checkbox from '@material-ui/core/Checkbox';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
  list: {
    marginLeft: '24px',
    marginRight: '24px',
  },
});

export const cyioExternalReferenceLinesMutationRelationAdd = graphql`
  mutation CyioAddExternalReferencesLinesRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
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
            importFiles(first: 1000) {
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

export const cyioExternalReferenceMutationRelationDelete = graphql`
  mutation CyioAddExternalReferencesLinesRelationDeleteMutation(
    $id: ID!
    $fromId: String!
    $relationship_type: String!
  ) {
    externalReferenceEdit(id: $id) {
      relationDelete(fromId: $fromId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

const sharedUpdater = (store, cyioCoreObjectId, newEdge) => {
  const entity = store.get(cyioCoreObjectId);
  const conn = ConnectionHandler.getConnection(
    entity,
    'Pagination_externalReferences',
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class CyioAddExternalReferencesLinesContainer extends Component {
  toggleExternalReference(externalReference, onlyCreate = false) {
    const {
      cyioCoreObjectOrCyioCoreRelationshipId,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
    } = this.props;
    const cyioCoreObjectOrCyioCoreRelationshipReferencesIds = map(
      (n) => n.node.id,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
    );
    const alreadyAdded = cyioCoreObjectOrCyioCoreRelationshipReferencesIds.includes(
      externalReference.id,
    );
    if (alreadyAdded && !onlyCreate) {
      const existingExternalReference = head(
        filter(
          (n) => n.node.id === externalReference.id,
          cyioCoreObjectOrCyioCoreRelationshipReferences,
        ),
      );
      commitMutation({
        mutation: cyioExternalReferenceMutationRelationDelete,
        variables: {
          id: existingExternalReference.node.id,
          fromId: cyioCoreObjectOrCyioCoreRelationshipId,
          relationship_type: 'external-reference',
        },
        updater: (store) => {
          const entity = store.get(cyioCoreObjectOrCyioCoreRelationshipId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_externalReferences',
          );
          ConnectionHandler.deleteNode(conn, externalReference.id);
        },
      });
    } else if (!alreadyAdded) {
      const input = {
        fromId: cyioCoreObjectOrCyioCoreRelationshipId,
        relationship_type: 'external-reference',
      };
      commitMutation({
        mutation: this.cyioExternalReferenceLinesMutationRelationAdd,
        variables: {
          id: externalReference.id,
          input,
        },
        updater: (store) => {
          const payload = store
            .getRootField('externalReferenceEdit')
            .getLinkedRecord('relationAdd', { input });
          const relationId = payload.getValue('id');
          const node = payload.getLinkedRecord('to');
          const relation = store.get(relationId);
          payload.setLinkedRecord(node, 'node');
          payload.setLinkedRecord(relation, 'relation');
          sharedUpdater(store, cyioCoreObjectOrCyioCoreRelationshipId, payload);
        },
      });
    }
  }

  render() {
    const {
      classes,
      data,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
    } = this.props;
    const cyioCoreObjectOrCyioCoreRelationshipReferencesIds = map(
      (n) => n.node.id,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
    );
    return (
      <div>
        <List className={classes.list}>
          {data.externalReferences.edges.map((externalReferenceNode) => {
            const externalReference = externalReferenceNode.node;
            const alreadyAdded = cyioCoreObjectOrCyioCoreRelationshipReferencesIds.includes(
              externalReference.id,
            );
            const externalReferenceId = externalReference.external_id
              ? `(${externalReference.external_id})`
              : '';
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
                    <Checkbox classes={{ root: classes.icon }} />
                  ) : (
                    <Checkbox classes={{ root: classes.icon }} />
                  )}
                </ListItemIcon>
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
              </ListItem>
            );
          })}
        </List>
        {/* <CyioExternalReferenceCreation
          display={open}
          contextual={true}
          inputValue={search}
          paginationOptions={paginationOptions}
          onCreate={this.toggleExternalReference.bind(this)}
        /> */}
      </div>
    );
  }
}

CyioAddExternalReferencesLinesContainer.propTypes = {
  cyioCoreObjectOrCyioCoreRelationshipId: PropTypes.string,
  cyioCoreObjectOrCyioCoreRelationshipReferences: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  open: PropTypes.bool,
  search: PropTypes.string,
};

export const cyioAddExternalReferencesLinesQuery = graphql`
  query CyioAddExternalReferencesLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...CyioAddExternalReferencesLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const CyioAddExternalReferencesLines = createPaginationContainer(
  CyioAddExternalReferencesLinesContainer,
  {
    data: graphql`
      fragment CyioAddExternalReferencesLines_data on Query
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
              connectors(onlyAlive: false) {
                id
                connector_type
                name
                active
                updated_at
              }
              importFiles(first: 1000) {
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
    query: cyioAddExternalReferencesLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(CyioAddExternalReferencesLines);
