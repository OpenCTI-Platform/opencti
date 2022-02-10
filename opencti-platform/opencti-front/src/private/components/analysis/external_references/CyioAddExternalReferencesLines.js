/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, createFragmentContainer } from 'react-relay';
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
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
  ) {
    addReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId})
  }
`;

export const cyioExternalReferenceMutationRelationDelete = graphql`
  mutation CyioAddExternalReferencesLinesRelationDeleteMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
  ) {
    removeReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId})
    # # externalReferenceEdit(id: $id) {
    #   relationDelete(fromId: $fromId, relationship_type: $relationship_type) {
    #     id
    #   }
    # }
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
          toId: existingExternalReference.node.id,
          fromId: cyioCoreObjectOrCyioCoreRelationshipId,
          fieldName: 'external_reference',
        },
        updater: (store) => {
          const entity = store.get(cyioCoreObjectOrCyioCoreRelationshipId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_cyioExternalReferenceList',
          );
          ConnectionHandler.deleteNode(conn, externalReference.id);
        },
      });
    } else if (!alreadyAdded) {
      commitMutation({
        mutation: cyioExternalReferenceLinesMutationRelationAdd,
        variables: {
          toId: externalReference.id,
          fromId: cyioCoreObjectOrCyioCoreRelationshipId,
          fieldName: 'external_reference',
        },
        updater: (store) => {
          const payload = store;
          // .getRootField('externalReferenceEdit')
          // .getLinkedRecord('relationAdd', { input });
          const relationId = payload.getValue('toId');
          // const node = payload.getLinkedRecord('to');
          const relation = store.get(relationId);
          // payload.setLinkedRecord(node, 'node');
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
      cyioCoreObjectOrCyioCoreRelationshipReferences || []);
    return (
      <div>
        <List className={classes.list}>
          {data.cyioExternalReferenceList.edges.map((externalReferenceNode) => {
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
    $count: Int!
  ) {
    ...CyioAddExternalReferencesLines_data
    @arguments(count: $count)
  }
`;

const CyioAddExternalReferencesLines = createFragmentContainer(
  CyioAddExternalReferencesLinesContainer,
  {
    data: graphql`
      fragment CyioAddExternalReferencesLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 4 }
      ) {
        cyioExternalReferences(limit: $count) {
          edges {
            cursor
            node {
              id
              created
              modified
              source_name
              description
              url
              hashes {
                algorithm
                value
              }
              external_id
              reference_purpose
              media_type
            }
          }
          pageInfo {
            globalCount
            startCursor
            endCursor
            hasNextPage
            hasPreviousPage
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(CyioAddExternalReferencesLines);
