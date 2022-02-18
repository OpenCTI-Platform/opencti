/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, createFragmentContainer } from 'react-relay';
import {
  map, filter, head, compose, pathOr,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import Checkbox from '@material-ui/core/Checkbox';
import ListItemText from '@material-ui/core/ListItemText';
import { CheckCircle, WorkOutline } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import ItemMarking from '../../../../components/ItemMarking';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

export const cyioNoteLinesMutationRelationAdd = graphql`
  mutation CyioAddNotesLinesRelationAddMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $to_type: String
    $from_type: String
  ) {
    addReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId, to_type: $to_type, from_type: $from_type})
  }
`;

export const cyioNoteMutationRelationDelete = graphql`
  mutation CyioAddNotesLinesRelationDeleteMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $to_type: String
    $from_type: String
  ) {
    removeReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId, to_type: $to_type, from_type: $from_type})
  }
`;

const sharedUpdater = (store, entityId, newEdge) => {
  const entity = store.get(entityId);
  const conn = ConnectionHandler.getConnection(entity, 'Pagination_notes');
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class CyioAddNotesLinesContainer extends Component {
  toggleNote(note) {
    const {
      cyioCoreObjectOrStixCoreRelationshipId,
      cyioCoreObjectOrStixCoreRelationshipNotes,
    } = this.props;
    const entityNotesIds = map(
      (n) => n.node.id,
      cyioCoreObjectOrStixCoreRelationshipNotes,
    );
    const alreadyAdded = entityNotesIds.includes(note.id);
    if (alreadyAdded) {
      const existingNote = head(
        filter(
          (n) => n.node.id === note.id,
          cyioCoreObjectOrStixCoreRelationshipNotes,
        ),
      );
      commitMutation({
        mutation: cyioNoteMutationRelationDelete,
        variables: {
          toId: existingNote.node.id,
          fromId: cyioCoreObjectOrStixCoreRelationshipId,
          fieldName: 'notes',
          to_type: note.__typename,
          from_type: note.entity_type,
        },
        updater: (store) => {
          const entity = store.get(cyioCoreObjectOrStixCoreRelationshipId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_notes',
          );
          ConnectionHandler.deleteNode(conn, note.id);
        },
      });
    } else {
      const input = {
        toId: cyioCoreObjectOrStixCoreRelationshipId,
        relationship_type: 'object',
      };
      commitMutation({
        mutation: cyioNoteLinesMutationRelationAdd,
        variables: {
          toId: note.id,
          fromId: cyioCoreObjectOrStixCoreRelationshipId,
          fieldName: 'notes',
          to_type: note.__typename,
          from_type: note.entity_type,
        },
        updater: (store) => {
          const payload = store
            .getRootField('noteEdit')
            .getLinkedRecord('relationAdd', { input });
          const relationId = payload.getValue('id');
          const node = payload.getLinkedRecord('from');
          const relation = store.get(relationId);
          payload.setLinkedRecord(node, 'node');
          payload.setLinkedRecord(relation, 'relation');
          sharedUpdater(store, cyioCoreObjectOrStixCoreRelationshipId, payload);
        },
      });
    }
  }

  render() {
    const { classes, data, cyioCoreObjectOrStixCoreRelationshipNotes } = this.props;
    const entityNotesIds = map(
      (n) => n.node.id,
      cyioCoreObjectOrStixCoreRelationshipNotes,
    );
    console.log('cyioAddNotesLines', data);
    return (
      <List>
        {data.cyioNotes.edges.map((noteNode) => {
          const note = noteNode.node;
          const alreadyAdded = entityNotesIds.includes(note.id);
          const noteId = note.external_id ? `(${note.external_id})` : '';
          return (
            <ListItem
              key={note.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleNote.bind(this, note)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <Checkbox classes={{ root: classes.icon }} />
                ) : (
                  <Checkbox classes={{ root: classes.icon }} />
                )}
              </ListItemIcon>
              <ListItemText
                primary={`${note.abstract} ${noteId}`}
                secondary={truncate(note.content, 120)}
              />
              {/* <div style={{ marginRight: 50 }}>
                {pathOr([], ['objectMarking', 'edges'], note).length > 0
                  && map(
                    (markingDefinition) => (
                      <ItemMarking
                        key={markingDefinition.node.id}
                        label={markingDefinition.node.definition}
                        variant="inList"
                      />
                    ),
                    note.objectMarking.edges,
                  )}
              </div> */}
            </ListItem>
          );
        })}
      </List>
    );
  }
}

CyioAddNotesLinesContainer.propTypes = {
  cyioCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  cyioCoreObjectOrStixCoreRelationshipNotes: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const cyioAddNotesLinesQuery = graphql`
  query CyioAddNotesLinesQuery($count: Int!) {
    ...CyioAddNotesLines_data
      @arguments(count: $count)
  }
`;

const CyioAddNotesLines = createFragmentContainer(
  CyioAddNotesLinesContainer,
  {
    data: graphql`
      fragment CyioAddNotesLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
      ) {
        cyioNotes(limit: $count) {
          edges {
            node {
              __typename
              id
              created
              modified
              entity_type
              labels {
                __typename
                id
                name
                color
                entity_type
                description
              }
              abstract
              content
              authors
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(CyioAddNotesLines);
