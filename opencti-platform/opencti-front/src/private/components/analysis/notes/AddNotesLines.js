import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, filter, head, compose, pathOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircle, WorkOutline } from '@mui/icons-material';
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

export const noteLinesMutationRelationAdd = graphql`
  mutation AddNotesLinesRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    noteEdit(id: $id) {
      relationAdd(input: $input) {
        id
        from {
          ...StixCoreObjectOrStixCoreRelationshipNoteCard_node
        }
      }
    }
  }
`;

export const noteMutationRelationDelete = graphql`
  mutation AddNotesLinesRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    noteEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

const sharedUpdater = (store, entityId, newEdge) => {
  const entity = store.get(entityId);
  const conn = ConnectionHandler.getConnection(entity, 'Pagination_notes');
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddNotesLinesContainer extends Component {
  toggleNote(note) {
    const {
      stixCoreObjectOrStixCoreRelationshipId,
      stixCoreObjectOrStixCoreRelationshipNotes,
    } = this.props;
    const entityNotesIds = map(
      (n) => n.node.id,
      stixCoreObjectOrStixCoreRelationshipNotes,
    );
    const alreadyAdded = entityNotesIds.includes(note.id);
    if (alreadyAdded) {
      const existingNote = head(
        filter(
          (n) => n.node.id === note.id,
          stixCoreObjectOrStixCoreRelationshipNotes,
        ),
      );
      commitMutation({
        mutation: noteMutationRelationDelete,
        variables: {
          id: existingNote.node.id,
          toId: stixCoreObjectOrStixCoreRelationshipId,
          relationship_type: 'object',
        },
        updater: (store) => {
          const entity = store.get(stixCoreObjectOrStixCoreRelationshipId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_notes',
          );
          ConnectionHandler.deleteNode(conn, note.id);
        },
      });
    } else {
      const input = {
        toId: stixCoreObjectOrStixCoreRelationshipId,
        relationship_type: 'object',
      };
      commitMutation({
        mutation: noteLinesMutationRelationAdd,
        variables: {
          id: note.id,
          input,
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
          sharedUpdater(store, stixCoreObjectOrStixCoreRelationshipId, payload);
        },
      });
    }
  }

  render() {
    const { classes, data, stixCoreObjectOrStixCoreRelationshipNotes } = this.props;
    const entityNotesIds = map(
      (n) => n.node.id,
      stixCoreObjectOrStixCoreRelationshipNotes,
    );
    return (
      <List>
        {data.notes.edges.map((noteNode) => {
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
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <WorkOutline />
                )}
              </ListItemIcon>
              <ListItemText
                primary={`${note.attribute_abstract} ${noteId}`}
                secondary={truncate(note.content, 120)}
              />
              <div style={{ marginRight: 50 }}>
                {pathOr('', ['createdBy', 'name'], note)}
              </div>
              <div style={{ marginRight: 50 }}>
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
              </div>
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddNotesLinesContainer.propTypes = {
  stixCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  stixCoreObjectOrStixCoreRelationshipNotes: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const addNotesLinesQuery = graphql`
  query AddNotesLinesQuery($search: String, $count: Int!, $cursor: ID) {
    ...AddNotesLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddNotesLines = createPaginationContainer(
  AddNotesLinesContainer,
  {
    data: graphql`
      fragment AddNotesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        notes(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_notes") {
          edges {
            node {
              id
              attribute_abstract
              content
              objectMarking {
                edges {
                  node {
                    id
                    definition
                    x_opencti_color
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
      return props.data && props.data.notes;
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
    query: addNotesLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(AddNotesLines);
