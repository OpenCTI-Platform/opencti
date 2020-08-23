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
import Avatar from '@material-ui/core/Avatar';
import { CheckCircle } from '@material-ui/icons';
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
});

const noteLinesMutationRelationAdd = graphql`
  mutation AddNotesLinesRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    noteEdit(id: $id) {
      relationAdd(input: $input) {
        id
        to {
          ... on Note {
            id
            source_name
            description
            url
            hash
            external_id
          }
        }
      }
    }
  }
`;

export const noteMutationRelationDelete = graphql`
  mutation AddNotesLinesRelationDeleteMutation(
    $id: ID!
    $fromId: String!
    $relationship_type: String!
  ) {
    noteEdit(id: $id) {
      relationDelete(fromId: $fromId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

const sharedUpdater = (store, entityId, newEdge) => {
  const entity = store.get(entityId);
  const conn = ConnectionHandler.getConnection(
    entity,
    'Pagination_notes',
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddNotesLinesContainer extends Component {
  toggleNote(note) {
    const { entityId, entityNotes } = this.props;
    const entityNotesIds = map(
      (n) => n.node.id,
      entityNotes,
    );
    const alreadyAdded = entityNotesIds.includes(
      note.id,
    );

    if (alreadyAdded) {
      const existingNote = head(
        filter(
          (n) => n.node.id === note.id,
          entityNotes,
        ),
      );
      commitMutation({
        mutation: noteMutationRelationDelete,
        variables: {
          id: entityId,
          toId: existingNote.id,
          relationship_type: 'external-reference',
        },
        updater: (store) => {
          const entity = store.get(entityId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_notes',
          );
          ConnectionHandler.deleteNode(conn, note.id);
        },
      });
    } else {
      const input = {
        fromId: entityId,
        relationship_type: 'external-reference',
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
          const node = payload.getLinkedRecord('to');
          const relation = store.get(relationId);
          payload.setLinkedRecord(node, 'node');
          payload.setLinkedRecord(relation, 'relation');
          sharedUpdater(store, entityId, payload);
        },
      });
    }
  }

  render() {
    const { classes, data, entityNotes } = this.props;
    const entityNotesIds = map(
      (n) => n.node.id,
      entityNotes,
    );
    return (
      <List>
        {data.notes.edges.map((noteNode) => {
          const note = noteNode.node;
          const alreadyAdded = entityNotesIds.includes(
            note.id,
          );
          const noteId = note.external_id
            ? `(${note.external_id})`
            : '';
          return (
            <ListItem
              key={note.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleNote.bind(
                this,
                note,
              )}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <Avatar classes={{ root: classes.avatar }}>
                    {note.source_name.substring(0, 1)}
                  </Avatar>
                )}
              </ListItemIcon>
              <ListItemText
                primary={`${note.source_name} ${noteId}`}
                secondary={truncate(
                  note.description !== null
                    && note.description.length > 0
                    ? note.description
                    : note.url,
                  120,
                )}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddNotesLinesContainer.propTypes = {
  entityId: PropTypes.string,
  entityNotes: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const addNotesLinesQuery = graphql`
  query AddNotesLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
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
              source_name
              description
              url
              external_id
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

export default compose(
  inject18n,
  withStyles(styles),
)(AddNotesLines);
