import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createPaginationContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircle, WorkOutline } from '@mui/icons-material';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import ItemMarkings from '../../../../components/ItemMarkings';
import { deleteNode, insertNode } from '../../../../utils/store';

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
    $input: StixRefRelationshipAddInput!
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

class AddNotesLinesContainer extends Component {
  toggleNote(note) {
    const {
      stixCoreObjectOrStixCoreRelationshipId,
      stixCoreObjectOrStixCoreRelationshipNotes,
      paginationOptions,
    } = this.props;
    const entityNotesIds = R.map(
      (n) => n.node.id,
      stixCoreObjectOrStixCoreRelationshipNotes,
    );
    const alreadyAdded = entityNotesIds.includes(note.id);
    if (alreadyAdded) {
      const existingNote = R.head(
        R.filter(
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
          deleteNode(
            store,
            'Pagination_notes',
            paginationOptions,
            existingNote.node.id,
          );
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
          insertNode(
            store,
            'Pagination_notes',
            paginationOptions,
            'noteEdit',
            null,
            'relationAdd',
            input,
            'from',
          );
        },
      });
    }
  }

  render() {
    const { classes, data, stixCoreObjectOrStixCoreRelationshipNotes } = this.props;
    const entityNotesIds = R.map(
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
                {R.pathOr('', ['createdBy', 'name'], note)}
              </div>
              <div style={{ marginRight: 50 }}>
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={data.objectMarking ?? []}
                />
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
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const addNotesLinesQuery = graphql`
  query AddNotesLinesQuery($search: String, $count: Int, $cursor: ID) {
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
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
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

export default R.compose(inject18n, withStyles(styles))(AddNotesLines);
