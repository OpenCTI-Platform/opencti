import { CheckCircle, WorkOutline } from '@mui/icons-material';
import ListItemButton from '@mui/material/ListItemButton';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Component } from 'react';
import { createPaginationContainer, graphql } from 'react-relay';
import inject18n from '../../../../components/i18n';
import ItemMarkings from '../../../../components/ItemMarkings';
import { commitMutation } from '../../../../relay/environment';
import { deleteNode, insertNode } from '../../../../utils/store';
import { truncate } from '../../../../utils/String';

const styles = () => ({
  avatar: {
    width: 24,
    height: 24,
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
            { input },
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
      <TableContainer>
        <Table
          sx={{
            '& .MuiTableRow-root:first-of-type td': {
              borderTop: 'none',
            },
          }}
        >
          <TableBody>
            {data.notes.edges.map((noteNode) => {
              const note = noteNode.node;
              const alreadyAdded = entityNotesIds.includes(note.id);
              const noteId = note.external_id ? `(${note.external_id})` : '';
              return (
                <TableRow
                  key={note.id}
                  component={ListItemButton}
                  classes={{ root: classes.menuItem }}
                  onClick={this.toggleNote.bind(this, note)}
                >
                  <TableCell sx={{ width: 48, paddingY: 1, paddingX: 2 }}>
                    {alreadyAdded ? (
                      <CheckCircle
                        color="primary"
                        sx={{ marginTop: 0.5 }}
                      />
                    ) : (
                      <WorkOutline sx={{ marginTop: 0.5 }} />
                    )}
                  </TableCell>
                  <TableCell sx={{ paddingY: 1, paddingX: 2 }}>
                    <Typography variant="body1" sx={{ fontWeight: 600 }}>
                      {`${note.attribute_abstract} ${noteId}`}
                    </Typography>
                    <Typography variant="body1">
                      {truncate(note.content, 120)}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ paddingY: 1, paddingX: 2, whiteSpace: 'nowrap' }}>
                    {note.createdBy?.name ?? '-'}
                  </TableCell>
                  <TableCell sx={{ paddingY: 1, paddingX: 2 }}>
                    <ItemMarkings
                      variant="inList"
                      markingDefinitions={note.objectMarking ?? []}
                    />
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>
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
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
              createdBy {
                name
                id
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
