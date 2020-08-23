import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import Button from '@material-ui/core/Button';
import Avatar from '@material-ui/core/Avatar';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import { LinkOff } from '@material-ui/icons';
import { compose } from 'ramda';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation } from '../../../../relay/environment';
import AddNotes from './AddNotes';
import { noteMutationRelationDelete } from './AddNotesLines';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class StixCoreObjectNotesLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      removeNote: null,
      removing: false,
    };
  }

  handleOpenDialog(noteEdge) {
    const openedState = {
      displayDialog: true,
      removeNote: noteEdge,
    };
    this.setState(openedState);
  }

  handleCloseDialog() {
    const closedState = {
      displayDialog: false,
      removeNote: null,
    };
    this.setState(closedState);
  }

  handleRemoval() {
    this.setState({ removing: true });
    this.removeNote(this.state.removeNote);
  }

  removeNote(noteEdge) {
    commitMutation({
      mutation: noteMutationRelationDelete,
      variables: {
        id: noteEdge.node.id,
        fromId: this.props.entityId,
        relationship_type: 'external-reference',
      },
      updater: (store) => {
        const entity = store.get(this.props.entityId);
        const conn = ConnectionHandler.getConnection(
          entity,
          'Pagination_notes',
        );
        ConnectionHandler.deleteNode(conn, noteEdge.node.id);
      },
      onCompleted: () => {
        this.setState({ removing: false });
        this.handleCloseDialog();
      },
    });
  }

  render() {
    const {
      t, classes, entityId, data,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('External references')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddNotes
            entityId={entityId}
            entityNotes={
              data.stixCoreObject.notes.edges
            }
          />
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <List>
            {data.stixCoreObject.notes.edges.map(
              (noteEdge) => {
                const note = noteEdge.node;
                const noteId = note.external_id
                  ? `(${note.external_id})`
                  : '';
                if (note.url) {
                  return (
                    <ListItem
                      key={note.id}
                      dense={true}
                      divider={true}
                      button={true}
                      component="a"
                      href={note.url}
                    >
                      <ListItemIcon>
                        <Avatar classes={{ root: classes.avatar }}>
                          {note.source_name.substring(0, 1)}
                        </Avatar>
                      </ListItemIcon>
                      <ListItemText
                        primary={`${note.source_name} ${noteId}`}
                        secondary={truncate(
                          note.description !== null
                            && note.description.length > 0
                            ? note.description
                            : note.url,
                          90,
                        )}
                      />
                      <ListItemSecondaryAction>
                        <IconButton
                          aria-label="Remove"
                          onClick={this.handleOpenDialog.bind(
                            this,
                            noteEdge,
                          )}
                        >
                          <LinkOff />
                        </IconButton>
                      </ListItemSecondaryAction>
                    </ListItem>
                  );
                }
                return (
                  <ListItem
                    key={note.id}
                    dense={true}
                    divider={true}
                    button={false}
                  >
                    <ListItemIcon>
                      <Avatar classes={{ root: classes.avatar }}>
                        {note.source_name.substring(0, 1)}
                      </Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={`${note.source_name} ${noteId}`}
                      secondary={truncate(note.description, 120)}
                    />
                    <ListItemSecondaryAction>
                      <IconButton
                        aria-label="Remove"
                        onClick={this.handleOpenDialog.bind(
                          this,
                          noteEdge,
                        )}
                      >
                        <LinkOff />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                );
              },
            )}
          </List>
        </Paper>
        <Dialog
          open={this.state.displayDialog}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDialog.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to remove this external reference?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseDialog.bind(this)}
              color="primary"
              disabled={this.state.removing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleRemoval.bind(this)}
              color="primary"
              disabled={this.state.removing}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixCoreObjectNotesLinesContainer.propTypes = {
  id: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixCoreObjectNotesLinesQuery = graphql`
  query StixCoreObjectNotesLinesQuery(
    $count: Int!
    $id: String
  ) {
    ...StixCoreObjectNotesLines_data
      @arguments(count: $count, id: $id)
  }
`;

const StixCoreObjectNotesLines = createPaginationContainer(
  StixCoreObjectNotesLinesContainer,
  {
    data: graphql`
      fragment StixCoreObjectNotesLines_data on Query
        @argumentDefinitions(
          count: { type: "Int", defaultValue: 25 }
          id: { type: "String" }
        ) {
        stixCoreObject(id: $id) {
          id
          notes(first: $count)
            @connection(key: "Pagination_notes") {
            edges {
              node {
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
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCoreObject.notes;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count }, fragmentVariables) {
      return {
        count,
        id: fragmentVariables.id,
      };
    },
    query: stixCoreObjectNotesLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectNotesLines);
