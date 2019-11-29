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
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import { LinkOff } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation } from '../../../../relay/environment';
import AddExternalReferences from './AddExternalReferences';
import { externalReferenceMutationRelationDelete } from './AddExternalReferencesLines';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  list: {
    padding: 0,
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

class EntityExternalReferencesLinesContainer extends Component {

  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      removeExternalReference: null,
      removing: false,
    };
  }

  handleOpenDialog(externalReferenceEdge) {
    const openedState = {
      displayDialog: true,
      removeExternalReference: externalReferenceEdge,
    }
    this.setState(openedState);
  }

  handleCloseDialog() {
    const closedState = {
      displayDialog: false,
      removeExternalReference: null,
    }
    this.setState(closedState);
  }

  handleRemoval() {
    this.setState({ removing: true });
    this.removeExternalReference(this.state.removeExternalReference);
  }

  removeExternalReference(externalReferenceEdge) {
    commitMutation({
      mutation: externalReferenceMutationRelationDelete,
      variables: {
        id: externalReferenceEdge.node.id,
        relationId: externalReferenceEdge.relation.id,
      },
      updater: (store) => {
        const container = store.getRoot();
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_externalReferences',
          this.props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, externalReferenceEdge.node.id);
      },
      onCompleted: () => {
        this.setState({ removing: false });
        this.handleCloseDialog();
      },
    });
  }

  render() {
    const {
      t, classes, entityId, data, paginationOptions,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('External references')}
        </Typography>
        <AddExternalReferences
          entityId={entityId}
          entityExternalReferences={data.externalReferences.edges}
          entityPaginationOptions={paginationOptions}
        />
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <List classes={{ root: classes.list }}>
            {data.externalReferences.edges.map((externalReferenceEdge) => {
              const externalReference = externalReferenceEdge.node;
              const externalReferenceId = externalReference.external_id
                ? `(${externalReference.external_id})`
                : '';
              if (externalReference.url) {
                return (
                  <ListItem
                    key={externalReference.id}
                    dense={true}
                    divider={true}
                    button={true}
                    component="a"
                    href={externalReference.url}
                  >
                    <ListItemIcon>
                      <Avatar classes={{ root: classes.avatar }}>
                        {externalReference.source_name.substring(0, 1)}
                      </Avatar>
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
                    <ListItemSecondaryAction>
                      <IconButton
                        aria-label="Remove"
                        onClick={this.handleOpenDialog.bind(
                          this,
                          externalReferenceEdge,
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
                  key={externalReference.id}
                  dense={true}
                  divider={true}
                  button={false}
                >
                  <ListItemIcon>
                    <Avatar classes={{ root: classes.avatar }}>
                      {externalReference.source_name.substring(0, 1)}
                    </Avatar>
                  </ListItemIcon>
                  <ListItemText
                    primary={`${externalReference.source_name} ${externalReferenceId}`}
                    secondary={truncate(externalReference.description, 120)}
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      aria-label="Remove"
                      onClick={this.handleOpenDialog.bind(
                        this,
                        externalReferenceEdge,
                      )}
                    >
                      <LinkOff />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>
        </Paper>
        <Dialog
          open={this.state.displayDialog}
          keepMounted={true}
          onClose={this.handleCloseDialog.bind(this)}
        >
          <DialogTitle>{t('Confirmation required')}</DialogTitle>
          <DialogContent>
            { this.state.removeExternalReference != null &&
              <DialogContentText>
                {t('Removing')} '{truncate(this.state.removeExternalReference.node.source_name, 30)}'.
              </DialogContentText>
            }
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
              {t('No')}
            </Button>
            <Button
              onClick={this.handleRemoval.bind(this)}
              color="primary"
              disabled={this.state.removing}
            >
              {t('Yes')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

EntityExternalReferencesLinesContainer.propTypes = {
  entityId: PropTypes.string,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const entityExternalReferencesLinesQuery = graphql`
  query EntityExternalReferencesLinesQuery(
    $objectId: String!
    $count: Int!
    $cursor: ID
    $orderBy: ExternalReferencesOrdering
    $orderMode: OrderingMode
  ) {
    ...EntityExternalReferencesLines_data
      @arguments(
        objectId: $objectId
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const EntityExternalReferencesLines = createPaginationContainer(
  EntityExternalReferencesLinesContainer,
  {
    data: graphql`
      fragment EntityExternalReferencesLines_data on Query
        @argumentDefinitions(
          objectId: { type: "String!" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: {
            type: "ExternalReferencesOrdering"
            defaultValue: "source_name"
          }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        externalReferences(
          objectId: $objectId
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_externalReferences") {
          edges {
            node {
              id
              source_name
              description
              url
              hash
              external_id
            }
            relation {
              id
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
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: entityExternalReferencesLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(EntityExternalReferencesLines);
