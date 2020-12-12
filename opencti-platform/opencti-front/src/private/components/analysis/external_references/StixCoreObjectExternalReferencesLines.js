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
import AddExternalReferences from './AddExternalReferences';
import { externalReferenceMutationRelationDelete } from './AddExternalReferencesLines';
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

class StixCoreObjectExternalReferencesLinesContainer extends Component {
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
    };
    this.setState(openedState);
  }

  handleCloseDialog() {
    const closedState = {
      displayDialog: false,
      removeExternalReference: null,
    };
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
        fromId: this.props.stixCoreObjectId,
        relationship_type: 'external-reference',
      },
      updater: (store) => {
        const entity = store.get(this.props.stixCoreObjectId);
        const conn = ConnectionHandler.getConnection(
          entity,
          'Pagination_externalReferences',
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
      t, classes, stixCoreObjectId, data,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('External references')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddExternalReferences
            stixCoreObjectId={stixCoreObjectId}
            stixCoreObjectExternalReferences={
              data.stixCoreObject.externalReferences.edges
            }
          />
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {data.stixCoreObject.externalReferences.edges.length > 0 ? (
            <List>
              {data.stixCoreObject.externalReferences.edges.map(
                (externalReferenceEdge) => {
                  const externalReference = externalReferenceEdge.node;
                  const externalReferenceId = externalReference.external_id
                    ? `(${externalReference.external_id})`
                    : '';
                  let externalReferenceSecondary = '';
                  if (
                    externalReference.url
                    && externalReference.url.length > 0
                  ) {
                    externalReferenceSecondary = externalReference.url;
                  } else if (
                    externalReference.description
                    && externalReference.description.length > 0
                  ) {
                    externalReferenceSecondary = externalReference.description;
                  }
                  if (externalReference.url) {
                    return (
                      <ListItem
                        key={externalReference.id}
                        dense={true}
                        divider={true}
                        button={true}
                        component="a"
                        href={externalReference.url}
                        target="_blank"
                      >
                        <ListItemIcon>
                          <Avatar classes={{ root: classes.avatar }}>
                            {externalReference.source_name.substring(0, 1)}
                          </Avatar>
                        </ListItemIcon>
                        <ListItemText
                          primary={`${externalReference.source_name} ${externalReferenceId}`}
                          secondary={truncate(externalReferenceSecondary, 90)}
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
                },
              )}
            </List>
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No entities of this type has been found.')}
              </span>
            </div>
          )}
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

StixCoreObjectExternalReferencesLinesContainer.propTypes = {
  stixCoreObjectId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const stixCoreObjectExternalReferencesLinesQuery = graphql`
  query StixCoreObjectExternalReferencesLinesQuery($count: Int!, $id: String!) {
    ...StixCoreObjectExternalReferencesLines_data
      @arguments(count: $count, id: $id)
  }
`;

const StixCoreObjectExternalReferencesLines = createPaginationContainer(
  StixCoreObjectExternalReferencesLinesContainer,
  {
    data: graphql`
      fragment StixCoreObjectExternalReferencesLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "String!" }
      ) {
        stixCoreObject(id: $id) {
          id
          externalReferences(first: $count)
            @connection(key: "Pagination_externalReferences") {
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
      return props.data && props.data.stixCoreObject.externalReferences;
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
    query: stixCoreObjectExternalReferencesLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectExternalReferencesLines);
