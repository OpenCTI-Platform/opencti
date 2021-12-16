import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  map, filter, head, compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import Dialog from '@material-ui/core/Dialog';
import Button from '@material-ui/core/Button';
import InputAdornment from '@material-ui/core/InputAdornment';
import CardActions from '@material-ui/core/CardActions';
import TextField from '@material-ui/core/TextField';
import Collapse from '@material-ui/core/Collapse';
import Divider from '@material-ui/core/Divider';
import DialogTitle from '@material-ui/core/DialogTitle';
import { ConnectionHandler } from 'relay-runtime';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { Add } from '@material-ui/icons';
import Skeleton from '@material-ui/lab/Skeleton';
import { QueryRenderer as QR } from 'react-relay';
import QueryRendererDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import CyioExternalReferenceCreation from './CyioExternalReferenceCreation';
import CyioAddExternalReferencesLines, {
  cyioAddExternalReferencesLinesQuery,
  cyioExternalReferenceMutationRelationDelete,
  cyioExternalReferenceLinesMutationRelationAdd,
} from './CyioAddExternalReferencesLines';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  dialog: {
    backgroundColor: 'red',
    overflow: 'hidden',
    height: '50vh',
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
    marginLeft: 15,
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    color: theme.palette.navAlt.backgroundHeaderText,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: 0,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  avatar: {
    width: 24,
    height: 24,
  },
  collapse: {
    width: '70%',
    maxHeight: '344px',
    overflowY: 'scroll',
    background: theme.palette.background.paper,
  },
  dialogMain: {
    padding: '24px',
    background: theme.palette.background.paper,
  },
});

const sharedUpdater = (store, cyioCoreObjectId, newEdge) => {
  const entity = store.get(cyioCoreObjectId);
  const conn = ConnectionHandler.getConnection(
    entity,
    'Pagination_externalReferences',
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class CyioAddExternalReferences extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      search: '',
      expanded: true,
    };
  }

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
        mutation: cyioExternalReferenceLinesMutationRelationAdd,
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

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false, search: '' });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  handleClick() {
    this.setState({ expanded: !this.state.expanded });
  }

  render() {
    const {
      t,
      classes,
      cyioCoreObjectOrCyioCoreRelationshipId,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
    } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <div>
        <IconButton
          color="secondary"
          aria-label="Add"
          onClick={this.handleOpen.bind(this)}
          classes={{ root: classes.createButton }}
        >
          <Add fontSize="small" />
        </IconButton>
      <div classes={{ root: classes.dialogRoot }}>
      <Dialog
        maxWidth='md'
        open={this.state.open}
        onClose={this.handleClose.bind(this)}
        timeout="auto"
        unmountOnExit
        PaperProps={{
          style: {
            backgroundColor: 'transparent',
            boxShadow: 'none',
            borderRadius: '0px',
            overflowY: 'hidden',
          },
        }}
      >
          <div className={ classes.dialogMain }>
            <DialogTitle style={{ padding: 10 }}>{t('Add External References')}</DialogTitle>
            {/* <CardHeader title="Add External Refrences"/> */}
              <CardActions sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <TextField style={{ width: 495 }} InputProps={{
                  endAdornment: (
                    <InputAdornment position="end" >
                      <CyioExternalReferenceCreation
                        display={this.state.open}
                        contextual={true}
                        inputValue={this.state.search}
                        paginationOptions={paginationOptions}
                        onCreate={this.toggleExternalReference.bind(this)}
                      />
                    </InputAdornment>
                  ),
                }} />
                <div style={{ float: 'right', marginLeft: '40px' }}>
                  <Button style={{ marginLeft: '10px', marginRight: '10px' }} onClick={this.handleClose.bind(this)} variant="outlined" >{t('Cancel')}</Button>
                  <Button variant="contained" color="primary">{t('Add')}</Button>
                </div>
                <Divider light={true} />
              </CardActions>
          </div>
          <Collapse sx={{ maxWidth: '500px', borderRadius: 0 }} in={this.state.expanded} timeout="auto" unmountOnExit>
            <div className={ classes.collapse }>
                <QR
                  environment={QueryRendererDarkLight}
                  query={cyioAddExternalReferencesLinesQuery}
                  variables={{
                    search: this.state.search,
                    count: 20,
                  }}
                  render={({ props }) => {
                    if (false) {
                      return (
                        <CyioAddExternalReferencesLines
                          cyioCoreObjectOrCyioCoreRelationshipId={
                            cyioCoreObjectOrCyioCoreRelationshipId
                          }
                          cyioCoreObjectOrCyioCoreRelationshipReferences={
                            cyioCoreObjectOrCyioCoreRelationshipReferences
                          }
                          data={props}
                          paginationOptions={paginationOptions}
                          open={this.state.open}
                          search={this.state.search}
                        />
                      );
                    }
                    return (
                      <List>
                        {Array.from(Array(20), (e, i) => (
                          <ListItem key={i} divider={true} button={false}>
                            <ListItemIcon>
                              <Skeleton
                                animation="wave"
                                variant="circle"
                                width={30}
                                height={30}
                              />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <Skeleton
                                  animation="wave"
                                  variant="rect"
                                  width="90%"
                                  height={15}
                                  style={{ marginBottom: 10 }}
                                />
                              }
                              secondary={
                                <Skeleton
                                  animation="wave"
                                  variant="rect"
                                  width="90%"
                                  height={15}
                                />
                              }
                            />
                          </ListItem>
                        ))}
                      </List>
                    );
                  }}
                />
              </div>
            </Collapse>
          </Dialog>
        </div>
      </div>
    );
  }
}

CyioAddExternalReferences.propTypes = {
  cyioCoreObjectOrCyioCoreRelationshipId: PropTypes.string,
  cyioCoreObjectOrCyioCoreRelationshipReferences: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(CyioAddExternalReferences);
