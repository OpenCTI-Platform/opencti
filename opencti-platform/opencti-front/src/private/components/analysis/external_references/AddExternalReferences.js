import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  map, filter, head, compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import Dialog from '@material-ui/core/Dialog';
import Button from '@material-ui/core/Button';
import InputAdornment from '@material-ui/core/InputAdornment';
import Card from '@material-ui/core/Card';
import CardContent from '@material-ui/core/CardContent';
import CardActions from '@material-ui/core/CardActions';
import TextField from '@material-ui/core/TextField';
import CardHeader from '@material-ui/core/CardHeader';
import Checkbox from '@material-ui/core/Checkbox';
import Collapse from '@material-ui/core/Collapse';
import DialogTitle from '@material-ui/core/DialogTitle';
import { ConnectionHandler } from 'relay-runtime';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import { Add, Close } from '@material-ui/icons';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer, commitMutation } from '../../../../relay/environment';
import ExternalReferenceCreation from './ExternalReferenceCreation';
import AddExternalReferencesLines, {
  addExternalReferencesLinesQuery,
  externalReferenceMutationRelationDelete,
  externalReferenceLinesMutationRelationAdd,
} from './AddExternalReferencesLines';
import '../../../../resources/css/customScrollbar.css';

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
    overflow: 'hidden',
    height: '50vh',
  },
  dialogRoot: {
    backgroundColor: 'transparent !important',
    borderRadius: '0 !important',
    boxShadow: 'none !important',
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
});

const sharedUpdater = (store, stixCoreObjectId, newEdge) => {
  const entity = store.get(stixCoreObjectId);
  const conn = ConnectionHandler.getConnection(
    entity,
    'Pagination_externalReferences',
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddExternalReferences extends Component {
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
      stixCoreObjectOrStixCoreRelationshipId,
      stixCoreObjectOrStixCoreRelationshipReferences,
    } = this.props;
    const stixCoreObjectOrStixCoreRelationshipReferencesIds = map(
      (n) => n.node.id,
      stixCoreObjectOrStixCoreRelationshipReferences,
    );
    const alreadyAdded = stixCoreObjectOrStixCoreRelationshipReferencesIds.includes(
      externalReference.id,
    );
    if (alreadyAdded && !onlyCreate) {
      const existingExternalReference = head(
        filter(
          (n) => n.node.id === externalReference.id,
          stixCoreObjectOrStixCoreRelationshipReferences,
        ),
      );
      commitMutation({
        mutation: externalReferenceMutationRelationDelete,
        variables: {
          id: existingExternalReference.node.id,
          fromId: stixCoreObjectOrStixCoreRelationshipId,
          relationship_type: 'external-reference',
        },
        updater: (store) => {
          const entity = store.get(stixCoreObjectOrStixCoreRelationshipId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_externalReferences',
          );
          ConnectionHandler.deleteNode(conn, externalReference.id);
        },
      });
    } else if (!alreadyAdded) {
      const input = {
        fromId: stixCoreObjectOrStixCoreRelationshipId,
        relationship_type: 'external-reference',
      };
      commitMutation({
        mutation: externalReferenceLinesMutationRelationAdd,
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
          sharedUpdater(store, stixCoreObjectOrStixCoreRelationshipId, payload);
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
      stixCoreObjectOrStixCoreRelationshipId,
      stixCoreObjectOrStixCoreRelationshipReferences,
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
      <div>
        <Dialog maxWidth='md' classes={{ root: classes.dialogRoot }} open={this.state.open} onClose={this.handleClose.bind(this)} timeout="auto" unmountOnExit>
          <div style={{ padding: '24px' }}>
            <DialogTitle style={{ padding: 10 }}>{t('Add External References')}</DialogTitle>
            {/* <CardHeader title="Add External Refrences"/> */}
              <CardActions sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <TextField style={{ width: 495 }} InputProps = {{
                  endAdornment: (
                    <InputAdornment position = "end" >
                      <ExternalReferenceCreation
                        display={this.state.open}
                        contextual={true}
                        inputValue={this.state.search}
                        paginationOptions={paginationOptions}
                        onCreate={this.toggleExternalReference.bind(this)}
                      />
                    </InputAdornment>
                  ),
                }}/>
                <Button style={{ marginLeft: '10px', marginRight: '10px' }} onClick={this.handleClose.bind(this)} variant="outlined" >{t('Cancel')}</Button>
                <Button variant="contained" color="primary">{t('Add')}</Button>
              </CardActions>
          </div>
          <Collapse sx={{ maxWidth: '500px', borderRadius: 0 }} style={{ backgroundColor: 'transparent' }} in={this.state.expanded} timeout="auto" unmountOnExit>
            <div>
              <QueryRenderer
                query={addExternalReferencesLinesQuery}
                variables={{
                  search: this.state.search,
                  count: 20,
                }}
                render={({ props }) => {
                  if (props) {
                    return (
                      <AddExternalReferencesLines
                        stixCoreObjectOrStixCoreRelationshipId={
                          stixCoreObjectOrStixCoreRelationshipId
                        }
                        stixCoreObjectOrStixCoreRelationshipReferences={
                          stixCoreObjectOrStixCoreRelationshipReferences
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
            {/* <CardContent fontSize="large" style={{ display: 'flex' }}>
              <Checkbox />
              <Typography style={{ marginLeft: '20px' }} >
                Heat oil in a paella pan or a large.
                <Typography variant="subtitle2">
                    https://Loremipsumfasdfasdfasdolorsit.com
                </Typography>
              </Typography>
            </CardContent>
            <CardContent fontSize="large" style={{ display: 'flex' }}>
              <Checkbox />
              <Typography style={{ marginLeft: '20px' }} >
                Heat oil in a paella pan or a large.
                <Typography variant="subtitle2">
                  https://Loremipsumdfasdfewfsdfsafolorsit.com
                </Typography>
              </Typography>
            </CardContent>
            <CardContent fontSize="large" style={{ display: 'flex' }}>
              <Checkbox />
              <Typography style={{ marginLeft: '20px' }} >
                Heat oil in a paella pan or a large.
                <Typography variant="subtitle2">
                    https://Loremipsumdfsfawefggdsgdsfgolorsit.com
                </Typography>
              </Typography>
            </CardContent> */}
            </div>
          </Collapse>
        </Dialog>
      </div>
      {/* <Dialog
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          fullWidth={true}
        >
        <DialogTitle>{t('Add External References')}</DialogTitle>
        <Card sx={{
          borderRadius: 0,
          maxWidth: 750,
          height: 140,
          textAlign: 'left',
          overflow: 'visible',
          position: 'relative',
        }}>
          <CardActions sx={{ display: 'flex', justifyContent: 'space-between', padding: '20px' }}>
            <TextField
              style={{ width: 495 }}
              InputProps = {{
                endAdornment: (
                  <InputAdornment position = "end" >
                      <ExternalReferenceCreation
                        display={this.state.open}
                        contextual={true}
                        inputValue={this.state.search}
                        paginationOptions={paginationOptions}
                        onCreate={this.toggleExternalReference.bind(this)}
                      />
                  </InputAdornment>
                ),
              }}/>
            <Button
              onClick={this.handleClose.bind(this)}
              style={{ marginLeft: '10px', marginRight: '10px', fontSize: '14px' }}
              variant="outlined" >
              {t('Cancel')}
            </Button>
            <Button variant="contained" color="primary">{t('Add')}</Button>
          </CardActions>
          <Collapse
            sx={{
              border: '1px solid black',
              width: 500,
              position: 'absolute',
              top: '140px',
              left: '0',
              zIndex: '20',
              background: 'white',
            }}
            in={this.state.expanded}
            timeout="auto"
            unmountOnExit
          >
            <QueryRenderer
              query={addExternalReferencesLinesQuery}
              variables={{
                search: this.state.search,
                count: 20,
              }}
              render={({ props }) => {
                if (props) {
                  return (
                    <AddExternalReferencesLines
                      stixCoreObjectOrStixCoreRelationshipId={
                        stixCoreObjectOrStixCoreRelationshipId
                      }
                      stixCoreObjectOrStixCoreRelationshipReferences={
                        stixCoreObjectOrStixCoreRelationshipReferences
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
            /> */}
            {/* <CardContent fontSize="large" style={{ display: 'flex' }}>
                <Checkbox />
                <Typography style={{ marginLeft: '20px' }} >
                    Heat oil in a paella pan or a large.
                    <Typography variant="subtitle2">
                        https://Loremipsumdolorsit.com
                    </Typography>
                </Typography>
            </CardContent>
            <CardContent fontSize="large" style={{ display: 'flex' }}>
              <Checkbox />
              <Typography style={{ marginLeft: '20px' }} >
                  Heat oil in a paella pan or a large.
                  <Typography variant="subtitle2">
                      https://Loremipsumdolorsit.com
                  </Typography>
              </Typography>
              </CardContent>
              <CardContent fontSize="large" style={{ display: 'flex' }}>
                <Checkbox />
                <Typography style={{ marginLeft: '20px' }} >
                    Heat oil in a paella pan or a large.
                    <Typography variant="subtitle2">
                        https://Loremipsumdolorsit.com
                    </Typography>
                </Typography>
              </CardContent>
              <hr /> */}
          {/* </Collapse> */}
        {/* </Card> */}
        {/* <Drawer
          open={this.state.open}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        > */}
        {/* <Dialog
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Add External References')}</DialogTitle>
          <div className={classes.search}>
            <SearchInput
              variant="inDrawer"
              placeholder={`${t('Search')}...`}
              onSubmit={this.handleSearch.bind(this)}
            />
          </div>
          <div style={{ marginLeft: 'auto' }}>
            <Button
              variant="outlined"
              onClick={this.handleClose.bind(this)}
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              classes={{ root: classes.button }}
            >
              {t('Add')}
            </Button>
          </div>
          <DialogContent classes={{ root: classes.dialog }}>
            <QueryRenderer
              query={addExternalReferencesLinesQuery}
              variables={{
                search: this.state.search,
                count: 20,
              }}
              render={({ props }) => {
                if (props) {
                  return (
                    <AddExternalReferencesLines
                      stixCoreObjectOrStixCoreRelationshipId={
                        stixCoreObjectOrStixCoreRelationshipId
                      }
                      stixCoreObjectOrStixCoreRelationshipReferences={
                        stixCoreObjectOrStixCoreRelationshipReferences
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
          </DialogContent> */}
          {/* <DialogContent classes={{ root: classes.dialog }}>
          </DialogContent>
          <DialogActions>
            <Button
              variant="contained"
              onClick={this.handleClose.bind(this)}
              classes={{ root: classes.button }}
            >
              {t('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="primary"
              classes={{ root: classes.button }}
            >
              {t('Create')}
            </Button>
          </DialogActions> */}
          {/* <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton>
            <Typography variant="h6" classes={{ root: classes.title }}>
              {t('Add external references')}
            </Typography>
            <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                placeholder={`${t('Search')}...`}
                onSubmit={this.handleSearch.bind(this)}
              />
            </div>
          </div> */}
          {/* <div className={classes.container}> */}
          {/* </div> */}
          {/* </Dialog> */}
        {/* </Drawer> */}
        {/* </Dialog> */}
      </div>
    );
  }
}

AddExternalReferences.propTypes = {
  stixCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  stixCoreObjectOrStixCoreRelationshipReferences: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(AddExternalReferences);
