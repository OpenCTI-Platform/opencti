/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import Button from '@material-ui/core/Button';
import InputAdornment from '@material-ui/core/InputAdornment';
import CardActions from '@material-ui/core/CardActions';
import TextField from '@material-ui/core/TextField';
import Collapse from '@material-ui/core/Collapse';
import Divider from '@material-ui/core/Divider';
import DialogTitle from '@material-ui/core/DialogTitle';
import { ConnectionHandler } from 'relay-runtime';
import KeyboardArrowDownOutlinedIcon from '@material-ui/icons/KeyboardArrowDownOutlined';
import { Add } from '@material-ui/icons';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import inject18n from '../../../../components/i18n';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import CyioExternalReferenceCreation from './CyioExternalReferenceCreation';
import CyioAddExternalReferencesLines, {
  cyioAddExternalReferencesLinesQuery,
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
  menuItemName: {
    padding: '15px 10px',
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
      expanded: false,
      totalExternalReference: [],
      removeIcon: false,
    };
    this.timeout = null;
  }

  toggleExternalReference(createExternalRef) {
    const {
      cyioCoreObjectOrCyioCoreRelationshipId,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
    } = this.props;
    if (this.state.totalExternalReference.length > 0) {
      this.state.totalExternalReference.map((externalReference) => (
        CM(environmentDarkLight, {
          mutation: cyioExternalReferenceLinesMutationRelationAdd,
          variables: {
            toId: externalReference.id,
            fromId: cyioCoreObjectOrCyioCoreRelationshipId,
            fieldName: this.props.fieldName,
            from_type: this.props.typename,
            to_type: externalReference.__typename,
          },
          onCompleted: (response) => {
            this.handleClose();
            this.setState({ totalExternalReference: [] });
            if (this.props.refreshQuery) {
              this.props.refreshQuery();
            }
          },
          // updater: (store) => {
          //   const payload = store
          //   // .getRootField('externalReferenceEdit')
          //   // .getLinkedRecord('relationAdd', { input });
          //   const relationId = payload.getValue('toId');
          //   // const node = payload.getLinkedRecord('to');
          //   const relation = store.get(relationId);
          //   payload.setLinkedRecord(node, 'node');
          //   payload.setLinkedRecord(relation, 'relation');
          //   sharedUpdater(store, cyioCoreObjectOrCyioCoreRelationshipId, payload);
          // },
        })
      ));
    } else {
      CM(environmentDarkLight, {
        mutation: cyioExternalReferenceLinesMutationRelationAdd,
        variables: {
          toId: createExternalRef.id,
          fromId: cyioCoreObjectOrCyioCoreRelationshipId,
          fieldName: this.props.fieldName,
          from_type: this.props.typename,
          to_type: createExternalRef.__typename,
        },
        // updater: (store) => {
        //   const payload = store
        //   // .getRootField('externalReferenceEdit')
        //   // .getLinkedRecord('relationAdd', { input });
        //   const relationId = payload.getValue('toId');
        //   // const node = payload.getLinkedRecord('to');
        //   const relation = store.get(relationId);
        //   payload.setLinkedRecord(node, 'node');
        //   payload.setLinkedRecord(relation, 'relation');
        //   sharedUpdater(store, cyioCoreObjectOrCyioCoreRelationshipId, payload);
        // },
        onCompleted: (response) => {
          this.setState({ totalExternalReference: [] });
          if (this.props.refreshQuery) {
            this.props.refreshQuery();
          }
        },
      });
    }
  }

  handleOpen() {
    this.setState({ open: true, expanded: false });
  }

  handleClose() {
    this.setState({ open: false, search: '', expanded: false });
  }

  handleDataCollect(dataCollect) {
    this.setState({ totalExternalReference: [...dataCollect] });
  }

  handleOpenSearch() {
    this.setState({ expanded: true });
  }

  handleCloseSearch() {
    this.setState({ expanded: false });
  }

  handleSearch(event) {
    const keyword = event.target.value;
    if (this.timeout) clearTimeout(this.timeout);
    this.timeout = setTimeout(() => {
      if (keyword.length === 0) {
        this.setState({ expanded: false });
      } else {
        this.setState({ search: keyword, expanded: true });
      }
    }, 1500);
  }

  render() {
    const {
      t,
      classes,
      disableAdd,
      menuItemName,
      cyioCoreObjectOrCyioCoreRelationshipId,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
      typename,
      removeIcon,
    } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <div>
        {menuItemName ? (
          <div
            className={classes.menuItemName}
            onClick={this.handleOpen.bind(this)}
          >
            {t(menuItemName)}
          </div>
        ) : (
          <IconButton
            color="default"
            aria-label="Add"
            onClick={this.handleOpen.bind(this)}
            classes={{ root: classes.createButton }}
            disabled={disableAdd}
          >
            {removeIcon ? (
              <></>
            ) : (
              <Add fontSize="small" />
            )}
          </IconButton>
        )}
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
            <div className={classes.dialogMain}>
              <DialogTitle style={{ padding: 10 }}>{t('Add External References')}</DialogTitle>
              {/* <CardHeader title="Add External Refrences"/> */}
              <CardActions sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <TextField
                  style={{ width: 495 }}
                  onChange={(event) => this.handleSearch(event)}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position="end" >
                        <CyioExternalReferenceCreation
                          display={this.state.open}
                          contextual={true}
                          inputValue={this.state.search}
                          onExpand={this.handleCloseSearch.bind(this)}
                          paginationOptions={paginationOptions}
                          onCreate={this.toggleExternalReference.bind(this)}
                        />
                        <div style={{ marginLeft: '10px' }}>
                          {
                            this.state.expanded
                              ? <KeyboardArrowDownOutlinedIcon onClick={this.handleCloseSearch.bind(this)} style={{ transform: 'rotate(180deg)', cursor: 'pointer' }} />
                              : <KeyboardArrowDownOutlinedIcon onClick={this.handleOpenSearch.bind(this)} style={{ cursor: 'pointer' }} />
                          }
                        </div>
                      </InputAdornment>
                    ),
                  }} />
                <div style={{ float: 'right', marginLeft: '40px' }}>
                  <Button style={{ marginLeft: '10px', marginRight: '10px' }} onClick={this.handleClose.bind(this)} variant="outlined" >{t('Cancel')}</Button>
                  <Button variant="contained" color="primary" onClick={this.toggleExternalReference.bind(this)}>{t('Add')}</Button>
                </div>
                <Divider light={true} />
              </CardActions>
            </div>
            <Collapse sx={{ maxWidth: '500px', borderRadius: 0 }} in={this.state.expanded} timeout="auto" unmountOnExit>
              <div className={classes.collapse}>
                <QR
                  environment={environmentDarkLight}
                  query={cyioAddExternalReferencesLinesQuery}
                  variables={{
                    search: this.state.search,
                    count: 4,
                  }}
                  render={({ props }) => {
                    if (props) {
                      return (
                        <CyioAddExternalReferencesLines
                          typename={typename}
                          cyioCoreObjectOrCyioCoreRelationshipId={
                            cyioCoreObjectOrCyioCoreRelationshipId
                          }
                          cyioCoreObjectOrCyioCoreRelationshipReferences={
                            cyioCoreObjectOrCyioCoreRelationshipReferences
                          }
                          data={props}
                          handleDataCollect={this.handleDataCollect.bind(this)}
                          paginationOptions={paginationOptions}
                          open={this.state.open}
                          search={this.state.search.toLowerCase()}
                        />
                      );
                    }
                    return <></>;
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
  refreshQuery: PropTypes.func,
  menuItemName: PropTypes.string,
  fieldName: PropTypes.string,
  disableAdd: PropTypes.bool,
  typename: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  removeIcon: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(CyioAddExternalReferences);
