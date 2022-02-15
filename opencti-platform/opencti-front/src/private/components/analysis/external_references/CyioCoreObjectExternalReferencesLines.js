/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
// import { createPaginationContainer } from 'react-relay';
// import { ConnectionHandler } from 'relay-runtime';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import Accordion from '@material-ui/core/Accordion';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import ExpandMoreIcon from '@material-ui/icons/ExpandMore';
import LinkIcon from '@material-ui/icons/Link';
import Divider from '@material-ui/core/Divider';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import ListItemText from '@material-ui/core/ListItemText';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import { ExpandMoreOutlined, ExpandLessOutlined } from '@material-ui/icons';
import Slide from '@material-ui/core/Slide';
import { interval } from 'rxjs';
import { commitMutation as CM, createFragmentContainer, createPaginationContainer } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
// import { commitMutation } from '../../../../relay/environment';
import CyioAddExternalReferences from './CyioAddExternalReferences';
import { cyioExternalReferenceMutationRelationDelete } from './CyioAddExternalReferencesLines';
import Security, {
  // KNOWLEDGE_KNENRICHMENT,
  KNOWLEDGE_KNUPDATE,
  // KNOWLEDGE_KNUPLOAD,
} from '../../../../utils/Security';
import { FIVE_SECONDS } from '../../../../utils/Time';
import CyioExternalReferencePopover from './CyioExternalReferencePopover';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: 0,
    position: 'relative',
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
  buttonExpand: {
    position: 'absolute',
    bottom: 2,
    width: '100%',
    height: 25,
    backgroundColor: 'rgba(255, 255, 255, .2)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor: 'rgba(255, 255, 255, .5)',
    },
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class CyioCoreObjectExternalReferencesLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      displayExternalLink: false,
      externalLink: null,
      removeExternalReference: null,
      removing: false,
      displayExternalRefID: false,
      expanded: false,
    };
  }

  // componentDidMount() {
  //   this.subscription = interval$.subscribe(() => {
  //     this.props.relay.refetchConnection(200);
  //   });
  // }

  // componentWillUnmount() {
  //   this.subscription.unsubscribe();
  // }

  handleToggleExpand() {
    this.setState({ expanded: !this.state.expanded });
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

  handleOpenExternalLink(url) {
    this.setState({ displayExternalLink: true, externalLink: url });
  }

  handleCloseExternalLink() {
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  handleBrowseExternalLink() {
    window.open(this.state.externalLink, '_blank');
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  handleToggleDetails() {
    this.setState({ displayExternalRefID: !this.state.displayExternalRefID });
  }

  removeExternalReference(externalReferenceEdge) {
    CM(environmentDarkLight, {
      mutation: cyioExternalReferenceMutationRelationDelete,
      variables: {
        toId: externalReferenceEdge.id,
        fromId: this.props.cyioCoreObjectId,
        fieldName: 'external_reference',
      },
      onCompleted: (resp) => {
        this.setState({ removing: false });
        this.handleCloseDialog();
      },
      // onError: (err) => console.log('ExtRefRemoveDarkLightMutationError', err),
    });
    // commitMutation({
    //   mutation: cyioExternalReferenceMutationRelationDelete,
    //   variables: {
    //     id: externalReferenceEdge.node.id,
    //     fromId: this.props.cyioCoreObjectId,
    //     relationship_type: 'external-reference',
    //   },
    //   updater: (store) => {
    //     const entity = store.get(this.props.cyioCoreObjectId);
    //     const conn = ConnectionHandler.getConnection(
    //       entity,
    //       'Pagination_externalReferences',
    //     );
    //     ConnectionHandler.deleteNode(conn, externalReferenceEdge.node.id);
    //   },
    //   onCompleted: () => {
    //     this.setState({ removing: false });
    //     this.handleCloseDialog();
    //   },
    // });
  }

  render() {
    const {
      t, classes, cyioCoreObjectId, externalReference,
    } = this.props;
    const { expanded, displayExternalRefID } = this.state;
    // const externalReferencesEdges = externalReference || [];
    // const externalReferencesEdges = [externalReference.externalReference];
    // const expandable = externalReferencesEdges.length > 7;
    return (
      <div>
        <List style={{ marginBottom: 0, padding: '12px' }}>
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: '90% 10%' }}>
              <Accordion onChange={this.handleToggleDetails.bind(this)} style={{ borderBottom: '0', boxShadow: 'none' }}>
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon />}
                  aria-controls="panel1a-content"
                  id="panel1a-header"
                  sx={{ width: '100%' }}
                >
                  <ListItemText
                    primary={externalReference.source_name}
                    secondary={!displayExternalRefID
                      ? (externalReference.url && truncate(t(externalReference.url), 80))
                      : (externalReference.id && t(externalReference.id))}
                  />
                </AccordionSummary>
                <AccordionDetails>
                  <div >
                    <Typography variant="subtitle1" gutterBottom={true}>
                      {externalReference.description}
                    </Typography>
                    <Typography variant="subtitle2" style={{ display: 'flex', color: '#F9B406' }} >
                      <LinkIcon fontSize="small" style={{ paddingRight: '5px' }} />
                      {externalReference.url && truncate(
                        t(externalReference.url),
                        80,
                      )}
                    </Typography>
                  </div>
                </AccordionDetails>
                {/* </ListItem> */}
              </Accordion>
              <div style={{ marginTop: '12px' }}>
                {/* <Security needs={[KNOWLEDGE_KNUPDATE]}> */}
                <CyioExternalReferencePopover
                  externalReference={externalReference}
                  externalReferenceId={externalReference.id}
                  handleRemove={this.handleOpenDialog.bind(
                    this,
                    externalReference,
                  )}
                />
                {/* </Security> */}
              </div>
            </div>
            <Divider variant="middle" light={true} />
          </div>
          {/* );
                },
              )} */}
        </List>
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
              disabled={this.state.removing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleRemoval.bind(this)}
              color="primary"
              disabled={this.state.removing}
            >
              {t('Remove')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          open={this.state.displayExternalLink}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseExternalLink.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to browse this external link?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleCloseExternalLink.bind(this)}>
              {t('Cancel')}
            </Button>
            <Button
              button={true}
              color="secondary"
              onClick={this.handleBrowseExternalLink.bind(this)}
            >
              {t('Browse the link')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

CyioCoreObjectExternalReferencesLinesContainer.propTypes = {
  cyioCoreObjectId: PropTypes.string,
  externalReference: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  relay: PropTypes.object,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(CyioCoreObjectExternalReferencesLinesContainer);
