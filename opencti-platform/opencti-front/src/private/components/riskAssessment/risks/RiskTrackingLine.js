import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createPaginationContainer, createFragmentContainer } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import Accordion from '@material-ui/core/Accordion';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import ExpandLessIcon from '@material-ui/icons/ExpandLess';
import Grid from '@material-ui/core/Grid';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import LaunchIcon from '@material-ui/icons/Launch';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Button from '@material-ui/core/Button';
import Avatar from '@material-ui/core/Avatar';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import { ExpandMoreOutlined, ExpandLessOutlined } from '@material-ui/icons';
import Slide from '@material-ui/core/Slide';
import { interval } from 'rxjs';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation } from '../../../../relay/environment';
// import AddExternalReferences from './AddExternalReferences';
// import { externalReferenceMutationRelationDelete } from './AddExternalReferencesLines';
import Security, {
  KNOWLEDGE_KNENRICHMENT,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPLOAD,
} from '../../../../utils/Security';
// import ExternalReferenceEnrichment from './ExternalReferenceEnrichment';
import FileLine from '../../common/files/FileLine';
import { FIVE_SECONDS } from '../../../../utils/Time';
import RiskTrackingLogEdition from './RiskTrackingLogEdition';
import FileUploader from '../../common/files/FileUploader';
import RiskTrackingPopover from './RiskTrackingPopover';
import RiskLogCreation from './RiskLogCreation';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: '0px 24px 24px 24px',
    borderRadius: 6,
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
  accordionDetails: {
    display: 'block',
    padding: '8px 20px',
  },
  accordionSummary: {
    height: 0,
    padding: 0,
  },
  listItem: {
    padding: '20px 0',
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  cardContent: {
    display: 'flex',
    alignItems: 'center',
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
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '78px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  span: {
    color: theme.palette.background.nav,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class RiskTrackingLineContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      displayUpdate: false,
      displayExternalLink: false,
      externalLink: null,
      removeExternalReference: null,
      removing: false,
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

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
  }

  handleOpenDialog(riskTrackingEdge) {
    const openedState = {
      displayDialog: true,
      removeExternalReference: riskTrackingEdge,
    };
    this.setState(openedState);
  }

  handleClick(e) {
    console.log('handleClick', e);
    this.setState({
      value: !this.state.value,
    });
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

  // removeExternalReference(externalReferenceEdge) {
  //   commitMutation({
  //     mutation: externalReferenceMutationRelationDelete,
  //     variables: {
  //       id: externalReferenceEdge.node.id,
  //       fromId: this.props.risk,
  //       relationship_type: 'external-reference',
  //     },
  //     updater: (store) => {
  //       const entity = store.get(this.props.risk);
  //       const conn = ConnectionHandler.getConnection(
  //         entity,
  //         'Pagination_externalReferences',
  //       );
  //       ConnectionHandler.deleteNode(conn, externalReferenceEdge.node.id);
  //     },
  //     onCompleted: () => {
  //       this.setState({ removing: false });
  //       this.handleCloseDialog();
  //     },
  //   });
  // }

  render() {
    const {
      t,
      fd,
      classes,
      riskId,
      node,
    } = this.props;
    const { expanded, displayUpdate } = this.state;
    console.log('riskTrackingNode', node);
    // console.log('riskTrackingRiskId', riskId);
    return (
      <>
        <ListItem classes={{ root: classes.listItem }} disablePadding={true} disableGutters={true} alignItems='flex-start' divider={true} style={{ display: 'grid', gridTemplateColumns: '95% 5%' }}>
          <Accordion style={{ borderBottom: '0', boxShadow: 'none' }}>
            <AccordionSummary
              onClick={this.handleClick.bind(this)}
              classes={{ root: classes.accordionSummary }}
              expandIcon={<ExpandLessIcon />}
              aria-controls="panel1a-content"
              id="panel1a-header"
            >
              <div style={{ display: 'flex', textAlign: 'left' }}>
                {this.state.value ? '' : (
                  <div className={classes.cardContent}>
                    <Avatar alt="Travis Howard" src="/static/images/avatar/2.jpg" />
                    <div style={{ marginLeft: '16px', paddingTop: '10px' }}>
                      <Typography>
                        {t('Risk Log Entry Title')}
                      </Typography>
                      <Typography color="textSecondary" variant="h3">
                        {t('Logged By')} <span className={classes.span}>{t('Start End')}</span>
                      </Typography>
                    </div>
                  </div>
                )}
              </div>
            </AccordionSummary>
            <AccordionDetails classes={{ root: classes.accordionDetails }}>
              {/* {displayUpdate ? (
                  <RiskTrackingLogEdition />
                ) : ( */}
              <>
                <Grid container={true}>
                  <Grid item={true} xs={4}>
                    <div style={{ marginBottom: '15px' }}>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t('Entry Type')}
                      </Typography>
                      <div className={classes.cardContent}>
                        <Avatar alt="Travis Howard" src="/static/images/avatar/2.jpg" />
                        <Typography style={{ marginLeft: '10px' }} align="left">
                          {/* {t('Lorem Ipsum')} */}
                          {node.entry_type && t(node.entry_type)}
                        </Typography>
                      </div>
                    </div>
                    <div>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t('Start Date')}
                      </Typography>
                      <Typography align="left" variant="subtitle2">
                        {node.event_start && fd(node.event_start)}
                      </Typography>
                    </div>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <div style={{ marginBottom: '27px' }}>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t('Title')}
                      </Typography>
                      <Typography align="left" variant="subtitle2">
                        {node.name && t(node.name)}
                      </Typography>
                    </div>
                    <div style={{ marginBottom: '30px' }}>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t(' End Date')}
                      </Typography>
                      <Typography align="left" variant="subtitle2">
                        {node.event_end && fd(node.event_end)}
                      </Typography>
                    </div>
                  </Grid>
                  <Grid item={true} xs={4} >
                    <Typography
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left' }}
                    >
                      {t('Description')}
                    </Typography>
                    <div className="clearfix" />
                    <div className={classes.scrollBg}>
                      <div className={classes.scrollDiv}>
                        <div className={classes.scrollObj}>
                          {/* {device.locations && device.locations.map((location, key) => (
                          <div key={key}>
                            {`${location.street_address && t(location.street_address)}, `}
                            {`${location.city && t(location.city)}, `}
  {`${location.country && t(location.country)}, ${location.postal_code && t(location.postal_code)}`}
                          </div>
                        ))} */}
                          {node.description && t(node.description)}
                        </div>
                      </div>
                    </div>
                  </Grid>
                </Grid>
                <Grid container={true}>
                  <Grid item={true} xs={3}>
                    <div>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t('Logged By')}
                      </Typography>
                      <div className={classes.cardContent}>
                        <Avatar alt="Travis Howard" src="/static/images/avatar/2.jpg" />
                        <div style={{ textAlign: 'left', marginLeft: '10px' }}>
                          <Typography variant="subtitle2">
                            {t('Lorem Ipsum')}
                          </Typography>
                          <Typography variant="h3" color="textSecondary">
                            {t('Lorem Ipsum Dolor Ist')}
                          </Typography>
                        </div>
                      </div>
                    </div>
                  </Grid>
                  <Grid item={true} xs={5}>
                    <div style={{ textAlign: 'left', marginLeft: '90px' }}>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t('Status Change')}
                      </Typography>
                      <Button color="primary" variant="outlined">
                        {node.status_change && t(node.status_change)}
                      </Button>
                    </div>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <Typography align="left" variant="h3" color="textSecondary">
                      {t('Related Response')}
                    </Typography>
                    <Typography align="left" variant="subtitle2">
                      <span className={classes.cardContent}>
                        <LaunchIcon style={{ marginRight: '5px' }} fontSize="small" />
                        {t('Lorem Ipsum')}
                      </span>
                    </Typography>
                  </Grid>
                </Grid>
              </>
              {/* )} */}
            </AccordionDetails>
          </Accordion>
          <div>
            <RiskTrackingPopover
              handleRemove={this.handleOpenDialog.bind(this)}
              handleOpenUpdate={this.handleOpenUpdate.bind(this)} />
          </div>
        </ListItem>
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
              {t('Delete')}
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
      </>
    );
  }
}

RiskTrackingLineContainer.propTypes = {
  riskId: PropTypes.string,
  node: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  relay: PropTypes.object,
};

const RiskTrackingLineFragment = createFragmentContainer(
  RiskTrackingLineContainer,
  {
    node: graphql`
    fragment RiskTrackingLine_node on LogEntry{
      id
      created
      modified
      entry_type        # Entry Type
      name              # Title
      description       # Description
      event_start       # Start Date
      event_end         # End Date
      status_change     # Status Change
      logged_by {
        ... on OscalPerson {
          id
          name
        }
        ... on OscalOrganization {
          id
          name
        }
      }
      related_responses {
        id
        name
      }
    }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(RiskTrackingLineFragment);
