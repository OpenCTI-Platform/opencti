import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Accordion from '@material-ui/core/Accordion';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import AccordionDetails from '@material-ui/core/AccordionDetails';
import FlagOutlinedIcon from '@material-ui/icons/FlagOutlined';
import ExpandLessIcon from '@material-ui/icons/ExpandLess';
import Grid from '@material-ui/core/Grid';
import ListItem from '@material-ui/core/ListItem';
import LaunchIcon from '@material-ui/icons/Launch';
import Button from '@material-ui/core/Button';
import Avatar from '@material-ui/core/Avatar';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Slide from '@material-ui/core/Slide';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeRaw from 'rehype-raw';
import remarkParse from 'remark-parse';
import inject18n from '../../../../components/i18n';
import RiskTrackingPopover from './RiskTrackingPopover';

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
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
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
  buttonPopover: {
    textTransform: 'capitalize',
  },
  avatarIconColor: {
    color: 'white',
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
    marginLeft: 10,
  },
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
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

  handleClick() {
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
      fld,
      classes,
      history,
      riskId,
      node,
      refreshQuery,
      riskStatusResponse,
    } = this.props;
    const riskTrackingLoggedBy = R.pipe(
      R.pathOr([], ['logged_by']),
      R.mergeAll,
    )(node);
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
                    <Avatar>
                      <FlagOutlinedIcon className={classes.avatarIconColor} />
                    </Avatar>
                    <div style={{ marginLeft: '16px', paddingTop: '10px' }}>
                      <Typography>
                        {node.name && t(node.name)}
                      </Typography>
                      <Typography color="textSecondary" variant="h3">
                        {t('Logged By')}
                        <span className={classes.span}>
                          {riskTrackingLoggedBy?.party && riskTrackingLoggedBy?.party.name}
                        </span>
                      </Typography>
                    </div>
                  </div>
                )}
              </div>
            </AccordionSummary>
            <AccordionDetails classes={{ root: classes.accordionDetails }}>
              <>
                <Grid container={true}>
                  <Grid item={true} xs={4}>
                    <div style={{ marginBottom: '15px' }}>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t('Entry Type')}
                      </Typography>
                      <div className={classes.cardContent}>
                        <Avatar>
                          <FlagOutlinedIcon className={classes.avatarIconColor} />
                        </Avatar>
                        <Typography style={{ marginLeft: '10px' }} align="left">
                          {node.entry_type && t(node.entry_type)}
                        </Typography>
                      </div>
                    </div>
                    <div>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t('Start Date')}
                      </Typography>
                      <Typography align="left" variant="subtitle2">
                        {node.event_start && fld(node.event_start)}
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
                        {node.event_end && fld(node.event_end)}
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
                          <Markdown
                            remarkPlugins={[remarkGfm, remarkParse]}
                            rehypePlugins={[rehypeRaw]}
                            parserOptions={{ commonmark: true }}
                            className="markdown"
                          >
                            {node.description && t(node.description)}
                          </Markdown>
                        </div>
                      </div>
                    </div>
                  </Grid>
                </Grid>
                <Grid style={{ marginTop: '10px' }} container={true}>
                  <Grid item={true} xs={4}>
                    <div>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t('Logged By')}
                      </Typography>
                      <div className={classes.cardContent}>
                        <Avatar>
                          <FlagOutlinedIcon className={classes.avatarIconColor} />
                        </Avatar>
                        <div style={{ textAlign: 'left', marginLeft: '10px' }}>
                          <Typography variant="subtitle2">
                            {riskTrackingLoggedBy?.party && t(riskTrackingLoggedBy?.party.name)}
                          </Typography>
                        </div>
                      </div>
                    </div>
                  </Grid>
                  <Grid item={true} xs={4}>
                    <div>
                      <Typography align="left" variant="h3" color="textSecondary">
                        {t('Status Change')}
                      </Typography>
                      <Button
                        variant="outlined"
                        className={classes.statusButton}
                      >
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
                        {node.related_responses && node.related_responses.map((value) => (
                          <>
                            <LaunchIcon style={{ marginRight: '5px' }} fontSize="small" />
                            {t(value.name)}
                          </>
                        ))}
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
              handleOpenUpdate={this.handleOpenUpdate.bind(this)}
              history={history}
              riskId={riskId}
              refreshQuery={refreshQuery}
              node={node}
              riskStatusResponse={riskStatusResponse}
            />
          </div>
        </ListItem>
        <Dialog
          open={this.state.displayDialog}
          keepMounted={true}
          TransitionComponent={Transition}
        >
          <DialogContent>
            <Typography style={{
              fontSize: '18px',
              lineHeight: '24px',
              color: 'white',
            }} >
              {t('Do you want to remove this risk log?')}
            </Typography>
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              size="small"
              variant="outlined"
              disabled={this.state.removing}
              classes={{ root: classes.buttonPopover }}
              onClick={this.handleCloseDialog.bind(this)}
            >
              {t('Cancel')}
            </Button>
            <Button
              size="small"
              color="secondary"
              variant="contained"
              disabled={this.state.removing}
              onClick={this.handleRemoval.bind(this)}
              classes={{ root: classes.buttonPopover }}
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
      </>
    );
  }
}

RiskTrackingLineContainer.propTypes = {
  riskId: PropTypes.string,
  node: PropTypes.object,
  limit: PropTypes.number,
  refreshQuery: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  relay: PropTypes.object,
  riskStatusResponse: PropTypes.array,
};

const RiskTrackingLineFragment = createFragmentContainer(
  RiskTrackingLineContainer,
  {
    node: graphql`
    fragment RiskTrackingLine_node on RiskLogEntry{
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
        id
        entity_type
        party {
          __typename
          id
          entity_type
          name
        }
        role {
          id
          entity_type
          role_identifier
          name
        }
      }
      related_responses {
        id
        name
        description
        response_type
      }
    }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(RiskTrackingLineFragment);
