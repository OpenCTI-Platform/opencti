import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
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
import IconButton from '@material-ui/core/IconButton';
import FlagIcon from '@material-ui/icons/Flag';
import Grid from '@material-ui/core/Grid';
import CardContent from '@material-ui/core/CardContent';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import MoreVertIcon from '@material-ui/icons/MoreVert';
import ExpandMoreIcon from '@material-ui/icons/ExpandMore';
import Accordion from '@material-ui/core/Accordion';
import AccordionSummary from '@material-ui/core/AccordionSummary';
import AccordionDetails from '@material-ui/core/AccordionDetails';
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
import inject18n from '../../../../../components/i18n';
import { truncate } from '../../../../../utils/String';
import { commitMutation } from '../../../../../relay/environment';
import RelatedTaskCreation from './RelatedTaskCreation';
// import { externalReferenceMutationRelationDelete } from './AddExternalReferencesLines';
import Security, {
  KNOWLEDGE_KNENRICHMENT,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPLOAD,
} from '../../../../../utils/Security';
// import ExternalReferenceEnrichment from './ExternalReferenceEnrichment';
import FileLine from '../../../common/files/FileLine';
import { FIVE_SECONDS } from '../../../../../utils/Time';
import FileUploader from '../../../common/files/FileUploader';
import RelatedTaskPopover from './RelatedTaskPopover';
import CyioCoreobjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '4px 0 0 0',
    padding: 0,
    borderRadius: 6,
    position: 'relative',
  },
  accordionDetails: {
    display: 'block',
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
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class RelatedTasksLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      displayExternalLink: false,
      externalLink: null,
      removeExternalReference: null,
      removing: false,
      expanded: false,
    };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetchConnection(200);
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleToggleExpand() {
    this.setState({ expanded: !this.state.expanded });
  }

  handleOpenDialog(relatedTasksLinesEdge) {
    const openedState = {
      displayDialog: true,
      removeExternalReference: relatedTasksLinesEdge,
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
  //       fromId: this.props.remediationId,
  //       relationship_type: 'external-reference',
  //     },
  //     updater: (store) => {
  //       const entity = store.get(this.props.remediationId);
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
      t, classes, remediationId, data,
    } = this.props;
    const { expanded } = this.state;
    // const externalReferencesEdges = data.riskResponse.external_references.edges;
    // const expandable = externalReferencesEdges.length > 7;
    console.log('RelatedTasksData', data);
    const relatedTasksEdges = R.pipe(
      R.pathOr([], ['tasks', 'edges']),
      R.map((value) => ({
        name: value.node.name,
        description: value.node.description,
        id: value.node.id,
        task_type: value.node.task_type,
      })),
    )(data.riskResponse);
    console.log('relatedTasksEdges', relatedTasksEdges);
    return (
      <div style={{ height: '100%' }}>
        <div className={classes.cardContent}>
          <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
            {t('Related Tasks')}
          </Typography>
          {/* <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 28 }} />}
        > */}
          <div>
            <RelatedTaskCreation
              display={true}
              contextual={true}
              remediationId={remediationId}
            // stixCoreObjectOrStixCoreRelationshipId={remediationId}
            // stixCoreObjectOrStixCoreRelationshipReferences={
            //   data.riskResponse.external_references.edges
            // }
            />
          </div>
          {/* </Security> */}
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <div style={{ display: 'grid', gridTemplateColumns: '90% 10%' }}>
            <Accordion style={{ borderBottom: '0', boxShadow: 'none' }}>
              <AccordionSummary
                onClick={() => this.handleClick()}
                expandIcon={<ExpandMoreIcon />}
                aria-controls="panel1a-content"
                id="panel1a-header"
              >
                {this.state.value ? '' : (
                  <CardContent className={classes.cardContent}>
                    <FlagIcon fontSize='large' color="disabled" />
                    <div style={{ marginLeft: '10px' }}>
                      <Typography align="left" color="textSecondary" variant="h3">{t('Lorel Ipsum')}</Typography>
                      <Typography align="left" variant="subtitle1">{t('https://loreipsumdolorsitametloreamet.com')}</Typography>
                    </div>
                  </CardContent>
                )
                }
              </AccordionSummary>
              <AccordionDetails classes={{ root: classes.accordionDetails }}>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={6}>
                    <Grid style={{
                      display: 'flex',
                      alignItems: 'center',
                      marginBottom: '15px',
                      marginLeft: '1px',
                    }}>
                      <div style={{ marginLeft: '10px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('Name')}</Typography>
                        <Typography align="left" variant="subtitle1">
                          {/* {t('Lorem Ipsum')} */}
                          {relatedTasksEdges?.length > 0 && relatedTasksEdges.map((value, key) => (
                            <>
                              <div className="clearfix" />
                              {value.name}
                            </>
                          ))}
                        </Typography>
                      </div>
                    </Grid>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Grid style={{
                      display: 'flex',
                      alignItems: 'center',
                      marginBottom: '15px',
                      marginLeft: '-4px',
                    }}>
                      <div style={{ marginLeft: '10px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('ID')}</Typography>
                        <Typography align="left" variant="subtitle1">
                          {/* {t('Lorem Ipsum')} */}
                          {relatedTasksEdges?.length > 0 && relatedTasksEdges.map((value, key) => (
                            <>
                              <div className="clearfix" />
                              {value.id}
                            </>
                          ))}
                        </Typography>
                      </div>
                    </Grid>
                  </Grid>
                </Grid>
                <Grid container={true}>
                  <Grid item={true} xs={6}>
                    <Grid style={{ display: 'flex', alignItems: 'center', marginBottom: '15px' }}>
                      <div style={{ marginLeft: '10px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('Task Type')}</Typography>
                        <div className={classes.cardContent}>
                          <FlagIcon fontSize='large' color="disabled" />
                          <Typography style={{ marginLeft: '10px' }} align="center" variant="subtitle1">
                            {/* {t('Lorem Ipsum')} */}
                          {relatedTasksEdges?.length > 0 && relatedTasksEdges.map((value, key) => (
                              <>
                                <div className="clearfix" />
                                {value.task_type}
                              </>
                          ))}
                          </Typography>
                        </div>
                      </div>
                    </Grid>
                    <Grid item={true} xs={6} className={classes.cardContent} style={{ marginBottom: '15px' }}>
                      <div style={{ marginLeft: '10px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('Start Date')}</Typography>
                        <Typography align="left" variant="subtitle1">
                          {t('21 June 2021')}
                        </Typography>
                      </div>
                    </Grid>
                    <Grid item={true} xs={6} className={classes.cardContent} style={{ marginBottom: '15px' }}>
                      <div style={{ marginLeft: '10px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('Tasks')}</Typography>
                        <Typography align="left" variant="subtitle1">
                          {t('Lorem Ipsum')}
                        </Typography>
                      </div>
                    </Grid>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Grid className={classes.cardContent} style={{ marginBottom: '20px' }}>
                      <div style={{ marginLeft: '18px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('Dependency')}</Typography>
                        <Typography align="left" variant="subtitle1">{t('Lorem Ipsum Dolor Sit Amet')}</Typography>
                      </div>
                    </Grid>
                    <Grid item={true} xs={6} style={{
                      display: 'flex',
                      alignItems: 'center',
                      marginBottom: '15px',
                    }}>
                      <div style={{ marginLeft: '18px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('End Date')}</Typography>
                        <Typography align="left" variant="subtitle1">{t('11 June 2021')}</Typography>
                      </div>
                    </Grid>
                    <Grid item={true} xs={12} style={{ display: 'flex', alignItems: 'center', marginBottom: '15px' }}>
                      <div style={{ marginLeft: '18px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('Responsible Role')}</Typography>
                        <div className={classes.cardContent}>
                          <Avatar alt="Travis Howard" src="/static/images/avatar/2.jpg" />
                          <div style={{ marginLeft: '10px' }}>
                            <Typography variant="subtitle1">
                              {t('Lorem Ipsum')}
                            </Typography>
                            {t('Lorem Ipsum')}
                          </div>
                        </div>
                      </div>
                    </Grid>
                  </Grid>

                </Grid>
                <Grid container={true}>
                  <Grid item={true} xs={12} style={{ marginBottom: '10px' }}>
                    <Typography
                      color="textSecondary"
                      gutterBottom={true}
                      style={{ float: 'left', marginTop: 20 }}
                    >
                      {t('Description')}
                    </Typography>
                    <div style={{ float: 'left', margin: '21px 0 0 5px' }}>
                      <Tooltip
                        title='Description'
                      >
                        <Information fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
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
                          {/* {t('Description')} */}
                          {relatedTasksEdges?.length > 0 && relatedTasksEdges.map((value, key) => (
                            <>
                              <div className="clearfix" />
                              {value.description}
                            </>
                          ))}
                        </div>
                      </div>
                    </div>
                  </Grid>
                  <Grid style={{ marginTop: '20px' }} xs={12} item={true}>
                    <CyioCoreobjectExternalReferences
                      cyioCoreObjectId={remediationId}
                    />
                  </Grid>
                  <Grid style={{ marginTop: '20px' }} xs={12} item={true}>
                    <CyioCoreObjectOrCyioCoreRelationshipNotes
                      cyioCoreObjectOrCyioCoreRelationshipId={remediationId}
                      marginTop='20px'
                    // data={props}
                    // marginTop={marginTop}
                    />
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>
            <div style={{ marginTop: '30px' }}>
              <RelatedTaskPopover
                handleRemove={this.handleOpenDialog.bind(this)}
                remediationId={remediationId}
              />
            </div>
          </div>
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
      </div>
    );
  }
}

RelatedTasksLinesContainer.propTypes = {
  remediationId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  relay: PropTypes.object,
};

export const RelatedTasksLinesQuery = graphql`
  query RelatedTasksLinesQuery($count: Int!, $id: ID!) {
    ...RelatedTasksLines_data
      @arguments(count: $count, id: $id)
  }
`;

const RelatedTasksLines = createPaginationContainer(
  RelatedTasksLinesContainer,
  {
    data: graphql`
      fragment RelatedTasksLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "ID!" }
      ) {
        riskResponse(id: $id) {
          id
          tasks(first: $count)
            @connection(key: "Pagination_related_tasks") {
            edges {
              node {
                id
                created
                modified
                labels
                task_type
                name
                description
                timing {
                  ... on DateRangeTiming {
                    start_date          # Start Date
                    end_date            # End Date
                  }
                  ... on OnDateTiming {
                    on_date             # Start Date
                  }
                }
                task_dependencies(first: 5) {
                  edges {
                    node {
                      id
                      name
                    }
                  }
                }
                responsible_roles {
                  id
                  created
                  modified
                  labels
                  role {
                    id
                    created
                    modified
                    role_identifier
                    name
                  }
                }
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
      return props.data && props.data.riskResponse.external_references;
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
    query: RelatedTasksLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(RelatedTasksLines);
