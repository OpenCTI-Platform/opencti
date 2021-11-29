import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createPaginationContainer } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import CardContent from '@material-ui/core/CardContent';
import GroupIcon from '@material-ui/icons/Group';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import MoreVertIcon from '@material-ui/icons/MoreVert';
import IconButton from '@material-ui/core/IconButton';
import ExpandMoreIcon from '@material-ui/icons/ExpandMore';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
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
import RequiredAssetCreation from './RequiredAssetCreation';
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
import RequiredAssetPopover from './RequiredAssetPopover';
import CyioCoreobjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNoteCard from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNoteCard';

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
  accordionDetails: {
    display: 'block',
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

class RequiredAssetsLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      displayExternalLink: false,
      externalLink: null,
      removeExternalReference: null,
      removing: false,
      expanded: false,
      value: false,
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

  handleClick() {
    this.setState({
      value: !this.state.value,
    });
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
    console.log('RequiredAssetsLinesData', data);
    const { expanded } = this.state;
    const externalReferencesEdges = data.itAsset.external_references.edges;
    const expandable = externalReferencesEdges.length > 7;
    return (
      <div style={{ height: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
            {t('Required Assets')}
          </Typography>
          {/* <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 28 }} />}
        > */}
          <RequiredAssetCreation
            remediationId={remediationId}
            display={true}
            contextual={true}
          // stixCoreObjectOrStixCoreRelationshipId={remediationId}
          // stixCoreObjectOrStixCoreRelationshipReferences={
          //   data.itAsset.external_references.edges
          // }
          />
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
                classes={{ root: classes.summary }}
              >
                {this.state.value ? '' : (
                  <CardContent style={{ display: 'flex', alignItems: 'center' }}>
                    <GroupIcon fontSize='large' color="disabled" />
                    <div style={{ marginLeft: '10px' }}>
                      <Typography align="left" color="textSecondary" variant="h3">{t('Lorel Ipsum')}</Typography>
                      <Typography align="left" variant="subtitle1">{t('https://loreipsumdolorsitametloreipsumdolorsitamet.com')}</Typography>
                    </div>
                  </CardContent>
                )
                }
              </AccordionSummary>
              <AccordionDetails classes={{ root: classes.accordionDetails }}>
                <Grid container={true} spacing={3} >
                  <Grid item={true} xs={6}>
                    <Grid style={{ display: 'flex', alignItems: 'center', marginBottom: '20px' }}>
                      <div style={{ marginLeft: '10px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('Name')}</Typography>
                        <Typography align="left" variant="subtitle1">{t('Lorem Ipsum')}</Typography>
                      </div>
                    </Grid>
                    <Grid style={{ display: 'flex', alignItems: 'center' }}>
                      <div style={{ marginLeft: '10px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('Subject Type')}</Typography>
                        <div style={{ display: 'flex', alignItems: 'center' }}>
                          <GroupIcon fontSize='large' color="disabled" />
                          <Typography style={{ marginLeft: '10px' }} align="center" variant="subtitle1">
                            {t('Lorem Ipsum')}
                          </Typography>
                        </div>
                      </div>
                    </Grid>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Grid style={{ display: 'flex', alignItems: 'center', marginBottom: '20px' }}>
                      <div style={{ marginLeft: '10px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('ID')}</Typography>
                        <Typography align="left" variant="subtitle1">{t('Lorem Ipsum')}</Typography>
                      </div>
                    </Grid>
                    <Grid style={{ display: 'flex', alignItems: 'center' }}>
                      <div style={{ marginLeft: '10px' }}>
                        <Typography align="left" color="textSecondary" variant="h3">{t('Asset')}</Typography>
                        <Typography align="left" variant="subtitle1">{t('Lorem Ipsum')}</Typography>
                      </div>
                    </Grid>
                  </Grid>

                </Grid>
                <Grid container={true}>
                  <Grid item={true} xs={12}>
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
                          {t('Description')}
                        </div>
                      </div>
                    </div>
                  </Grid>
                </Grid>
                <Grid style={{ marginTop: '20px' }} container={true}>
                  <CyioCoreobjectExternalReferences />
                </Grid>
                <Grid style={{ marginTop: '20px' }} container={true}>
                  <CyioCoreObjectOrCyioCoreRelationshipNoteCard
                    cyioCoreObjectId={remediationId}
                  // data={props}
                  // marginTop={marginTop}
                  />
                </Grid>
              </AccordionDetails>
            </Accordion>
            <div style={{ marginTop: '30px' }}>
              <RequiredAssetPopover remediationId={remediationId} />
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

RequiredAssetsLinesContainer.propTypes = {
  remediationId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  relay: PropTypes.object,
};

export const requiredAssetsLinesQuery = graphql`
  query RequiredAssetsLinesQuery($count: Int!, $id: ID!) {
    ...RequiredAssetsLines_data
      @arguments(count: $count, id: $id)
  }
`;

const RequiredAssetsLines = createPaginationContainer(
  RequiredAssetsLinesContainer,
  {
    data: graphql`
      fragment RequiredAssetsLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "ID!" }
      ) {
        itAsset(id: $id) {
          id
          external_references(first: $count)
            @connection(key: "Pagination_external_references") {
            edges {
              node {
                id
                source_name
                description
                url
                hashes {
                  value
                }
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
      return props.data && props.data.itAsset.external_references;
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
    query: requiredAssetsLinesQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(RequiredAssetsLines);
