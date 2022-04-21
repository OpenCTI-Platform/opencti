/* eslint-disable */
/* refactor */
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
// import { interval } from 'rxjs';
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
// import { FIVE_SECONDS } from '../../../../../utils/Time';
import FileUploader from '../../../common/files/FileUploader';
import RelatedTaskPopover from './RelatedTaskPopover';
import CyioCoreobjectExternalReferences from '../../../analysis/external_references/CyioCoreObjectExternalReferences';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import RelatedTaskLine from './RelatedTaskLine';

// const interval$ = interval(FIVE_SECONDS);

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
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
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
      t, classes, remediationId, data, refreshQuery, history,
    } = this.props;
    const { expanded } = this.state;
    const relatedTaskData = data.riskResponse;
    // const externalReferencesEdges = data.riskResponse.external_references.edges;
    // const expandable = externalReferencesEdges.length > 7;
    console.log('RelatedTasksData', data);
    const relatedTasksEdges = R.pathOr([], ['tasks'], data.riskResponse);
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
              relatedTaskData={relatedTaskData}
              display={true}
              contextual={true}
              history={history}
              refreshQuery={refreshQuery}
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
          {relatedTasksEdges.map((relatedTask, i) => (
            <RelatedTaskLine
              remediationId={remediationId}
              key={relatedTask.id}
              data={relatedTask}
              refreshQuery={refreshQuery}
              relatedTaskData={relatedTaskData}
            />
          ))}
        </Paper>
        <Dialog
          open={this.state.displayDialog}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDialog.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to remove this related task?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              onClick={this.handleCloseDialog.bind(this)}
              disabled={this.state.removing}
              variant="outlined"
              size="small"
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleRemoval.bind(this)}
              color="primary"
              disabled={this.state.removing}
              variant="contained"
              size="small"
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
  refreshQuery: PropTypes.func,
  relay: PropTypes.object,
};

export const RelatedTasksLinesQuery = graphql`
  query RelatedTasksLinesQuery($id: ID!) {
    ...RelatedTasksLines_data
      @arguments(id: $id)
  }
`;

const RelatedTasksLines = createFragmentContainer(
  RelatedTasksLinesContainer,
  {
    data: graphql`
      fragment RelatedTasksLines_data on Query
      @argumentDefinitions(
        id: { type: "ID!" }
      ) {
        riskResponse(id: $id) {
          __typename
          id
          links {
            __typename
            id
            # created
            # modified
            external_id
            source_name
            description
            entity_type
            url
            media_type
          }
          remarks {
            __typename
            id
            abstract
            content
            authors
            entity_type
          }
          tasks {   # Related Tasks
            id
            task_type
            name
            description
          }
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(RelatedTasksLines);
