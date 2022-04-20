import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer, createPaginationContainer } from 'react-relay';
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
import RiskTrackingLine from './RiskTrackingLine';

// const interval$ = interval(FIVE_SECONDS);

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
    height: '0px',
    padding: '0',
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
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class RiskTrackingLinesContainer extends Component {
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
      search: '',
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
      t, classes, riskId, data, history, refreshQuery,
    } = this.props;
    const riskLogEdges = R.pathOr([], ['risk_log', 'edges'], data);
    const { expanded, displayUpdate } = this.state;
    const riskStatusResponse = R.pipe(
      R.pathOr([], ['remediations']),
      R.map((n) => ({
        id: n.id,
        name: n.name,
      })),
    )(data);
    const expandable = riskLogEdges.length > 7;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <div style={{ height: '100%' }}>
        <div className={classes.cardContent}>
          <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
            {t('Risk Log')}
          </Typography>
          {/* <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 28 }} />}
        > */}
          <RiskLogCreation
            display={true}
            contextual={true}
            inputValue={this.state.search}
            paginationOptions={paginationOptions}
            riskId={riskId}
            refreshQuery={refreshQuery}
            data={data}
            history={history}
            riskStatusResponse={riskStatusResponse}
          // stixCoreObjectOrStixCoreRelationshipReferences={
          //   data.risk.risk_log.edges
          // }
          />
          {/* </Security> */}
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {(riskLogEdges.length > 0 ? (riskLogEdges.map((riskTrackingEdge, key) => {
            const riskLogItem = riskTrackingEdge.node;
            return <RiskTrackingLine
              history={history}
              node={riskLogItem}
              key={riskLogItem.id}
              refreshQuery={refreshQuery}
              riskId={riskId}
              riskStatusResponse={riskStatusResponse}
            />;
          }))
            : <div style={{ paddingTop: '20px', textAlign: 'center' }}>
              {t('No Record Found')}
            </div>
          )}
        </Paper>
      </div>
    );
  }
}

RiskTrackingLinesContainer.propTypes = {
  riskId: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  refreshQuery: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  relay: PropTypes.object,
};

export const RiskTrackingLinesQuery = graphql`
  query RiskTrackingLinesQuery($id: ID!) {
    risk(id: $id) {
      ...RiskTrackingLines_data
    }
  }
`;

const RiskTrackingLines = createFragmentContainer(
  RiskTrackingLinesContainer,
  {
    data: graphql`
      fragment RiskTrackingLines_data on Risk {
        id
        risk_log {
          edges {
            node {
              id
              entity_type
              entry_type     # used to determine icon
              name           # title
              description    # description under title
              logged_by {
                __typename
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
              # needed for expanded view
              event_start    # start date
              event_end      # end date
              status_change  # status change
              related_responses {
                id
                entity_type
                name
              }
            }
          }
        }
        remediations {
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
)(RiskTrackingLines);
