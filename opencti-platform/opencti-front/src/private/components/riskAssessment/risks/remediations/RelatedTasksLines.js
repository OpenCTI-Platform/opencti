/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../../components/i18n';
import RelatedTaskCreation from './RelatedTaskCreation';
import RelatedTaskLine from './RelatedTaskLine';

// const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
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
      t, classes, remediationId, data, refreshQuery, history, fromType, toType,
    } = this.props;
    const { expanded } = this.state;
    const relatedTaskData = data.riskResponse;
    const relatedTasksEdges = R.pathOr([], ['tasks'], data.riskResponse);
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
            <RelatedTaskCreation
              relatedTaskData={relatedTaskData}
              display={true}
              contextual={true}
              fromType={fromType}
              toType={toType}
              history={history}
              refreshQuery={refreshQuery}
              remediationId={remediationId}
            // stixCoreObjectOrStixCoreRelationshipId={remediationId}
            // stixCoreObjectOrStixCoreRelationshipReferences={
            //   data.riskResponse.external_references.edges
            // }
            />
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
              relatedTaskId={relatedTask.id}
            />
          ))}
        </Paper>
        <Dialog
          open={this.state.displayDialog}
          keepMounted={true}
          TransitionComponent={Transition}
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
  toType: PropTypes.string,
  fromType: PropTypes.string,
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
          tasks {   # Related Tasks
            __typename
            id
            task_type
            name
            description
            timing {
              ... on DateRangeTiming {
                start_date
                end_date
              }
            }
            task_dependencies {
              __typename
              id
              name
            }
            related_tasks {
              __typename
              id
              name
            }
            responsible_roles {
              id
              name
              parties {
                id
                party_type
                name
              }
              role {
                id
                name
                role_identifier
              }
            }
            associated_activities {
              __typename
              id
              activity_id {
                __typename
                id
                name
              }
            }
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
