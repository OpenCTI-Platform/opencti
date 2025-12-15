import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { ArrowRightAlt, EditOutlined, ExpandLessOutlined, ExpandMoreOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Divider from '@mui/material/Divider';
import Chip from '@mui/material/Chip';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import { DraftChip } from '../draft/DraftChip';
import { itemColor } from '../../../../utils/Colors';
import { resolveLink } from '../../../../utils/Entity';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipEdition, { stixCoreRelationshipEditionDeleteMutation } from './StixCoreRelationshipEdition';
import { commitMutation } from '../../../../relay/environment';
import { stixCoreRelationshipEditionFocus } from './StixCoreRelationshipEditionOverview';
import StixCoreRelationshipStixCoreRelationships from './StixCoreRelationshipStixCoreRelationships';
import ItemAuthor from '../../../../components/ItemAuthor';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreRelationshipInference from './StixCoreRelationshipInference';
import StixCoreRelationshipExternalReferences from '../../analyses/external_references/StixCoreRelationshipExternalReferences';
import StixCoreRelationshipLatestHistory from './StixCoreRelationshipLatestHistory';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemStatus from '../../../../components/ItemStatus';
import ItemCreators from '../../../../components/ItemCreators';
import StixCoreRelationshipSharing from './StixCoreRelationshipSharing';
import ItemMarkings from '../../../../components/ItemMarkings';
import StixCoreObjectKillChainPhasesView from '../stix_core_objects/StixCoreObjectKillChainPhasesView';
import StixCoreObjectOrStixRelationshipLastContainers from '../containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreRelationshipObjectLabelsView from './StixCoreRelationshipLabelsView';
import Transition from '../../../../components/Transition';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import withRouter from '../../../../utils/compat_router/withRouter';

const styles = (theme) => ({
  container: {
    margin: 0,
    position: 'relative',
  },
  gridContainer: {
    marginBottom: 20,
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  editButtonWithPadding: {
    position: 'fixed',
    bottom: 30,
    right: 220,
  },
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
    borderRadius: 10,
  },
  itemHeader: {
    padding: '10px 0 10px 0',
  },
  icon: {
    position: 'absolute',
    top: 8,
    left: 5,
    fontSize: 8,
  },
  type: {
    width: '100%',
    textAlign: 'center',
    color: theme.palette.text.primary,
    fontSize: 11,
  },
  content: {
    width: '100%',
    padding: '0 10px 0 10px',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: theme.palette.text.primary,
    textAlign: 'center',
    wordBreak: 'break-word',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
  middle: {
    margin: '0 auto',
    paddingTop: 20,
    width: 200,
    textAlign: 'center',
    color: theme.palette.text.primary,
  },
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
  paperWithoutPadding: {
    marginTop: theme.spacing(1),
    padding: 0,
    borderRadius: 4,
  },
  paperRelationships: {
    marginTop: theme.spacing(3),
    position: 'relative',
    padding: 0,
    borderRadius: 4,
  },
  paperReports: {
    minHeight: '100%',
    marginTop: theme.spacing(1),
    padding: '25px 15px 15px 15px',
    borderRadius: 4,
  },
  buttonExpand: {
    position: 'absolute',
    left: 0,
    bottom: 0,
    width: '100%',
    height: 25,
    color: theme.palette.primary.main,
    backgroundColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    '&:hover': {
      backgroundColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .2)'
          : 'rgba(0, 0, 0, .2)',
    },
  },
  chipInList: {
    fontSize: 15,
    height: 30,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
});

class StixCoreRelationshipContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { openEdit: false, openDelete: false, expanded: false };
  }

  handleToggleExpand() {
    this.setState({ expanded: !this.state.expanded });
  }

  handleOpenEdition() {
    this.setState({ openEdit: true });
  }

  handleCloseEdition() {
    const { stixCoreRelationship } = this.props;
    commitMutation({
      mutation: stixCoreRelationshipEditionFocus,
      variables: {
        id: stixCoreRelationship.id,
        input: { focusOn: '' },
      },
    });
    this.setState({ openEdit: false });
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  submitDelete() {
    this.setState({ deleting: true });
    const {
      location,
      stixCoreRelationship,
    } = this.props;
    commitMutation({
      mutation: stixCoreRelationshipEditionDeleteMutation,
      variables: {
        id: stixCoreRelationship.id,
      },
      onCompleted: () => {
        this.handleCloseEdition();
        this.props.navigate(
          location.pathname.replace(`/relations/${stixCoreRelationship.id}`, ''),
        );
      },
    });
  }

  render() {
    const { t, fldt, nsdt, classes, stixCoreRelationship } = this.props;
    const { expanded } = this.state;
    const { from } = stixCoreRelationship;
    const { to } = stixCoreRelationship;
    const fromRestricted = from === null;

    const linkFrom = from
      ? from.relationship_type
        ? `${resolveLink(from.from.entity_type)}/${
          from.from.id
        }/knowledge/relations`
        : resolveLink(from.entity_type)
      : '';
    const toRestricted = to === null;

    const linkTo = to
      ? to.relationship_type
        ? `${resolveLink(to.from.entity_type)}/${
          to.from.id
        }/knowledge/relations`
        : resolveLink(to.entity_type)
      : '';
    const expandable = stixCoreRelationship.x_opencti_inferences
      && stixCoreRelationship.x_opencti_inferences.length > 1;
    return (
      <div className={classes.container}>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item xs={6}>
            <Typography variant="h4" gutterBottom={true} sx={{ float: 'left' }}>
              {t('Relationship')}{stixCoreRelationship.draftVersion && (<DraftChip />)}
            </Typography>
            {!stixCoreRelationship.is_inferred && (
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <IconButton
                  onClick={this.handleOpenEdition.bind(this)}
                  sx={{ margin: '-15px 0px 0px -2px', float: 'left' }}
                >
                  <EditOutlined fontSize="small" />
                </IconButton>
                <StixCoreRelationshipEdition
                  open={this.state.openEdit}
                  stixCoreRelationshipId={stixCoreRelationship.id}
                  handleClose={this.handleCloseEdition.bind(this)}
                  handleDelete={this.handleOpenDelete.bind(this)}
                />
              </Security>
            )}
            <Paper
              classes={{ root: classes.paperRelationships }}
              variant="outlined"
              className="paper-for-grid"
            >
              <Link to={!fromRestricted ? `${linkFrom}/${from.id}` : '#'}>
                <div
                  className={classes.item}
                  style={{
                    border: `2px solid ${itemColor(
                      !fromRestricted ? from.entity_type : 'Restricted',
                    )}`,
                    top: 20,
                    left: 20,
                  }}
                >
                  <div
                    className={classes.itemHeader}
                    style={{
                      borderBottom: `1px solid ${itemColor(
                        !fromRestricted ? from.entity_type : 'Restricted',
                      )}`,
                    }}
                  >
                    <div className={classes.icon}>
                      <ItemIcon
                        type={!fromRestricted ? from.entity_type : 'Restricted'}
                        color={itemColor(
                          !fromRestricted ? from.entity_type : 'Restricted',
                        )}
                        size="small"
                      />
                    </div>
                    <div className={classes.type}>
                      { }
                      {!fromRestricted
                        ? from.relationship_type
                          ? t('Relationship')
                          : t(`entity_${from.entity_type}`)
                        : t('Restricted')}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {!fromRestricted
                        ? truncate(
                            getMainRepresentative(from) !== 'Unknown'
                              ? getMainRepresentative(from)
                              : t(`relationship_${from.entity_type}`),
                            50,
                          )
                        : t('Restricted')}
                      {!fromRestricted && stixCoreRelationship.from.draftVersion && (<DraftChip />)}
                    </span>
                  </div>
                </div>
              </Link>
              <div className={classes.middle}>
                <ArrowRightAlt fontSize="large" />
                <br />
                <Chip
                  variant="outlined"
                  classes={{ root: classes.chipInList }}
                  color="primary"
                  label={t(
                    `relationship_${stixCoreRelationship.relationship_type}`,
                  )}
                />
              </div>
              <Link to={!toRestricted ? `${linkTo}/${to.id}` : '#'}>
                <div
                  className={classes.item}
                  style={{
                    border: `2px solid ${itemColor(
                      !toRestricted ? to.entity_type : 'Restricted',
                    )}`,
                    top: 20,
                    right: 20,
                  }}
                >
                  <div
                    className={classes.itemHeader}
                    style={{
                      borderBottom: `1px solid ${itemColor(
                        !toRestricted ? to.entity_type : 'Restricted',
                      )}`,
                    }}
                  >
                    <div className={classes.icon}>
                      <ItemIcon
                        type={!toRestricted ? to.entity_type : 'Unknown'}
                        color={itemColor(
                          !toRestricted ? to.entity_type : 'Restricted',
                        )}
                        size="small"
                      />
                    </div>
                    <div className={classes.type}>
                      {

                        !toRestricted
                          ? to.relationship_type
                            ? t('Relationship')
                            : t(`entity_${to.entity_type}`)
                          : t('Restricted')
                      }
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {!toRestricted
                        ? truncate(
                            getMainRepresentative(to) !== 'Unknown'
                              ? getMainRepresentative(to)
                              : t(`relationship_${to.entity_type}`),
                            50,
                          )
                        : t('Restricted')}
                      {!toRestricted && stixCoreRelationship.to.draftVersion && (<DraftChip />)}
                    </span>
                  </div>
                </div>
              </Link>
              <Divider style={{ marginTop: 30 }} />
              <div style={{ padding: 15 }}>
                <Grid container={true} spacing={3}>
                  <Grid item xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Marking')}
                    </Typography>
                    <ItemMarkings markingDefinitions={stixCoreRelationship.objectMarking ?? []} />
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('Start time')}
                    </Typography>
                    {nsdt(stixCoreRelationship.start_time)}
                    <Typography
                      variant="h3"
                      style={{ marginTop: 20 }}
                      gutterBottom={true}
                    >
                      {t('Stop time')}
                    </Typography>
                    {nsdt(stixCoreRelationship.stop_time)}
                  </Grid>
                  <Grid item xs={6}>
                    <StixCoreRelationshipSharing
                      elementId={stixCoreRelationship.id}
                    />
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('Description')}
                    </Typography>
                    <MarkdownDisplay
                      content={
                        stixCoreRelationship.x_opencti_inferences !== null ? (
                          t('Inferred knowledge')
                        ) : (
                          stixCoreRelationship.description
                        )
                      }
                      remarkGfmPlugin={true}
                      commonmark={true}
                    />
                    <StixCoreObjectKillChainPhasesView
                      killChainPhases={
                        stixCoreRelationship.killChainPhases
                      }
                    />
                  </Grid>
                </Grid>
              </div>
            </Paper>
          </Grid>
          <Grid item xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} className="paper-for-grid" variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Confidence level')}
                  </Typography>
                  <ItemConfidence
                    confidence={stixCoreRelationship.confidence}
                    entityType="stix-core-relationship"
                  />
                  {stixCoreRelationship.x_opencti_inferences === null && (
                    <div>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        style={{ marginTop: 20 }}
                      >
                        {t('Author')}
                      </Typography>
                      <ItemAuthor
                        createdBy={R.propOr(
                          null,
                          'createdBy',
                          stixCoreRelationship,
                        )}
                      />
                    </div>
                  )}
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Original creation date')}
                  </Typography>
                  {nsdt(stixCoreRelationship.created)}
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Modification date')}
                  </Typography>
                  {nsdt(stixCoreRelationship.updated_at)}
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Processing status')}
                  </Typography>
                  <ItemStatus
                    status={stixCoreRelationship.status}
                    disabled={!stixCoreRelationship.workflowEnabled}
                  />
                  <StixCoreRelationshipObjectLabelsView
                    labels={stixCoreRelationship.objectLabel}
                    id={stixCoreRelationship.id}
                    marginTop={20}
                  />
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Platform creation date')}
                  </Typography>
                  {fldt(stixCoreRelationship.created_at)}
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Creators')}
                  </Typography>
                  <ItemCreators
                    creators={stixCoreRelationship.creators ?? []}
                  />
                </Grid>
              </Grid>
            </Paper>
          </Grid>
          {stixCoreRelationship.x_opencti_inferences == null && (
            <>
              <Grid item xs={6}>
                <StixCoreRelationshipStixCoreRelationships
                  entityId={stixCoreRelationship.id}
                />
              </Grid>
              <Grid item xs={6}>
                <StixCoreObjectOrStixRelationshipLastContainers
                  stixCoreObjectOrStixRelationshipId={stixCoreRelationship.id}
                />
              </Grid>
              <Grid item xs={6}>
                <StixCoreRelationshipExternalReferences
                  stixCoreRelationshipId={stixCoreRelationship.id}
                />
              </Grid>
              <Grid item xs={6}>
                <StixCoreRelationshipLatestHistory
                  stixCoreRelationshipId={stixCoreRelationship.id}
                />
              </Grid>
              <Grid item xs={12}>
                <StixCoreObjectOrStixCoreRelationshipNotes
                  stixCoreObjectOrStixCoreRelationshipId={stixCoreRelationship.id}
                  isRelationship={true}
                  defaultMarkings={stixCoreRelationship.objectMarking ?? []}
                />
              </Grid>
            </>
          )}
        </Grid>
        <div>
          {stixCoreRelationship.x_opencti_inferences !== null && (
            <div style={{ margin: '50px 0 0 0' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Inference explanation')} (
                {stixCoreRelationship.x_opencti_inferences.length})
              </Typography>
              {R.take(
                expanded ? 200 : 1,
                stixCoreRelationship.x_opencti_inferences,
              ).map((inference) => (
                <StixCoreRelationshipInference
                  key={inference.rule.id}
                  inference={inference}
                  stixRelationship={stixCoreRelationship}
                />
              ))}
              {expandable && (
                <IconButton
                  variant="tertiary"
                  size="small"
                  onClick={this.handleToggleExpand.bind(this)}
                  classes={{ root: classes.buttonExpand }}
                >
                  {expanded ? (
                    <ExpandLessOutlined />
                  ) : (
                    <ExpandMoreOutlined />
                  )}
                </IconButton>
              )}
            </div>
          )}
        </div>
        <Dialog
          open={this.state.displayDelete}
          slotProps={{ paper: { elevation: 1 } }}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogTitle>
            {t('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this relationship?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={this.submitDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Confirm')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixCoreRelationshipContainer.propTypes = {
  entityId: PropTypes.string,
  stixCoreRelationship: PropTypes.object,
  paddingRight: PropTypes.bool,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
  match: PropTypes.object,
  navigate: PropTypes.func,
  location: PropTypes.object,
};

const StixCoreRelationshipOverview = createFragmentContainer(
  StixCoreRelationshipContainer,
  {
    stixCoreRelationship: graphql`
      fragment StixCoreRelationshipOverview_stixCoreRelationship on StixCoreRelationship {
        id
        draftVersion {
          draft_id
          draft_operation
        }
        entity_type
        parent_types
        relationship_type
        confidence
        created
        start_time
        stop_time
        description
        fromRole
        toRole
        created_at
        updated_at
        is_inferred
        creators {
          id
          name
        }
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
        killChainPhases {
          id
          entity_type
          kill_chain_name
          phase_name
          x_opencti_order
        }
        x_opencti_inferences {
          rule {
            id
            name
            description
          }
          explanation {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
              created_at
            }
            ... on AttackPattern {
              name
            }
            ... on Campaign {
              name
            }
            ... on CourseOfAction {
              name
            }
            ... on Individual {
              name
            }
            ... on Organization {
              name
            }
            ... on Sector {
              name
            }
            ... on System {
              name
            }
            ... on Indicator {
              name
            }
            ... on Infrastructure {
              name
            }
            ... on IntrusionSet {
              name
            }
            ... on Position {
              name
            }
            ... on City {
              name
            }
            ... on AdministrativeArea {
              name
            }
            ... on Country {
              name
            }
            ... on Region {
              name
            }
            ... on Malware {
              name
            }
            ... on MalwareAnalysis {
              result_name
            }
            ... on ThreatActor {
              name
            }
            ... on Tool {
              name
            }
            ... on Vulnerability {
              name
            }
            ... on Incident {
              name
            }
            ... on Event {
              name
            }
            ... on Channel {
              name
            }
            ... on Narrative {
              name
            }
            ... on Language {
              name
            }
            ... on DataComponent {
              name
            }
            ... on DataSource {
              name
            }
            ... on Case {
              name
            }
            ... on StixCoreRelationship {
              id
              relationship_type
              created_at
              start_time
              stop_time
              created
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreObject {
                  created_at
                }
                ... on StixCoreRelationship {
                  relationship_type
                  created_at
                  start_time
                  stop_time
                  created
                }
                ... on AttackPattern {
                  name
                }
                ... on Campaign {
                  name
                }
                ... on CourseOfAction {
                  name
                }
                ... on Individual {
                  name
                }
                ... on Organization {
                  name
                }
                ... on Sector {
                  name
                }
                ... on System {
                  name
                }
                ... on Indicator {
                  name
                }
                ... on Infrastructure {
                  name
                }
                ... on IntrusionSet {
                  name
                }
                ... on Position {
                  name
                }
                ... on City {
                  name
                }
                ... on AdministrativeArea {
                  name
                }
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
                }
                ... on MalwareAnalysis {
                  result_name
                }
                ... on ThreatActor {
                  name
                }
                ... on Tool {
                  name
                }
                ... on Vulnerability {
                  name
                }
                ... on Incident {
                  name
                }
                ... on Event {
                  name
                }
                ... on Channel {
                  name
                }
                ... on Narrative {
                  name
                }
                ... on Language {
                  name
                }
                ... on DataComponent {
                  name
                }
                ... on DataSource {
                  name
                }
                ... on Case {
                  name
                }
                ... on StixCyberObservable {
                  observable_value
                }
                ... on ObservedData {
                  name
                  objects(first: 1) {
                    edges {
                      node {
                        ... on StixCoreObject {
                          id
                          entity_type
                          parent_types
                          created_at
                          createdBy {
                            ... on Identity {
                              id
                              name
                              entity_type
                            }
                          }
                          objectMarking {
                            id
                            definition_type
                            definition
                            x_opencti_order
                            x_opencti_color
                          }
                        }
                        ... on AttackPattern {
                          name
                          description
                          x_mitre_id
                        }
                        ... on Campaign {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Note {
                          attribute_abstract
                        }
                        ... on ObservedData {
                          name
                          first_observed
                          last_observed
                        }
                        ... on Opinion {
                          opinion
                        }
                        ... on Report {
                          name
                          description
                          published
                        }
                        ... on Grouping {
                          name
                          description
                        }
                        ... on CourseOfAction {
                          name
                          description
                        }
                        ... on Individual {
                          name
                          description
                        }
                        ... on Organization {
                          name
                          description
                        }
                        ... on Sector {
                          name
                          description
                        }
                        ... on System {
                          name
                          description
                        }
                        ... on Indicator {
                          name
                          description
                          valid_from
                        }
                        ... on Infrastructure {
                          name
                          description
                        }
                        ... on IntrusionSet {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Position {
                          name
                          description
                        }
                        ... on City {
                          name
                          description
                        }
                        ... on AdministrativeArea {
                          name
                          description
                        }
                        ... on Country {
                          name
                          description
                        }
                        ... on Region {
                          name
                          description
                        }
                        ... on Malware {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on MalwareAnalysis {
                          result_name
                        }
                        ... on ThreatActor {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Tool {
                          name
                          description
                        }
                        ... on Vulnerability {
                          name
                          description
                        }
                        ... on Incident {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Event {
                          name
                          description
                          start_time
                          stop_time
                        }
                        ... on Channel {
                          name
                          description
                        }
                        ... on Narrative {
                          name
                          description
                        }
                        ... on Language {
                          name
                        }
                        ... on DataComponent {
                          name
                        }
                        ... on DataSource {
                          name
                        }
                        ... on Case {
                          name
                        }
                        ... on StixCyberObservable {
                          observable_value
                          x_opencti_description
                        }
                      }
                    }
                  }
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
                  start_time
                  stop_time
                  created
                  from {
                    ... on BasicObject {
                      id
                      entity_type
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
                    }
                    ... on AttackPattern {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on MalwareAnalysis {
                      result_name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                    ... on Event {
                      name
                    }
                    ... on Channel {
                      name
                    }
                    ... on Narrative {
                      name
                    }
                    ... on Language {
                      name
                    }
                    ... on DataComponent {
                      name
                    }
                    ... on DataSource {
                      name
                    }
                    ... on Case {
                      name
                    }
                  }
                  to {
                    ... on BasicObject {
                      id
                      entity_type
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
                    }
                    ... on AttackPattern {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on MalwareAnalysis {
                      result_name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                    ... on Event {
                      name
                    }
                    ... on Channel {
                      name
                    }
                    ... on Narrative {
                      name
                    }
                    ... on Language {
                      name
                    }
                    ... on DataComponent {
                      name
                    }
                    ... on DataSource {
                      name
                    }
                    ... on Case {
                      name
                    }
                    ... on ObservedData {
                      name
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition_type
                                definition
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
                            }
                            ... on Language {
                              name
                            }
                            ... on DataComponent {
                              name
                            }
                            ... on DataSource {
                              name
                            }
                            ... on Case {
                              name
                            }
                            ... on StixCyberObservable {
                              observable_value
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
              fromId
              fromType
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreObject {
                  created_at
                }
                ... on StixCoreRelationship {
                  created_at
                  relationship_type
                  start_time
                  stop_time
                  created
                }
                ... on AttackPattern {
                  name
                }
                ... on Campaign {
                  name
                }
                ... on CourseOfAction {
                  name
                }
                ... on Individual {
                  name
                }
                ... on Organization {
                  name
                }
                ... on Sector {
                  name
                }
                ... on System {
                  name
                }
                ... on Indicator {
                  name
                }
                ... on Infrastructure {
                  name
                }
                ... on IntrusionSet {
                  name
                }
                ... on Position {
                  name
                }
                ... on City {
                  name
                }
                ... on AdministrativeArea {
                  name
                }
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
                }
                ... on MalwareAnalysis {
                  result_name
                }
                ... on ThreatActor {
                  name
                }
                ... on Tool {
                  name
                }
                ... on Vulnerability {
                  name
                }
                ... on Incident {
                  name
                }
                ... on Event {
                  name
                }
                ... on Channel {
                  name
                }
                ... on Narrative {
                  name
                }
                ... on Language {
                  name
                }
                ... on DataComponent {
                  name
                }
                ... on DataSource {
                  name
                }
                ... on Case {
                  name
                }
                ... on StixCyberObservable {
                  observable_value
                }
                ... on ObservedData {
                  name
                  objects(first: 1) {
                    edges {
                      node {
                        ... on StixCoreObject {
                          id
                          entity_type
                          parent_types
                          created_at
                          createdBy {
                            ... on Identity {
                              id
                              name
                              entity_type
                            }
                          }
                          objectMarking {
                            id
                            definition
                            x_opencti_order
                            x_opencti_color
                          }
                        }
                        ... on AttackPattern {
                          name
                          description
                          x_mitre_id
                        }
                        ... on Campaign {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Note {
                          attribute_abstract
                        }
                        ... on ObservedData {
                          name
                          first_observed
                          last_observed
                        }
                        ... on Opinion {
                          opinion
                        }
                        ... on Report {
                          name
                          description
                          published
                        }
                        ... on Grouping {
                          name
                          description
                        }
                        ... on CourseOfAction {
                          name
                          description
                        }
                        ... on Individual {
                          name
                          description
                        }
                        ... on Organization {
                          name
                          description
                        }
                        ... on Sector {
                          name
                          description
                        }
                        ... on System {
                          name
                          description
                        }
                        ... on Indicator {
                          name
                          description
                          valid_from
                        }
                        ... on Infrastructure {
                          name
                          description
                        }
                        ... on IntrusionSet {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Position {
                          name
                          description
                        }
                        ... on City {
                          name
                          description
                        }
                        ... on AdministrativeArea {
                          name
                          description
                        }
                        ... on Country {
                          name
                          description
                        }
                        ... on Region {
                          name
                          description
                        }
                        ... on Malware {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on MalwareAnalysis {
                          result_name
                        }
                        ... on ThreatActor {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Tool {
                          name
                          description
                        }
                        ... on Vulnerability {
                          name
                          description
                        }
                        ... on Incident {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Event {
                          name
                          description
                          start_time
                          stop_time
                        }
                        ... on Channel {
                          name
                          description
                        }
                        ... on Narrative {
                          name
                          description
                        }
                        ... on Language {
                          name
                        }
                        ... on DataComponent {
                          name
                        }
                        ... on DataSource {
                          name
                        }
                        ... on Case {
                          name
                        }
                        ... on StixCyberObservable {
                          observable_value
                          x_opencti_description
                        }
                      }
                    }
                  }
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
                  start_time
                  stop_time
                  created
                  from {
                    ... on BasicObject {
                      id
                      entity_type
                      parent_types
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                      parent_types
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
                    }
                    ... on AttackPattern {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on MalwareAnalysis {
                      result_name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                    ... on Event {
                      name
                    }
                    ... on Channel {
                      name
                    }
                    ... on Narrative {
                      name
                    }
                    ... on Language {
                      name
                    }
                    ... on DataComponent {
                      name
                    }
                    ... on DataSource {
                      name
                    }
                    ... on Case {
                      name
                    }
                    ... on StixCyberObservable {
                      observable_value
                    }
                    ... on ObservedData {
                      name
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
                            }
                            ... on Language {
                              name
                            }
                            ... on DataComponent {
                              name
                            }
                            ... on DataSource {
                              name
                            }
                            ... on Case {
                              name
                            }
                            ... on StixCyberObservable {
                              observable_value
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                  to {
                    ... on BasicObject {
                      id
                      entity_type
                      parent_types
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                      parent_types
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
                    }
                    ... on AttackPattern {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on MalwareAnalysis {
                      result_name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                    ... on Event {
                      name
                    }
                    ... on Channel {
                      name
                    }
                    ... on Narrative {
                      name
                    }
                    ... on Language {
                      name
                    }
                    ... on DataComponent {
                      name
                    }
                    ... on DataSource {
                      name
                    }
                    ... on Case {
                      name
                    }
                    ... on StixCyberObservable {
                      observable_value
                    }
                    ... on ObservedData {
                      name
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
                            }
                            ... on Language {
                              name
                            }
                            ... on DataComponent {
                              name
                            }
                            ... on DataSource {
                              name
                            }
                            ... on Case {
                              name
                            }
                            ... on StixCyberObservable {
                              observable_value
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
              toId
              toType
            }
            ... on StixSightingRelationship {
              id
              created_at
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreObject {
                  created_at
                }
                ... on StixCoreRelationship {
                  relationship_type
                  created_at
                  start_time
                  stop_time
                  created
                }
                ... on AttackPattern {
                  name
                }
                ... on Campaign {
                  name
                }
                ... on CourseOfAction {
                  name
                }
                ... on Individual {
                  name
                }
                ... on Organization {
                  name
                }
                ... on Sector {
                  name
                }
                ... on System {
                  name
                }
                ... on Indicator {
                  name
                }
                ... on Infrastructure {
                  name
                }
                ... on IntrusionSet {
                  name
                }
                ... on Position {
                  name
                }
                ... on City {
                  name
                }
                ... on AdministrativeArea {
                  name
                }
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
                }
                ... on MalwareAnalysis {
                  result_name
                }
                ... on ThreatActor {
                  name
                }
                ... on Tool {
                  name
                }
                ... on Vulnerability {
                  name
                }
                ... on Incident {
                  name
                }
                ... on Event {
                  name
                }
                ... on Channel {
                  name
                }
                ... on Narrative {
                  name
                }
                ... on Language {
                  name
                }
                ... on DataComponent {
                  name
                }
                ... on DataSource {
                  name
                }
                ... on Case {
                  name
                }
                ... on StixCyberObservable {
                  observable_value
                }
                ... on ObservedData {
                  name
                  objects(first: 1) {
                    edges {
                      node {
                        ... on StixCoreObject {
                          id
                          entity_type
                          parent_types
                          created_at
                          createdBy {
                            ... on Identity {
                              id
                              name
                              entity_type
                            }
                          }
                          objectMarking {
                            id
                            definition
                            x_opencti_order
                            x_opencti_color
                          }
                        }
                        ... on AttackPattern {
                          name
                          description
                          x_mitre_id
                        }
                        ... on Campaign {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Note {
                          attribute_abstract
                        }
                        ... on ObservedData {
                          name
                          first_observed
                          last_observed
                        }
                        ... on Opinion {
                          opinion
                        }
                        ... on Report {
                          name
                          description
                          published
                        }
                        ... on Grouping {
                          name
                          description
                        }
                        ... on CourseOfAction {
                          name
                          description
                        }
                        ... on Individual {
                          name
                          description
                        }
                        ... on Organization {
                          name
                          description
                        }
                        ... on Sector {
                          name
                          description
                        }
                        ... on System {
                          name
                          description
                        }
                        ... on Indicator {
                          name
                          description
                          valid_from
                        }
                        ... on Infrastructure {
                          name
                          description
                        }
                        ... on IntrusionSet {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Position {
                          name
                          description
                        }
                        ... on City {
                          name
                          description
                        }
                        ... on AdministrativeArea {
                          name
                          description
                        }
                        ... on Country {
                          name
                          description
                        }
                        ... on Region {
                          name
                          description
                        }
                        ... on Malware {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on MalwareAnalysis {
                          result_name
                        }
                        ... on ThreatActor {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Tool {
                          name
                          description
                        }
                        ... on Vulnerability {
                          name
                          description
                        }
                        ... on Incident {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Event {
                          name
                          description
                          start_time
                          stop_time
                        }
                        ... on Channel {
                          name
                          description
                        }
                        ... on Narrative {
                          name
                          description
                        }
                        ... on Language {
                          name
                        }
                        ... on DataComponent {
                          name
                        }
                        ... on DataSource {
                          name
                        }
                        ... on Case {
                          name
                        }
                        ... on StixCyberObservable {
                          observable_value
                          x_opencti_description
                        }
                      }
                    }
                  }
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
                  start_time
                  stop_time
                  created
                  from {
                    ... on BasicObject {
                      id
                      entity_type
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
                    }
                    ... on AttackPattern {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on MalwareAnalysis {
                      result_name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                    ... on Event {
                      name
                    }
                    ... on Channel {
                      name
                    }
                    ... on Narrative {
                      name
                    }
                    ... on Language {
                      name
                    }
                    ... on DataComponent {
                      name
                    }
                    ... on DataSource {
                      name
                    }
                    ... on Case {
                      name
                    }
                  }
                  to {
                    ... on BasicObject {
                      id
                      entity_type
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
                    }
                    ... on AttackPattern {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on MalwareAnalysis {
                      result_name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                    ... on Event {
                      name
                    }
                    ... on Channel {
                      name
                    }
                    ... on Narrative {
                      name
                    }
                    ... on Language {
                      name
                    }
                    ... on DataComponent {
                      name
                    }
                    ... on DataSource {
                      name
                    }
                    ... on Case {
                      name
                    }
                    ... on ObservedData {
                      name
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
                            }
                            ... on Language {
                              name
                            }
                            ... on DataComponent {
                              name
                            }
                            ... on DataSource {
                              name
                            }
                            ... on Case {
                              name
                            }
                            ... on StixCyberObservable {
                              observable_value
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
              fromId
              fromType
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on BasicRelationship {
                  id
                  entity_type
                  parent_types
                }
                ... on StixCoreObject {
                  created_at
                }
                ... on StixCoreRelationship {
                  created_at
                  relationship_type
                  start_time
                  stop_time
                  created
                }
                ... on AttackPattern {
                  name
                }
                ... on Campaign {
                  name
                }
                ... on CourseOfAction {
                  name
                }
                ... on Individual {
                  name
                }
                ... on Organization {
                  name
                }
                ... on Sector {
                  name
                }
                ... on System {
                  name
                }
                ... on Indicator {
                  name
                }
                ... on Infrastructure {
                  name
                }
                ... on IntrusionSet {
                  name
                }
                ... on Position {
                  name
                }
                ... on City {
                  name
                }
                ... on AdministrativeArea {
                  name
                }
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
                }
                ... on MalwareAnalysis {
                  result_name
                }
                ... on ThreatActor {
                  name
                }
                ... on Tool {
                  name
                }
                ... on Vulnerability {
                  name
                }
                ... on Incident {
                  name
                }
                ... on Event {
                  name
                }
                ... on Channel {
                  name
                }
                ... on Narrative {
                  name
                }
                ... on Language {
                  name
                }
                ... on DataComponent {
                  name
                }
                ... on DataSource {
                  name
                }
                ... on Case {
                  name
                }
                ... on StixCyberObservable {
                  observable_value
                }
                ... on ObservedData {
                  name
                  objects(first: 1) {
                    edges {
                      node {
                        ... on StixCoreObject {
                          id
                          entity_type
                          parent_types
                          created_at
                          createdBy {
                            ... on Identity {
                              id
                              name
                              entity_type
                            }
                          }
                          objectMarking {
                            id
                            definition
                            x_opencti_order
                            x_opencti_color
                          }
                        }
                        ... on AttackPattern {
                          name
                          description
                          x_mitre_id
                        }
                        ... on Campaign {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Note {
                          attribute_abstract
                        }
                        ... on ObservedData {
                          name
                          first_observed
                          last_observed
                        }
                        ... on Opinion {
                          opinion
                        }
                        ... on Report {
                          name
                          description
                          published
                        }
                        ... on Grouping {
                          name
                          description
                        }
                        ... on CourseOfAction {
                          name
                          description
                        }
                        ... on Individual {
                          name
                          description
                        }
                        ... on Organization {
                          name
                          description
                        }
                        ... on Sector {
                          name
                          description
                        }
                        ... on System {
                          name
                          description
                        }
                        ... on Indicator {
                          name
                          description
                          valid_from
                        }
                        ... on Infrastructure {
                          name
                          description
                        }
                        ... on IntrusionSet {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Position {
                          name
                          description
                        }
                        ... on City {
                          name
                          description
                        }
                        ... on AdministrativeArea {
                          name
                          description
                        }
                        ... on Country {
                          name
                          description
                        }
                        ... on Region {
                          name
                          description
                        }
                        ... on Malware {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on MalwareAnalysis {
                          result_name
                        }
                        ... on ThreatActor {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Tool {
                          name
                          description
                        }
                        ... on Vulnerability {
                          name
                          description
                        }
                        ... on Incident {
                          name
                          description
                          first_seen
                          last_seen
                        }
                        ... on Event {
                          name
                          description
                          start_time
                          stop_time
                        }
                        ... on Channel {
                          name
                          description
                        }
                        ... on Narrative {
                          name
                          description
                        }
                        ... on Language {
                          name
                        }
                        ... on DataComponent {
                          name
                        }
                        ... on DataSource {
                          name
                        }
                        ... on Case {
                          name
                        }
                        ... on StixCyberObservable {
                          observable_value
                          x_opencti_description
                        }
                      }
                    }
                  }
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
                  start_time
                  stop_time
                  created
                  from {
                    ... on BasicObject {
                      id
                      entity_type
                      parent_types
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                      parent_types
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
                    }
                    ... on AttackPattern {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on MalwareAnalysis {
                      result_name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                    ... on Event {
                      name
                    }
                    ... on Channel {
                      name
                    }
                    ... on Narrative {
                      name
                    }
                    ... on Language {
                      name
                    }
                    ... on DataComponent {
                      name
                    }
                    ... on DataSource {
                      name
                    }
                    ... on Case {
                      name
                    }
                    ... on StixCyberObservable {
                      observable_value
                    }
                    ... on ObservedData {
                      name
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
                            }
                            ... on Language {
                              name
                            }
                            ... on DataComponent {
                              name
                            }
                            ... on DataSource {
                              name
                            }
                            ... on Case {
                              name
                            }
                            ... on StixCyberObservable {
                              observable_value
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                  to {
                    ... on BasicObject {
                      id
                      entity_type
                      parent_types
                    }
                    ... on BasicRelationship {
                      id
                      entity_type
                      parent_types
                    }
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      created_at
                      start_time
                      stop_time
                      created
                    }
                    ... on AttackPattern {
                      name
                    }
                    ... on Campaign {
                      name
                    }
                    ... on CourseOfAction {
                      name
                    }
                    ... on Individual {
                      name
                    }
                    ... on Organization {
                      name
                    }
                    ... on Sector {
                      name
                    }
                    ... on System {
                      name
                    }
                    ... on Indicator {
                      name
                    }
                    ... on Infrastructure {
                      name
                    }
                    ... on IntrusionSet {
                      name
                    }
                    ... on Position {
                      name
                    }
                    ... on City {
                      name
                    }
                    ... on AdministrativeArea {
                      name
                    }
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
                    }
                    ... on MalwareAnalysis {
                      result_name
                    }
                    ... on ThreatActor {
                      name
                    }
                    ... on Tool {
                      name
                    }
                    ... on Vulnerability {
                      name
                    }
                    ... on Incident {
                      name
                    }
                    ... on Event {
                      name
                    }
                    ... on Channel {
                      name
                    }
                    ... on Narrative {
                      name
                    }
                    ... on Language {
                      name
                    }
                    ... on DataComponent {
                      name
                    }
                    ... on DataSource {
                      name
                    }
                    ... on Case {
                      name
                    }
                    ... on StixCyberObservable {
                      observable_value
                    }
                    ... on ObservedData {
                      name
                      objects(first: 1) {
                        edges {
                          node {
                            ... on StixCoreObject {
                              id
                              entity_type
                              parent_types
                              created_at
                              createdBy {
                                ... on Identity {
                                  id
                                  name
                                  entity_type
                                }
                              }
                              objectMarking {
                                id
                                definition
                                x_opencti_order
                                x_opencti_color
                              }
                            }
                            ... on AttackPattern {
                              name
                              description
                              x_mitre_id
                            }
                            ... on Campaign {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Note {
                              attribute_abstract
                            }
                            ... on ObservedData {
                              name
                              first_observed
                              last_observed
                            }
                            ... on Opinion {
                              opinion
                            }
                            ... on Report {
                              name
                              description
                              published
                            }
                            ... on Grouping {
                              name
                              description
                            }
                            ... on CourseOfAction {
                              name
                              description
                            }
                            ... on Individual {
                              name
                              description
                            }
                            ... on Organization {
                              name
                              description
                            }
                            ... on Sector {
                              name
                              description
                            }
                            ... on System {
                              name
                              description
                            }
                            ... on Indicator {
                              name
                              description
                              valid_from
                            }
                            ... on Infrastructure {
                              name
                              description
                            }
                            ... on IntrusionSet {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Position {
                              name
                              description
                            }
                            ... on City {
                              name
                              description
                            }
                            ... on AdministrativeArea {
                              name
                              description
                            }
                            ... on Country {
                              name
                              description
                            }
                            ... on Region {
                              name
                              description
                            }
                            ... on Malware {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on MalwareAnalysis {
                              result_name
                            }
                            ... on ThreatActor {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Tool {
                              name
                              description
                            }
                            ... on Vulnerability {
                              name
                              description
                            }
                            ... on Incident {
                              name
                              description
                              first_seen
                              last_seen
                            }
                            ... on Event {
                              name
                              description
                              start_time
                              stop_time
                            }
                            ... on Channel {
                              name
                              description
                            }
                            ... on Narrative {
                              name
                              description
                            }
                            ... on Language {
                              name
                            }
                            ... on DataComponent {
                              name
                            }
                            ... on DataSource {
                              name
                            }
                            ... on Case {
                              name
                            }
                            ... on StixCyberObservable {
                              observable_value
                              x_opencti_description
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
              toId
              toType
            }
          }
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          id
          definition
          x_opencti_order
          x_opencti_color
        }
        objectLabel {
          id
          value
          color
        }
        from {
          ... on BasicObject {
            id
            entity_type
            parent_types
          }
          ... on BasicRelationship {
            id
            entity_type
            parent_types
          }
          ... on StixCoreObject {
            draftVersion {
              draft_id
              draft_operation
            }
            created_at
          }
          ... on StixCoreRelationship {
            draftVersion {
              draft_id
              draft_operation
            }
            created_at
            start_time
            stop_time
            created
          }
          ... on StixCyberObservable {
            observable_value
            representative {
              main
            }
          }
          ... on AttackPattern {
            name
          }
          ... on Campaign {
            name
          }
          ... on CourseOfAction {
            name
          }
          ... on Individual {
            name
          }
          ... on Organization {
            name
          }
          ... on Sector {
            name
          }
          ... on System {
            name
          }
          ... on Indicator {
            name
          }
          ... on Infrastructure {
            name
          }
          ... on IntrusionSet {
            name
          }
          ... on Position {
            name
          }
          ... on City {
            name
          }
          ... on AdministrativeArea {
            name
          }
          ... on Country {
            name
          }
          ... on Region {
            name
          }
          ... on Malware {
            name
          }
          ... on MalwareAnalysis {
            result_name
          }
          ... on ThreatActor {
            name
          }
          ... on Tool {
            name
          }
          ... on Vulnerability {
            name
          }
          ... on Incident {
            name
          }
          ... on Event {
            name
          }
          ... on Channel {
            name
          }
          ... on Narrative {
            name
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on StixDomainObject {
            representative {
              main
            }
          }
          ... on ObservedData {
            name
            objects(first: 1) {
              edges {
                node {
                  ... on StixCoreObject {
                    id
                    entity_type
                    parent_types
                    created_at
                    createdBy {
                      ... on Identity {
                        id
                        name
                        entity_type
                      }
                    }
                    objectMarking {
                      id
                      definition
                      x_opencti_order
                      x_opencti_color
                    }
                  }
                  ... on AttackPattern {
                    name
                    description
                    x_mitre_id
                  }
                  ... on Campaign {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Note {
                    attribute_abstract
                  }
                  ... on ObservedData {
                    name
                    first_observed
                    last_observed
                  }
                  ... on Opinion {
                    opinion
                  }
                  ... on Report {
                    name
                    description
                    published
                  }
                  ... on Grouping {
                    name
                    description
                  }
                  ... on CourseOfAction {
                    name
                    description
                  }
                  ... on Individual {
                    name
                    description
                  }
                  ... on Organization {
                    name
                    description
                  }
                  ... on Sector {
                    name
                    description
                  }
                  ... on System {
                    name
                    description
                  }
                  ... on Indicator {
                    name
                    description
                    valid_from
                  }
                  ... on Infrastructure {
                    name
                    description
                  }
                  ... on IntrusionSet {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Position {
                    name
                    description
                  }
                  ... on City {
                    name
                    description
                  }
                  ... on AdministrativeArea {
                    name
                  }
                  ... on Country {
                    name
                    description
                  }
                  ... on Region {
                    name
                    description
                  }
                  ... on Malware {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on MalwareAnalysis {
                    result_name
                  }
                  ... on ThreatActor {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Tool {
                    name
                    description
                  }
                  ... on Vulnerability {
                    name
                    description
                  }
                  ... on Incident {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Event {
                    name
                    description
                    start_time
                    stop_time
                  }
                  ... on Channel {
                    name
                    description
                  }
                  ... on Narrative {
                    name
                    description
                  }
                  ... on Language {
                    name
                  }
                  ... on DataComponent {
                    name
                  }
                  ... on DataSource {
                    name
                  }
                  ... on Case {
                    name
                  }
                  ... on StixCyberObservable {
                    observable_value
                    x_opencti_description
                  }
                }
              }
            }
          }
          ... on StixCoreRelationship {
            id
            entity_type
            relationship_type
            start_time
            stop_time
            created
            from {
              ... on BasicObject {
                id
                entity_type
              }
              ... on BasicRelationship {
                id
                entity_type
              }
              ... on StixCoreObject {
                created_at
              }
              ... on StixCoreRelationship {
                created_at
                start_time
                stop_time
                created
              }
              ... on StixCyberObservable {
                observable_value
                representative {
                  main
                }
              }
              ... on AttackPattern {
                name
              }
              ... on Campaign {
                name
              }
              ... on CourseOfAction {
                name
              }
              ... on Individual {
                name
              }
              ... on Organization {
                name
              }
              ... on Sector {
                name
              }
              ... on System {
                name
              }
              ... on Indicator {
                name
              }
              ... on Infrastructure {
                name
              }
              ... on IntrusionSet {
                name
              }
              ... on Position {
                name
              }
              ... on City {
                name
              }
              ... on AdministrativeArea {
                name
              }
              ... on Country {
                name
              }
              ... on Region {
                name
              }
              ... on Malware {
                name
              }
              ... on MalwareAnalysis {
                result_name
              }
              ... on ThreatActor {
                name
              }
              ... on Tool {
                name
              }
              ... on Vulnerability {
                name
              }
              ... on Incident {
                name
              }
              ... on Event {
                name
              }
              ... on Channel {
                name
              }
              ... on Narrative {
                name
              }
              ... on Language {
                name
              }
              ... on DataComponent {
                name
              }
              ... on DataSource {
                name
              }
              ... on Case {
                name
              }
            }
            to {
              ... on BasicObject {
                id
                entity_type
              }
              ... on BasicRelationship {
                id
                entity_type
              }
              ... on StixCoreObject {
                created_at
              }
              ... on StixCoreRelationship {
                created_at
                start_time
                stop_time
                created
              }
              ... on StixCyberObservable {
                observable_value
                representative {
                  main
                }
              }
              ... on AttackPattern {
                name
              }
              ... on Campaign {
                name
              }
              ... on CourseOfAction {
                name
              }
              ... on Individual {
                name
              }
              ... on Organization {
                name
              }
              ... on Sector {
                name
              }
              ... on System {
                name
              }
              ... on Indicator {
                name
              }
              ... on Infrastructure {
                name
              }
              ... on IntrusionSet {
                name
              }
              ... on Position {
                name
              }
              ... on City {
                name
              }
              ... on AdministrativeArea {
                name
              }
              ... on Country {
                name
              }
              ... on Region {
                name
              }
              ... on Malware {
                name
              }
              ... on MalwareAnalysis {
                result_name
              }
              ... on ThreatActor {
                name
              }
              ... on Tool {
                name
              }
              ... on Vulnerability {
                name
              }
              ... on Incident {
                name
              }
              ... on Event {
                name
              }
              ... on Channel {
                name
              }
              ... on Narrative {
                name
              }
              ... on Language {
                name
              }
              ... on DataComponent {
                name
              }
              ... on DataSource {
                name
              }
              ... on Case {
                name
              }
            }
          }
        }
        fromId
        fromType
        to {
          ... on BasicObject {
            id
            entity_type
            parent_types
          }
          ... on BasicRelationship {
            id
            entity_type
            parent_types
          }
          ... on StixCoreObject {
            draftVersion {
              draft_id
              draft_operation
            }
            created_at
          }
          ... on StixCoreRelationship {
            draftVersion {
              draft_id
              draft_operation
            }
            created_at
            start_time
            stop_time
            created
          }
          ... on AttackPattern {
            name
          }
          ... on Campaign {
            name
          }
          ... on CourseOfAction {
            name
          }
          ... on Individual {
            name
          }
          ... on Organization {
            name
          }
          ... on Sector {
            name
          }
          ... on System {
            name
          }
          ... on Indicator {
            name
          }
          ... on Infrastructure {
            name
          }
          ... on IntrusionSet {
            name
          }
          ... on Position {
            name
          }
          ... on City {
            name
          }
          ... on AdministrativeArea {
            name
          }
          ... on Country {
            name
          }
          ... on Region {
            name
          }
          ... on Malware {
            name
          }
          ... on MalwareAnalysis {
            result_name
          }
          ... on ThreatActor {
            name
          }
          ... on Tool {
            name
          }
          ... on Vulnerability {
            name
          }
          ... on Incident {
            name
          }
          ... on Event {
            name
          }
          ... on Channel {
            name
          }
          ... on Narrative {
            name
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on ObservedData {
            name
            objects(first: 1) {
              edges {
                node {
                  ... on StixCoreObject {
                    id
                    entity_type
                    parent_types
                    created_at
                    createdBy {
                      ... on Identity {
                        id
                        name
                        entity_type
                      }
                    }
                    objectMarking {
                      id
                      definition
                      x_opencti_order
                      x_opencti_color
                    }
                  }
                  ... on AttackPattern {
                    name
                    description
                    x_mitre_id
                  }
                  ... on Campaign {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Note {
                    attribute_abstract
                  }
                  ... on ObservedData {
                    name
                    first_observed
                    last_observed
                  }
                  ... on Opinion {
                    opinion
                  }
                  ... on Report {
                    name
                    description
                    published
                  }
                  ... on Grouping {
                    name
                    description
                  }
                  ... on CourseOfAction {
                    name
                    description
                  }
                  ... on Individual {
                    name
                    description
                  }
                  ... on Organization {
                    name
                    description
                  }
                  ... on Sector {
                    name
                    description
                  }
                  ... on System {
                    name
                    description
                  }
                  ... on Indicator {
                    name
                    description
                    valid_from
                  }
                  ... on Infrastructure {
                    name
                    description
                  }
                  ... on IntrusionSet {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Position {
                    name
                    description
                  }
                  ... on City {
                    name
                    description
                  }
                  ... on AdministrativeArea {
                    name
                    description
                  }
                  ... on Country {
                    name
                    description
                  }
                  ... on Region {
                    name
                    description
                  }
                  ... on Malware {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on MalwareAnalysis {
                    result_name
                  }
                  ... on ThreatActor {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Tool {
                    name
                    description
                  }
                  ... on Vulnerability {
                    name
                    description
                  }
                  ... on Incident {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Event {
                    name
                    start_time
                    stop_time
                  }
                  ... on Channel {
                    name
                  }
                  ... on Narrative {
                    name
                  }
                  ... on Language {
                    name
                  }
                  ... on DataComponent {
                    name
                  }
                  ... on DataSource {
                    name
                  }
                  ... on Case {
                    name
                  }
                  ... on StixCyberObservable {
                    observable_value
                    x_opencti_description
                  }
                }
              }
            }
          }
          ... on StixCoreRelationship {
            id
            entity_type
            relationship_type
            start_time
            stop_time
            created
            from {
              ... on BasicObject {
                id
                entity_type
                parent_types
              }
              ... on BasicRelationship {
                id
                entity_type
                parent_types
              }
              ... on AttackPattern {
                name
              }
              ... on Campaign {
                name
              }
              ... on CourseOfAction {
                name
              }
              ... on Individual {
                name
              }
              ... on Organization {
                name
              }
              ... on Sector {
                name
              }
              ... on System {
                name
              }
              ... on Indicator {
                name
              }
              ... on Infrastructure {
                name
              }
              ... on IntrusionSet {
                name
              }
              ... on Position {
                name
              }
              ... on City {
                name
              }
              ... on AdministrativeArea {
                name
              }
              ... on Country {
                name
              }
              ... on Region {
                name
              }
              ... on Malware {
                name
              }
              ... on MalwareAnalysis {
                result_name
              }
              ... on ThreatActor {
                name
              }
              ... on Tool {
                name
              }
              ... on Vulnerability {
                name
              }
              ... on Incident {
                name
              }
              ... on Event {
                name
              }
              ... on Channel {
                name
              }
              ... on Narrative {
                name
              }
              ... on Language {
                name
              }
              ... on DataComponent {
                name
              }
              ... on DataSource {
                name
              }
              ... on Case {
                name
              }
              ... on StixCyberObservable {
                observable_value
              }
            }
            to {
              ... on BasicObject {
                id
                entity_type
                parent_types
              }
              ... on BasicRelationship {
                id
                entity_type
                parent_types
              }
              ... on AttackPattern {
                name
              }
              ... on Campaign {
                name
              }
              ... on CourseOfAction {
                name
              }
              ... on Individual {
                name
              }
              ... on Organization {
                name
              }
              ... on Sector {
                name
              }
              ... on System {
                name
              }
              ... on Indicator {
                name
              }
              ... on Infrastructure {
                name
              }
              ... on IntrusionSet {
                name
              }
              ... on Position {
                name
              }
              ... on City {
                name
              }
              ... on AdministrativeArea {
                name
              }
              ... on Country {
                name
              }
              ... on Region {
                name
              }
              ... on Malware {
                name
              }
              ... on MalwareAnalysis {
                result_name
              }
              ... on ThreatActor {
                name
              }
              ... on Tool {
                name
              }
              ... on Vulnerability {
                name
              }
              ... on Incident {
                name
              }
              ... on Event {
                name
              }
              ... on Channel {
                name
              }
              ... on Narrative {
                name
              }
              ... on Language {
                name
              }
              ... on DataComponent {
                name
              }
              ... on DataSource {
                name
              }
              ... on Case {
                name
              }
              ... on StixCyberObservable {
                observable_value
              }
            }
          }
        }
        toId
        toType
      }
    `,
  },
);

export default R.compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(StixCoreRelationshipOverview);
