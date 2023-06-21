import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Fab from '@mui/material/Fab';
import { ArrowRightAlt, Edit } from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import Divider from '@mui/material/Divider';
import Button from '@mui/material/Button';
import { itemColor } from '../../../../utils/Colors';
import { resolveLink } from '../../../../utils/Entity';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixSightingRelationshipEdition, {
  stixSightingRelationshipEditionDeleteMutation,
} from './StixSightingRelationshipEdition';
import { commitMutation } from '../../../../relay/environment';
import { stixSightingRelationshipEditionFocus } from './StixSightingRelationshipEditionOverview';
import ItemAuthor from '../../../../components/ItemAuthor';
import StixSightingRelationshipInference from './StixSightingRelationshipInference';
import StixSightingRelationshipExternalReferences from '../../analysis/external_references/StixSightingRelationshipExternalReferences';
import StixSightingRelationshipLatestHistory from './StixSightingRelationshipLatestHistory';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ItemStatus from '../../../../components/ItemStatus';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixSightingRelationshipSharing from './StixSightingRelationshipSharing';
import ItemCreator from '../../../../components/ItemCreator';
import ItemMarkings from '../../../../components/ItemMarkings';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixSightingRelationshipLabelsView from './StixSightingRelationshipLabelsView';
import Transition from '../../../../components/Transition';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const styles = (theme) => ({
  container: {
    margin: 0,
    position: 'relative',
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
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  paperWithoutPadding: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  paperReports: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
  gridContainer: {
    marginBottom: 20,
  },
  number: {
    color: theme.palette.secondary.main,
    fontSize: 16,
    fontWeight: 800,
  },
  positive: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  negative: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  chipInList: {
    fontSize: 15,
    height: 30,
    textTransform: 'uppercase',
    borderRadius: 0,
  },
});

class StixSightingRelationshipContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { openEdit: false, openDelete: false };
  }

  handleOpenEdition() {
    this.setState({ openEdit: true });
  }

  handleCloseEdition() {
    const { stixSightingRelationship } = this.props;
    commitMutation({
      mutation: stixSightingRelationshipEditionFocus,
      variables: {
        id: stixSightingRelationship.id,
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
    const { location, stixSightingRelationship } = this.props;
    commitMutation({
      mutation: stixSightingRelationshipEditionDeleteMutation,
      variables: {
        id: stixSightingRelationship.id,
      },
      onCompleted: () => {
        this.handleCloseEdition();
        this.props.history.push(
          location.pathname.replace(
            `/sightings/${stixSightingRelationship.id}`,
            '',
          ),
        );
      },
    });
  }

  render() {
    const {
      t,
      n,
      fldt,
      nsdt,
      classes,
      stixSightingRelationship,
      paddingRight,
    } = this.props;
    const { from } = stixSightingRelationship;
    const { to } = stixSightingRelationship;
    const fromRestricted = from === null;
    // eslint-disable-next-line no-nested-ternary
    const linkFrom = from
      ? from.relationship_type
        ? `${resolveLink(from.from.entity_type)}/${
          from.from.id
        }/knowledge/relations`
        : resolveLink(from.entity_type)
      : '';
    const toRestricted = to === null;
    // eslint-disable-next-line no-nested-ternary
    const linkTo = to
      ? to.relationship_type
        ? `${resolveLink(to.from.entity_type)}/${
          to.from.id
        }/knowledge/relations`
        : resolveLink(to.entity_type)
      : '';
    return (
      <div className={classes.container}>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Relationship')}
            </Typography>
            <Paper
              classes={{ root: classes.paperWithoutPadding }}
              variant="outlined"
              style={{ position: 'relative' }}
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
                      {/* eslint-disable-next-line no-nested-ternary */}
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
                          from.name
                              || from.observable_value
                              || from.attribute_abstract
                              || from.content
                              || t(`relationship_${from.entity_type}`),
                          50,
                        )
                        : t('Restricted')}
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
                  label={t('sighted in/at')}
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
                      {/* eslint-disable-next-line no-nested-ternary */}
                      {!toRestricted
                        ? to.relationship_type
                          ? t('Relationship')
                          : t(`entity_${to.entity_type}`)
                        : 'Restricted'}
                    </div>
                  </div>
                  <div className={classes.content}>
                    <span className={classes.name}>
                      {!toRestricted
                        ? truncate(
                          to.name
                              || to.observable_value
                              || to.attribute_abstract
                              || to.content
                              || t(`relationship_${to.entity_type}`),
                          50,
                        )
                        : t('Restricted')}
                    </span>
                  </div>
                </div>
              </Link>
              <Divider style={{ marginTop: 30 }} />
              <div style={{ padding: 15 }}>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Marking')}
                    </Typography>
                    <ItemMarkings
                      markingDefinitionsEdges={
                        stixSightingRelationship.objectMarking.edges
                      }
                    />
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('First seen')}
                    </Typography>
                    {nsdt(stixSightingRelationship.first_seen)}
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('Last seen')}
                    </Typography>
                    {nsdt(stixSightingRelationship.last_seen)}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <div>
                      <StixSightingRelationshipSharing
                        elementId={stixSightingRelationship.id}
                        disabled={
                          stixSightingRelationship.x_opencti_inferences !== null
                        }
                      />
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        style={{ marginTop: 20 }}
                      >
                        {t('filter_x_opencti_negative')}
                      </Typography>
                      <Chip
                        classes={{
                          root: stixSightingRelationship.x_opencti_negative
                            ? classes.negative
                            : classes.positive,
                        }}
                        label={
                          stixSightingRelationship.x_opencti_negative
                            ? t('False positive')
                            : t('True positive')
                        }
                      />
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        style={{ marginTop: 20 }}
                      >
                        {t('Count')}
                      </Typography>
                      <span className={classes.number}>
                        {n(stixSightingRelationship.attribute_count)}
                      </span>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        style={{ marginTop: 20 }}
                      >
                        {t('Description')}
                      </Typography>
                      <MarkdownDisplay
                        content={
                          stixSightingRelationship.x_opencti_inferences
                          !== null ? (
                            <i>{t('Inferred knowledge')}</i>
                            ) : (
                              stixSightingRelationship.description
                            )
                        }
                        remarkGfmPlugin={true}
                        commonmark={true}
                      />
                    </div>
                  </Grid>
                </Grid>
              </div>
            </Paper>
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Confidence level')}
                  </Typography>
                  <ItemConfidence
                    confidence={stixSightingRelationship.confidence}
                    entityType={stixSightingRelationship.entity_type}
                  />
                  {stixSightingRelationship.x_opencti_inferences === null && (
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
                          stixSightingRelationship,
                        )}
                      />
                    </div>
                  )}
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Creation date')}
                  </Typography>
                  {nsdt(stixSightingRelationship.created)}
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Modification date')}
                  </Typography>
                  {nsdt(stixSightingRelationship.updated_at)}
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Processing status')}
                  </Typography>
                  <ItemStatus
                    status={stixSightingRelationship.status}
                    disabled={!stixSightingRelationship.workflowEnabled}
                  />
                  <StixSightingRelationshipLabelsView
                    labels={stixSightingRelationship.objectLabel}
                    id={stixSightingRelationship.id}
                    marginTop={20}
                  />
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Creation date (in this platform)')}
                  </Typography>
                  {fldt(stixSightingRelationship.created_at)}
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Creators')}
                  </Typography>
                  <div>
                    {(stixSightingRelationship.creators ?? []).map((c) => {
                      return (
                        <div
                          key={`creator-${c.id}`}
                          style={{ float: 'left', marginRight: '10px' }}
                        >
                          <ItemCreator creator={c} />
                        </div>
                      );
                    })}
                    <div style={{ clear: 'both' }} />
                  </div>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
        <div>
          {stixSightingRelationship.x_opencti_inferences !== null ? (
            <div style={{ marginTop: 40 }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Inference explanation')}
              </Typography>
              {stixSightingRelationship.x_opencti_inferences.map(
                (inference) => (
                  <StixSightingRelationshipInference
                    key={inference.rule.id}
                    inference={inference}
                    stixSightingRelationship={stixSightingRelationship}
                    paddingRight={paddingRight}
                  />
                ),
              )}
            </div>
          ) : (
            <div style={{ margin: '50px 0 0 0' }}>
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <StixCoreObjectOrStixRelationshipLastContainers
                    stixCoreObjectOrStixRelationshipId={
                      stixSightingRelationship.id
                    }
                  />
                </Grid>
              </Grid>
              <Grid container={true} spacing={3} style={{ marginTop: 25 }}>
                <Grid item={true} xs={6}>
                  <StixSightingRelationshipExternalReferences
                    stixSightingRelationshipId={stixSightingRelationship.id}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <StixSightingRelationshipLatestHistory
                    stixSightingRelationshipId={stixSightingRelationship.id}
                  />
                </Grid>
              </Grid>
              <StixCoreObjectOrStixCoreRelationshipNotes
                marginTop={55}
                stixCoreObjectOrStixCoreRelationshipId={
                  stixSightingRelationship.id
                }
                isRelationship={true}
                defaultMarkings={(
                  stixSightingRelationship.objectMarking?.edges ?? []
                ).map((edge) => edge.node)}
              />
            </div>
          )}
        </div>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Fab
            onClick={this.handleOpenEdition.bind(this)}
            color="secondary"
            aria-label="Edit"
            className={
              paddingRight ? classes.editButtonWithPadding : classes.editButton
            }
          >
            <Edit />
          </Fab>
          <StixSightingRelationshipEdition
            open={this.state.openEdit}
            stixSightingRelationshipId={stixSightingRelationship.id}
            inferred={stixSightingRelationship.x_opencti_inferences !== null}
            handleClose={this.handleCloseEdition.bind(this)}
            handleDelete={this.handleOpenDelete.bind(this)}
          />
        </Security>
        <Dialog
          open={this.state.displayDelete}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this sighting?')}
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
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixSightingRelationshipContainer.propTypes = {
  entityId: PropTypes.string,
  stixSightingRelationship: PropTypes.object,
  paddingRight: PropTypes.bool,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
};

const StixSightingRelationshipOverview = createFragmentContainer(
  StixSightingRelationshipContainer,
  {
    stixSightingRelationship: graphql`
      fragment StixSightingRelationshipOverview_stixSightingRelationship on StixSightingRelationship {
        id
        entity_type
        parent_types
        confidence
        created
        first_seen
        last_seen
        attribute_count
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
        x_opencti_negative
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
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
            ... on StixRefRelationship {
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
              }
            }
            ... on StixCoreObject {
              created_at
            }
            ... on StixCoreRelationship {
              relationship_type
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
                        edges {
                          node {
                            id
                            definition_type
                            definition
                            x_opencti_order
                            x_opencti_color
                          }
                        }
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
                    ... on ThreatActorGroup {
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
                    ... on StixCyberObservable {
                      observable_value
                      x_opencti_description
                    }
                  }
                }
              }
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
            ... on ThreatActorGroup {
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
            ... on StixCoreRelationship {
              id
              relationship_type
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
                ... on ThreatActorGroup {
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
                ... on StixCyberObservable {
                  observable_value
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
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
                      relationship_type
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
                    ... on ThreatActorGroup {
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
                      relationship_type
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
                    ... on ThreatActorGroup {
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
                ... on ThreatActorGroup {
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
                ... on StixCyberObservable {
                  observable_value
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  relationship_type
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
                    ... on ThreatActorGroup {
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
                    ... on StixCoreObject {
                      created_at
                    }
                    ... on StixCoreRelationship {
                      relationship_type
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
                    ... on ThreatActorGroup {
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
                    ... on StixCyberObservable {
                      observable_value
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
                ... on ThreatActorGroup {
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
                            edges {
                              node {
                                id
                                definition_type
                                definition
                                x_opencti_order
                                x_opencti_color
                              }
                            }
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
                        ... on ThreatActorGroup {
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
                    ... on ThreatActorGroup {
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
                    ... on ThreatActorGroup {
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
                                edges {
                                  node {
                                    id
                                    definition_type
                                    definition
                                    x_opencti_order
                                    x_opencti_color
                                  }
                                }
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
                            ... on ThreatActorGroup {
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
                ... on ThreatActorGroup {
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
                            edges {
                              node {
                                id
                                definition_type
                                definition
                                x_opencti_order
                                x_opencti_color
                              }
                            }
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
                        ... on ThreatActorGroup {
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
                    ... on ThreatActorGroup {
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
                                edges {
                                  node {
                                    id
                                    definition_type
                                    definition
                                    x_opencti_order
                                    x_opencti_color
                                  }
                                }
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
                            ... on ThreatActorGroup {
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
                    ... on ThreatActorGroup {
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
                                edges {
                                  node {
                                    id
                                    definition_type
                                    definition
                                    x_opencti_order
                                    x_opencti_color
                                  }
                                }
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
                            ... on ThreatActorGroup {
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
          edges {
            node {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
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
            created_at
          }
          ... on StixSightingRelationship {
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
                      edges {
                        node {
                          id
                          definition_type
                          definition
                          x_opencti_order
                          x_opencti_color
                        }
                      }
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
                  ... on ThreatActorGroup {
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
                  ... on StixCyberObservable {
                    observable_value
                    x_opencti_description
                  }
                }
              }
            }
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
          ... on ThreatActorGroup {
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
          ... on StixCyberObservable {
            observable_value
          }
          ... on StixCoreRelationship {
            id
            entity_type
            relationship_type
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
              ... on StixSightingRelationship {
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
              ... on ThreatActorGroup {
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
              ... on StixSightingRelationship {
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
              ... on ThreatActorGroup {
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
          ... on StixSightingRelationship {
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
          ... on ThreatActorGroup {
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
          ... on StixCyberObservable {
            observable_value
          }
          ... on StixSightingRelationship {
            id
            entity_type
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
              ... on ThreatActorGroup {
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
              ... on ThreatActorGroup {
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
)(StixSightingRelationshipOverview);
