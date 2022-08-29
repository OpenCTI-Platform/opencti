import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import { graphql, createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Fab from '@mui/material/Fab';
import { ArrowRightAlt, Edit } from '@mui/icons-material';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import Chip from '@mui/material/Chip';
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
import ItemMarking from '../../../../components/ItemMarking';
import ItemAuthor from '../../../../components/ItemAuthor';
import StixSightingRelationshipNotes from '../../analysis/notes/StixSightingRelationshipNotes';
import StixSightingRelationshipInference from './StixSightingRelationshipInference';
import StixSightingRelationshipExternalReferences from '../../analysis/external_references/StixSightingRelationshipExternalReferences';
import StixSightingRelationshipLatestHistory from './StixSightingRelationshipLatestHistory';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import ItemStatus from '../../../../components/ItemStatus';

const styles = (theme) => ({
  container: {
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
});

class StixSightingRelationshipContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { openEdit: false };
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

  handleDelete() {
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
      theme,
      stixSightingRelationship,
      paddingRight,
    } = this.props;
    const { from } = stixSightingRelationship;
    const { to } = stixSightingRelationship;
    const linkFrom = from.relationship_type
      ? `${resolveLink(from.from.entity_type)}/${
        from.from.id
      }/knowledge/relations`
      : resolveLink(from.entity_type);
    const linkTo = to.relationship_type
      ? `${resolveLink(to.from.entity_type)}/${to.from.id}/knowledge/relations`
      : resolveLink(to.entity_type);
    return (
      <div className={classes.container}>
        <Link to={`${linkFrom}/${from.id}`}>
          <div
            className={classes.item}
            style={{
              border: `2px solid ${itemColor(from.entity_type)}`,
              top: 10,
              left: 0,
            }}
          >
            <div
              className={classes.itemHeader}
              style={{
                borderBottom: `1px solid ${itemColor(from.entity_type)}`,
              }}
            >
              <div className={classes.icon}>
                <ItemIcon
                  type={from.entity_type}
                  color={itemColor(from.entity_type)}
                  size="small"
                />
              </div>
              <div className={classes.type}>
                {from.relationship_type
                  ? t('Relationship')
                  : t(`entity_${from.entity_type}`)}
              </div>
            </div>
            <div className={classes.content}>
              <span className={classes.name}>
                {truncate(
                  from.name
                    || from.observable_value
                    || from.attribute_abstract
                    || from.content
                    || t(`relationship_${from.entity_type}`),
                  50,
                )}
              </span>
            </div>
          </div>
        </Link>
        <div className={classes.middle}>
          <ArrowRightAlt fontSize="large" />
          <br />
          <div
            style={{
              padding: '5px 8px 5px 8px',
              backgroundColor: theme.palette.background.accent,
              color: theme.palette.text.primary,
              fontSize: 12,
              display: 'inline-block',
            }}
          >
            <strong>{t('sighted in/at')}</strong>
          </div>
        </div>
        <Link to={`${linkTo}/${to.id}`}>
          <div
            className={classes.item}
            style={{
              border: `2px solid ${itemColor(to.entity_type)}`,
              top: 10,
              right: 0,
            }}
          >
            <div
              className={classes.itemHeader}
              style={{
                borderBottom: `1px solid ${itemColor(to.entity_type)}`,
              }}
            >
              <div className={classes.icon}>
                <ItemIcon
                  type={to.entity_type}
                  color={itemColor(to.entity_type)}
                  size="small"
                />
              </div>
              <div className={classes.type}>
                {to.relationship_type
                  ? t('Relationship')
                  : t(`entity_${to.entity_type}`)}
              </div>
            </div>
            <div className={classes.content}>
              <span className={classes.name}>
                {truncate(
                  to.name
                    || to.observable_value
                    || to.attribute_abstract
                    || to.content
                    || t(`relationship_${to.entity_type}`),
                  50,
                )}
              </span>
            </div>
          </div>
        </Link>
        <div className="clearfix" style={{ height: 40 }} />
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Marking')}
                  </Typography>
                  {stixSightingRelationship.objectMarking.edges.length > 0
                    && R.map(
                      (markingDefinition) => (
                        <ItemMarking
                          key={markingDefinition.node.id}
                          label={markingDefinition.node.definition}
                          color={markingDefinition.node.x_opencti_color}
                        />
                      ),
                      stixSightingRelationship.objectMarking.edges,
                    )}
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
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Confidence level')}
                  </Typography>
                  <ItemConfidence
                    confidence={stixSightingRelationship.confidence}
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
                    style={{
                      marginTop:
                        stixSightingRelationship.x_opencti_inferences === null
                          ? 20
                          : 0,
                    }}
                  >
                    {t('Status')}
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
                        : t('Malicious')
                    }
                  />
                </Grid>
              </Grid>
            </Paper>
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ fontWeight: 500 }}
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
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Count')}
                  </Typography>
                  <span>{n(stixSightingRelationship.attribute_count)}</span>
                  {stixSightingRelationship.x_opencti_inferences === null && (
                    <div>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        style={{ marginTop: 20 }}
                      >
                        {t('Description')}
                      </Typography>
                      <Markdown
                        remarkPlugins={[remarkGfm, remarkParse]}
                        parserOptions={{ commonmark: true }}
                        className="markdown"
                      >
                        {stixSightingRelationship.description}
                      </Markdown>
                    </div>
                  )}
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
            <div style={{ margin: '40px 0 0px 0' }}>
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
              <StixSightingRelationshipNotes
                marginTop={55}
                stixSightingRelationshipId={stixSightingRelationship.id}
                isRelationship={true}
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
            handleDelete={this.handleDelete.bind(this)}
          />
        </Security>
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
        creator {
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
            ... on StixMetaRelationship {
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
                            definition
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
            ... on Country {
              name
            }
            ... on Region {
              name
            }
            ... on Malware {
              name
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
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
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
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
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
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
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
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
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
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
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
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
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
                    ... on StixCyberObservable {
                      observable_value
                    }
                  }
                }
              }
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
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
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
                ... on StixCyberObservable {
                  observable_value
                }
                ... on ObservedData {
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
                                definition
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
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
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
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
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
                    ... on ObservedData {
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
                                    definition
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
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
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
                ... on StixCyberObservable {
                  observable_value
                }
                ... on ObservedData {
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
                                definition
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
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
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
                    ... on StixCyberObservable {
                      observable_value
                    }
                    ... on ObservedData {
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
                                    definition
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
                    ... on Country {
                      name
                    }
                    ... on Region {
                      name
                    }
                    ... on Malware {
                      name
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
                    ... on StixCyberObservable {
                      observable_value
                    }
                    ... on ObservedData {
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
                                    definition
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
              definition
              x_opencti_color
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
                          definition
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
          ... on Country {
            name
          }
          ... on Region {
            name
          }
          ... on Malware {
            name
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
              ... on Country {
                name
              }
              ... on Region {
                name
              }
              ... on Malware {
                name
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
              ... on Country {
                name
              }
              ... on Region {
                name
              }
              ... on Malware {
                name
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
          ... on Country {
            name
          }
          ... on Region {
            name
          }
          ... on Malware {
            name
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
              ... on Country {
                name
              }
              ... on Region {
                name
              }
              ... on Malware {
                name
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
              ... on Country {
                name
              }
              ... on Region {
                name
              }
              ... on Malware {
                name
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
              ... on StixCyberObservable {
                observable_value
              }
            }
          }
        }
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
