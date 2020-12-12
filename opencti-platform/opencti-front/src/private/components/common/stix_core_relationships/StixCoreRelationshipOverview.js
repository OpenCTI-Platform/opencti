import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import {
  compose, includes, map, propOr,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import { DiagramEngine } from 'storm-react-diagrams';
import { createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Fab from '@material-ui/core/Fab';
import { ArrowRightAlt, Edit } from '@material-ui/icons';
import { itemColor } from '../../../../utils/Colors';
import { resolveLink } from '../../../../utils/Entity';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreRelationshipEdition, {
  stixCoreRelationshipEditionDeleteMutation,
} from './StixCoreRelationshipEdition';
import { commitMutation } from '../../../../relay/environment';
import SimpleLabelFactory from '../../../../components/graph_node/SimpleLabelFactory';
import SimpleLinkFactory from '../../../../components/graph_node/SimpleLinkFactory';
import EntityNodeFactory from '../../../../components/graph_node/EntityNodeFactory';
import GlobalPortFactory from '../../../../components/graph_node/GlobalPortFactory';
import { stixCoreRelationshipEditionFocus } from './StixCoreRelationshipEditionOverview';
import ItemMarking from '../../../../components/ItemMarking';
import StixCoreRelationshipStixCoreRelationships from './StixCoreRelationshipStixCoreRelationships';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import ItemAuthor from '../../../../components/ItemAuthor';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';

const styles = () => ({
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
    color: '#ffffff',
    fontSize: 11,
  },
  content: {
    width: '100%',
    padding: '0 10px 0 10px',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: '#ffffff',
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
    color: '#ffffff',
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
});

class StixCoreRelationshipContainer extends Component {
  constructor(props) {
    super(props);
    const engine = new DiagramEngine();
    engine.installDefaultFactories();
    engine.registerPortFactory(new GlobalPortFactory());
    engine.registerNodeFactory(new EntityNodeFactory());
    engine.registerLinkFactory(new SimpleLinkFactory());
    engine.registerLabelFactory(new SimpleLabelFactory());
    this.state = { openEdit: false, engine };
  }

  handleOpenEdition() {
    this.setState({ openEdit: true });
  }

  handleCloseEdition() {
    const {
      match: {
        params: { relationId },
      },
    } = this.props;
    commitMutation({
      mutation: stixCoreRelationshipEditionFocus,
      variables: {
        id: relationId,
        input: { focusOn: '' },
      },
    });
    this.setState({ openEdit: false });
  }

  handleDelete() {
    const {
      location,
      match: {
        params: { relationId },
      },
    } = this.props;
    commitMutation({
      mutation: stixCoreRelationshipEditionDeleteMutation,
      variables: {
        id: relationId,
      },
      onCompleted: () => {
        this.handleCloseEdition();
        this.props.history.push(
          location.pathname.replace(`/relations/${relationId}`, ''),
        );
      },
    });
  }

  render() {
    const {
      t, nsdt, classes, stixCoreRelationship, paddingRight,
    } = this.props;
    const { from } = stixCoreRelationship;
    const { to } = stixCoreRelationship;
    const linkFrom = from.entity_type === 'stix-relation'
      || from.entity_type === 'stix_relation'
      ? `${resolveLink(from.from.entity_type)}/${
        from.from.id
      }/knowledge/relations`
      : resolveLink(from.entity_type);
    const linkTo = to.entity_type === 'stix-relation' || to.entity_type === 'stix_relation'
      ? `${resolveLink(to.from.entity_type)}/${
        to.from.id
      }/knowledge/relations`
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
                {includes('Stix-Cyber-Observable', from.parent_types)
                  ? t(`entity_${from.entity_type}`)
                  : t(
                    `entity_${
                      from.entity_type === 'stix_relation'
                        || from.entity_type === 'stix-relation'
                        ? from.parent_types[0]
                        : from.entity_type
                    }`,
                  )}
              </div>
            </div>
            <div className={classes.content}>
              <span className={classes.name}>
                {truncate(
                  /* eslint-disable-next-line no-nested-ternary */
                  includes('Stix-Cyber-Observable', from.parent_types)
                    ? from.observable_value
                    : from.entity_type === 'stix_relation'
                      || from.entity_type === 'stix-relation'
                      ? `${from.from.name} ${String.fromCharCode(8594)} ${
                        from.to.name
                      }`
                      : from.name,
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
              backgroundColor: '#14262c',
              color: '#ffffff',
              fontSize: 12,
              display: 'inline-block',
            }}
          >
            <strong>
              {t(`relationship_${stixCoreRelationship.relationship_type}`)}
            </strong>
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
                {includes('Stix-Cyber-Observable', to.parent_types)
                  ? t(`entity_${to.entity_type}`)
                  : t(
                    `entity_${
                      to.entity_type === 'stix_relation'
                        || to.entity_type === 'stix-relation'
                        ? to.parent_types[0]
                        : to.entity_type
                    }`,
                  )}
              </div>
            </div>
            <div className={classes.content}>
              <span className={classes.name}>
                {truncate(
                  /* eslint-disable-next-line no-nested-ternary */
                  includes('Stix-Cyber-Observable', to.parent_types)
                    ? to.observable_value
                    : to.entity_type === 'stix_relation'
                      || to.entity_type === 'stix-relation'
                      ? `${to.from.name} ${String.fromCharCode(8594)} ${
                        to.to.name
                      }`
                      : to.name,
                  50,
                )}
              </span>
            </div>
          </div>
        </Link>
        <div className="clearfix" style={{ height: 20 }} />
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Marking')}
              </Typography>
              {stixCoreRelationship.objectMarking.edges.length > 0 ? (
                map(
                  (markingDefinition) => (
                    <ItemMarking
                      key={markingDefinition.node.id}
                      label={markingDefinition.node.definition}
                    />
                  ),
                  stixCoreRelationship.objectMarking.edges,
                )
              ) : (
                <ItemMarking label="TLP:WHITE" />
              )}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creation date')}
              </Typography>
              {nsdt(stixCoreRelationship.created_at)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Modification date')}
              </Typography>
              {nsdt(stixCoreRelationship.updated_at)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Author')}
              </Typography>
              <ItemAuthor
                createdBy={propOr(null, 'createdBy', stixCoreRelationship)}
              />
            </Paper>
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Confidence level')}
              </Typography>
              <ItemConfidence confidence={stixCoreRelationship.confidence} />
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
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Stop time')}
              </Typography>
              {nsdt(stixCoreRelationship.stop_time)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Description')}
              </Typography>
              <Markdown
                className="markdown"
                source={stixCoreRelationship.description}
              />
            </Paper>
          </Grid>
        </Grid>
        <div>
          <div style={{ margin: '40px 0 0px 0' }}>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={6}>
                <StixCoreRelationshipStixCoreRelationships
                  entityId={stixCoreRelationship.id}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <StixCoreObjectOrStixCoreRelationshipLastReports
                  stixCoreObjectOrStixCoreRelationshipId={
                    stixCoreRelationship.id
                  }
                />
              </Grid>
            </Grid>
            <StixCoreObjectOrStixCoreRelationshipNotes
              marginTop={55}
              stixCoreObjectOrStixCoreRelationshipId={stixCoreRelationship.id}
              isRelationship={true}
            />
          </div>
        </div>
        <div>
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
          <StixCoreRelationshipEdition
            open={this.state.openEdit}
            stixCoreRelationshipId={stixCoreRelationship.id}
            handleClose={this.handleCloseEdition.bind(this)}
            handleDelete={this.handleDelete.bind(this)}
          />
        </div>
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
  history: PropTypes.object,
  location: PropTypes.object,
};

const StixCoreRelationshipOverview = createFragmentContainer(
  StixCoreRelationshipContainer,
  {
    stixCoreRelationship: graphql`
      fragment StixCoreRelationshipOverview_stixCoreRelationship on StixCoreRelationship {
        id
        relationship_type
        confidence
        start_time
        stop_time
        description
        fromRole
        toRole
        created_at
        updated_at
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
          ... on XOpenCTIIncident {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on StixCoreRelationship {
            from {
              ... on BasicObject {
                id
                entity_type
              }
              ... on BasicRelationship {
                id
                entity_type
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
              ... on XOpenCTIIncident {
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
              ... on XOpenCTIIncident {
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
          ... on XOpenCTIIncident {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on StixCoreRelationship {
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
              ... on XOpenCTIIncident {
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
              ... on XOpenCTIIncident {
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

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixCoreRelationshipOverview);
