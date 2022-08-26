import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Timeline from '@mui/lab/Timeline';
import TimelineItem from '@mui/lab/TimelineItem';
import TimelineOppositeContent from '@mui/lab/TimelineOppositeContent';
import TimelineSeparator from '@mui/lab/TimelineSeparator';
import { Link } from 'react-router-dom';
import TimelineDot from '@mui/lab/TimelineDot';
import TimelineConnector from '@mui/lab/TimelineConnector';
import TimelineContent from '@mui/lab/TimelineContent';
import Markdown from 'react-markdown';
import { defaultValue } from '../../../../utils/Graph';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
  },
  paper: {
    padding: 15,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
});

const entityStixCoreRelationshipsTimelineStixCoreRelationshipQuery = graphql`
  query EntityStixCoreRelationshipsTimelineStixCoreRelationshipQuery(
    $elementId: [String]
    $elementWithTargetTypes: [String]
    $relationship_type: [String]
    $startTimeStart: DateTime
    $stopTimeStop: DateTime
    $count: Int!
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    stixCoreRelationships(
      elementId: $elementId
      elementWithTargetTypes: $elementWithTargetTypes
      relationship_type: $relationship_type
      startTimeStart: $startTimeStart
      stopTimeStop: $stopTimeStop
      first: $count
      orderBy: $orderBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
          relationship_type
          confidence
          start_time
          stop_time
          description
          is_inferred
          created
          x_opencti_inferences {
            rule {
              id
              name
            }
          }
          from {
            ... on StixDomainObject {
              id
              entity_type
              parent_types
              created_at
              updated_at
              objectLabel {
                edges {
                  node {
                    id
                    value
                    color
                  }
                }
              }
            }
            ... on AttackPattern {
              name
              description
              x_mitre_id
              killChainPhases {
                edges {
                  node {
                    id
                    phase_name
                    x_opencti_order
                  }
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
              objectLabel {
                edges {
                  node {
                    id
                    value
                    color
                  }
                }
              }
            }
            ... on Campaign {
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
            }
            ... on Infrastructure {
              name
              description
            }
            ... on IntrusionSet {
              name
              description
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
            }
            ... on ThreatActor {
              name
              description
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
            }
            ... on Event {
              name
              description
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
            ... on StixCyberObservable {
              id
              entity_type
              parent_types
              observable_value
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
            }
            ... on Indicator {
              id
              name
              pattern_type
              pattern_version
              description
              valid_from
              valid_until
              x_opencti_score
              x_opencti_main_observable_type
              created
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
            }
            ... on StixCoreRelationship {
              id
              entity_type
              parent_types
              created
              created_at
              from {
                ... on StixDomainObject {
                  id
                  entity_type
                  parent_types
                  created_at
                  updated_at
                  objectLabel {
                    edges {
                      node {
                        id
                        value
                        color
                      }
                    }
                  }
                }
                ... on AttackPattern {
                  name
                  description
                  x_mitre_id
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
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
                  objectLabel {
                    edges {
                      node {
                        id
                        value
                        color
                      }
                    }
                  }
                }
                ... on Campaign {
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
                }
                ... on Infrastructure {
                  name
                  description
                }
                ... on IntrusionSet {
                  name
                  description
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
                }
                ... on ThreatActor {
                  name
                  description
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
                }
                ... on StixCyberObservable {
                  id
                  entity_type
                  parent_types
                  observable_value
                  objectMarking {
                    edges {
                      node {
                        id
                        definition
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
                }
                ... on Indicator {
                  id
                  name
                  pattern_type
                  pattern_version
                  description
                  valid_from
                  valid_until
                  x_opencti_score
                  x_opencti_main_observable_type
                  created
                  objectMarking {
                    edges {
                      node {
                        id
                        definition
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
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  parent_types
                  created
                  created_at
                }
              }
              to {
                ... on StixDomainObject {
                  id
                  entity_type
                  parent_types
                  created_at
                  updated_at
                  objectLabel {
                    edges {
                      node {
                        id
                        value
                        color
                      }
                    }
                  }
                }
                ... on AttackPattern {
                  name
                  description
                  x_mitre_id
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
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
                  objectLabel {
                    edges {
                      node {
                        id
                        value
                        color
                      }
                    }
                  }
                }
                ... on Campaign {
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
                }
                ... on Infrastructure {
                  name
                  description
                }
                ... on IntrusionSet {
                  name
                  description
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
                }
                ... on ThreatActor {
                  name
                  description
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
                }
                ... on StixCyberObservable {
                  id
                  entity_type
                  parent_types
                  observable_value
                  objectMarking {
                    edges {
                      node {
                        id
                        definition
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
                }
                ... on Indicator {
                  id
                  name
                  pattern_type
                  pattern_version
                  description
                  valid_from
                  valid_until
                  x_opencti_score
                  x_opencti_main_observable_type
                  created
                  objectMarking {
                    edges {
                      node {
                        id
                        definition
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
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  created
                  created_at
                  parent_types
                }
              }
            }
          }
          to {
            ... on StixDomainObject {
              id
              entity_type
              parent_types
              created_at
              updated_at
              objectLabel {
                edges {
                  node {
                    id
                    value
                    color
                  }
                }
              }
            }
            ... on AttackPattern {
              name
              description
              x_mitre_id
              killChainPhases {
                edges {
                  node {
                    id
                    phase_name
                    x_opencti_order
                  }
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
              objectLabel {
                edges {
                  node {
                    id
                    value
                    color
                  }
                }
              }
            }
            ... on Campaign {
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
            }
            ... on Infrastructure {
              name
              description
            }
            ... on IntrusionSet {
              name
              description
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
            }
            ... on ThreatActor {
              name
              description
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
            }
            ... on StixCyberObservable {
              id
              entity_type
              parent_types
              observable_value
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
            }
            ... on Indicator {
              id
              name
              pattern_type
              pattern_version
              description
              valid_from
              valid_until
              x_opencti_score
              x_opencti_main_observable_type
              created
              objectMarking {
                edges {
                  node {
                    id
                    definition
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
            }
            ... on StixCoreRelationship {
              id
              entity_type
              created
              created_at
              parent_types
              from {
                ... on StixDomainObject {
                  id
                  entity_type
                  parent_types
                  created_at
                  updated_at
                  objectLabel {
                    edges {
                      node {
                        id
                        value
                        color
                      }
                    }
                  }
                }
                ... on AttackPattern {
                  name
                  description
                  x_mitre_id
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
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
                  objectLabel {
                    edges {
                      node {
                        id
                        value
                        color
                      }
                    }
                  }
                }
                ... on Campaign {
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
                }
                ... on Infrastructure {
                  name
                  description
                }
                ... on IntrusionSet {
                  name
                  description
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
                }
                ... on ThreatActor {
                  name
                  description
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
                }
                ... on StixCyberObservable {
                  id
                  entity_type
                  parent_types
                  observable_value
                  objectMarking {
                    edges {
                      node {
                        id
                        definition
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
                }
                ... on Indicator {
                  id
                  name
                  pattern_type
                  pattern_version
                  description
                  valid_from
                  valid_until
                  x_opencti_score
                  x_opencti_main_observable_type
                  created
                  objectMarking {
                    edges {
                      node {
                        id
                        definition
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
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  parent_types
                  created
                  created_at
                }
              }
              to {
                ... on StixDomainObject {
                  id
                  entity_type
                  parent_types
                  created_at
                  updated_at
                  objectLabel {
                    edges {
                      node {
                        id
                        value
                        color
                      }
                    }
                  }
                }
                ... on AttackPattern {
                  name
                  description
                  x_mitre_id
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
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
                  objectLabel {
                    edges {
                      node {
                        id
                        value
                        color
                      }
                    }
                  }
                }
                ... on Campaign {
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
                }
                ... on Infrastructure {
                  name
                  description
                }
                ... on IntrusionSet {
                  name
                  description
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
                }
                ... on ThreatActor {
                  name
                  description
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
                }
                ... on StixCyberObservable {
                  id
                  entity_type
                  parent_types
                  observable_value
                  objectMarking {
                    edges {
                      node {
                        id
                        definition
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
                }
                ... on Indicator {
                  id
                  name
                  pattern_type
                  pattern_version
                  description
                  valid_from
                  valid_until
                  x_opencti_score
                  x_opencti_main_observable_type
                  created
                  objectMarking {
                    edges {
                      node {
                        id
                        definition
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
                }
                ... on StixCoreRelationship {
                  id
                  entity_type
                  created
                  created_at
                  parent_types
                }
              }
            }
          }
          killChainPhases {
            edges {
              node {
                id
                phase_name
                x_opencti_order
              }
            }
          }
        }
      }
    }
  }
`;

class EntityStixCoreRelationshipsTimeline extends Component {
  constructor(props) {
    super(props);
    this.state = { period: 36, interval: 2 };
  }

  renderContent() {
    const {
      t,
      entityId,
      toTypes,
      relationshipType,
      fldt,
      startDate,
      endDate,
      classes,
    } = this.props;
    const finalStartDate = startDate || null;
    const finalEndDate = endDate || null;
    const stixCoreRelationshipsVariables = {
      elementId: entityId || null,
      elementWithTargetTypes: toTypes,
      relationship_type: relationshipType,
      startTimeStart: finalStartDate,
      stopTimeStop: finalEndDate,
      orderBy: 'created',
      orderMode: 'desc',
      count: 20,
    };
    return (
      <QueryRenderer
        query={entityStixCoreRelationshipsTimelineStixCoreRelationshipQuery}
        variables={stixCoreRelationshipsVariables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreRelationships
            && props.stixCoreRelationships.edges.length > 0
          ) {
            const stixCoreRelationshipsEdges = props.stixCoreRelationships.edges;
            return (
              <div id="container" className={classes.container}>
                <Timeline position="alternate">
                  {stixCoreRelationshipsEdges.map(
                    (stixCoreRelationshipEdge) => {
                      const stixCoreRelationship = stixCoreRelationshipEdge.node;
                      const remoteNode = stixCoreRelationship.from
                        && stixCoreRelationship.from.id === entityId
                        ? stixCoreRelationship.to
                        : stixCoreRelationship.from;
                      const restricted = stixCoreRelationship.from === null
                        || stixCoreRelationship.to === null;
                      const link = restricted
                        ? null
                        : `${resolveLink(remoteNode.entity_type)}/${
                          remoteNode.id
                        }/knowledge/relations/${stixCoreRelationship.id}`;
                      return (
                        <TimelineItem key={stixCoreRelationship.id}>
                          <TimelineOppositeContent
                            sx={{ paddingTop: '18px' }}
                            color="text.secondary"
                          >
                            {fldt(stixCoreRelationship.created)}
                          </TimelineOppositeContent>
                          <TimelineSeparator>
                            <Link to={link}>
                              <TimelineDot color="primary" variant="outlined">
                                <ItemIcon type={remoteNode.entity_type} />
                              </TimelineDot>
                            </Link>
                            <TimelineConnector />
                          </TimelineSeparator>
                          <TimelineContent>
                            <Paper variant="outlined" className={classes.paper}>
                              <Typography variant="h2">
                                {defaultValue(remoteNode)}
                              </Typography>
                              <div style={{ marginTop: -5, color: '#a8a8a8' }}>
                                <Markdown>
                                  {truncate(remoteNode.description, 150)}
                                </Markdown>
                              </div>
                            </Paper>
                          </TimelineContent>
                        </TimelineItem>
                      );
                    },
                  )}
                </Timeline>
              </div>
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  }

  render() {
    const { t, classes, title, variant, height } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography
          variant={variant === 'inEntity' ? 'h3' : 'h4'}
          gutterBottom={true}
        >
          {title || t('History of relationships')}
        </Typography>
        {variant === 'inLine' || variant === 'inEntity' ? (
          this.renderContent()
        ) : (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        )}
      </div>
    );
  }
}

EntityStixCoreRelationshipsTimeline.propTypes = {
  variant: PropTypes.string,
  title: PropTypes.string,
  entityId: PropTypes.string,
  relationshipType: PropTypes.string,
  field: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  toTypes: PropTypes.array,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(EntityStixCoreRelationshipsTimeline);
