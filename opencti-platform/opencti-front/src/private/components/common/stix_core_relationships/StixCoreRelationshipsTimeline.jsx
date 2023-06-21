import React from 'react';
import { graphql } from 'react-relay';
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
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import { defaultValue } from '../../../../utils/Graph';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { convertFilters } from '../../../../utils/ListParameters';
import { itemColor } from '../../../../utils/Colors';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const useStyles = makeStyles((theme) => ({
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
}));

const stixCoreRelationshipsTimelineStixCoreRelationshipQuery = graphql`
  query StixCoreRelationshipsTimelineStixCoreRelationshipQuery(
    $relationship_type: [String]
    $fromId: [String]
    $toId: [String]
    $fromTypes: [String]
    $toTypes: [String]
    $first: Int!
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreRelationshipsFiltering]
    $search: String
  ) {
    stixCoreRelationships(
      relationship_type: $relationship_type
      fromId: $fromId
      toId: $toId
      fromTypes: $fromTypes
      toTypes: $toTypes
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
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
            }
            ... on ThreatActorGroup {
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
            ... on DataComponent {
              name
            }
            ... on DataSource {
              name
            }
            ... on Case {
              name
            }
            ... on Note {
              attribute_abstract
              content
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
                ... on ThreatActorGroup {
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
                ... on ThreatActorGroup {
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
            ... on ThreatActorGroup {
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
                ... on ThreatActorGroup {
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
                ... on ThreatActorGroup {
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

const StixCoreRelationshipsTimeline = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    let finalFilters = convertFilters(selection.filters);
    const relationshipType = R.head(finalFilters.filter((n) => n.key === 'relationship_type'))
      ?.values || null;
    const fromId = R.head(finalFilters.filter((n) => n.key === 'fromId'))?.values || null;
    const toId = R.head(finalFilters.filter((n) => n.key === 'toId'))?.values || null;
    const fromTypes = R.head(finalFilters.filter((n) => n.key === 'fromTypes'))?.values || null;
    const toTypes = R.head(finalFilters.filter((n) => n.key === 'toTypes'))?.values || null;
    finalFilters = finalFilters.filter(
      (n) => ![
        'relationship_type',
        'fromId',
        'toId',
        'fromTypes',
        'toTypes',
      ].includes(n.key),
    );
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    if (startDate) {
      finalFilters.push({
        key: dateAttribute,
        values: [startDate],
        operator: 'gt',
      });
    }
    if (endDate) {
      finalFilters.push({
        key: dateAttribute,
        values: [endDate],
        operator: 'lt',
      });
    }
    return (
      <QueryRenderer
        query={stixCoreRelationshipsTimelineStixCoreRelationshipQuery}
        variables={{
          relationship_type: relationshipType,
          fromId,
          toId,
          fromTypes,
          toTypes,
          first: 50,
          orderBy: dateAttribute,
          orderMode: 'desc',
          filters: finalFilters,
        }}
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
                        && stixCoreRelationship.from.id === fromId
                        && selection.isTo !== false
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
                              <TimelineDot
                                sx={{
                                  borderColor: itemColor(
                                    remoteNode.entity_type,
                                  ),
                                }}
                                variant="outlined"
                              >
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
                                <MarkdownDisplay
                                  content={remoteNode.description}
                                  limit={150}
                                />
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
  };
  return (
    <div style={{ height: height || '100%' }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{
          margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
        }}
      >
        {parameters.title ?? t('Relationships timeline')}
      </Typography>
      {variant !== 'inLine' ? (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      ) : (
        renderContent()
      )}
    </div>
  );
};

export default StixCoreRelationshipsTimeline;
