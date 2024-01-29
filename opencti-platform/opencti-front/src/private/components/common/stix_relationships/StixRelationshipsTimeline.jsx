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
import makeStyles from '@mui/styles/makeStyles';
import { defaultValue } from '../../../../utils/Graph';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { itemColor } from '../../../../utils/Colors';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';

const useStyles = makeStyles({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
  },
  paper: {
    padding: 15,
  },
});

const stixRelationshipsTimelineStixRelationshipQuery = graphql`
  query StixRelationshipsTimelineStixRelationshipQuery(
    $relationship_type: [String]
    $fromId: [String]
    $toId: [String]
    $fromTypes: [String]
    $toTypes: [String]
    $first: Int!
    $orderBy: StixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
    $dynamicTo: FilterGroup
    $search: String
  ) {
    stixRelationships(
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
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
          relationship_type
          confidence
          is_inferred
          created
          x_opencti_inferences {
            rule {
              id
              name
            }
          }
          ... on StixCoreRelationship {
            start_time
            stop_time
            description
            killChainPhases {
              id
              phase_name
              x_opencti_order
            }
          }
          ... on StixSightingRelationship {
            first_seen
            last_seen
          }
          from {
            ... on StixDomainObject {
              id
              entity_type
              parent_types
              created_at
              updated_at
              objectLabel {
                id
                value
                color
              }
            }
            ... on AttackPattern {
              name
              description
              x_mitre_id
              killChainPhases {
                id
                phase_name
                x_opencti_order
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
            ... on Opinion {
              opinion
            }
            ... on StixCyberObservable {
              id
              entity_type
              parent_types
              observable_value
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
            }
            ... on StixRelationship {
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
                    id
                    value
                    color
                  }
                }
                ... on AttackPattern {
                  name
                  description
                  x_mitre_id
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
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
                }
                ... on StixRelationship {
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
                    id
                    value
                    color
                  }
                }
                ... on AttackPattern {
                  name
                  description
                  x_mitre_id
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
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
                }
                ... on StixRelationship {
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
                id
                value
                color
              }
            }
            ... on AttackPattern {
              name
              description
              x_mitre_id
              killChainPhases {
                id
                phase_name
                x_opencti_order
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
            }
            ... on StixRelationship {
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
                    id
                    value
                    color
                  }
                }
                ... on AttackPattern {
                  name
                  description
                  x_mitre_id
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
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
                }
                ... on StixRelationship {
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
                    id
                    value
                    color
                  }
                }
                ... on AttackPattern {
                  name
                  description
                  x_mitre_id
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
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
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                  }
                  objectLabel {
                    id
                    value
                    color
                  }
                }
                ... on StixRelationship {
                  id
                  entity_type
                  created
                  created_at
                  parent_types
                }
              }
            }
          }
        }
      }
    }
  }
`;

const StixRelationshipsTimeline = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}) => {
  const classes = useStyles();
  const { t_i18n, fldt } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, { startDate, endDate, dateAttribute });
    const fromId = filters.filters.find((o) => o.key === 'fromId')?.values || null;
    return (
      <QueryRenderer
        query={stixRelationshipsTimelineStixRelationshipQuery}
        variables={{
          first: 50,
          orderBy: dateAttribute,
          orderMode: 'desc',
          filters,
          dynamicFrom: selection.dynamicFrom,
          dynamicTo: selection.dynamicTo,
        }}
        render={({ props }) => {
          if (
            props
            && props.stixRelationships
            && props.stixRelationships.edges.length > 0
          ) {
            const stixRelationshipsEdges = props.stixRelationships.edges;
            return (
              <div id="container" className={classes.container}>
                <Timeline position="alternate">
                  {stixRelationshipsEdges.map((stixRelationshipEdge) => {
                    const stixRelationship = stixRelationshipEdge.node;
                    const remoteNode = stixRelationship.from
                      && stixRelationship.from.id === fromId
                      && selection.isTo !== false
                      ? stixRelationship.to
                      : stixRelationship.from;
                    const restricted = stixRelationship.from === null
                      || stixRelationship.to === null;
                    const link = restricted
                      ? null
                      : `${resolveLink(remoteNode.entity_type)}/${
                        remoteNode.id
                      }/knowledge/relations/${stixRelationship.id}`;
                    return (
                      <TimelineItem key={stixRelationship.id}>
                        <TimelineOppositeContent
                          sx={{ paddingTop: '18px' }}
                          color="text.secondary"
                        >
                          {fldt(stixRelationship.created)}
                        </TimelineOppositeContent>
                        <TimelineSeparator>
                          <Link to={link}>
                            <TimelineDot
                              sx={{
                                borderColor: itemColor(remoteNode.entity_type),
                              }}
                              variant="outlined"
                              className="noDrag"
                            >
                              <ItemIcon type={remoteNode.entity_type} />
                            </TimelineDot>
                          </Link>
                          <TimelineConnector />
                        </TimelineSeparator>
                        <TimelineContent>
                          <Paper variant="outlined" classes={{ root: classes.paper }} className="noDrag">
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
                  })}
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
                  {t_i18n('No entities of this type has been found.')}
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
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {parameters.title ?? t_i18n('Relationships timeline')}
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

export default StixRelationshipsTimeline;
