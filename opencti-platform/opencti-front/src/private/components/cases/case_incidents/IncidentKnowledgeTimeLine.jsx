import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Timeline from '@mui/lab/Timeline';
import TimelineItem from '@mui/lab/TimelineItem';
import TimelineOppositeContent from '@mui/lab/TimelineOppositeContent';
import TimelineSeparator from '@mui/lab/TimelineSeparator';
import { Link } from 'react-router-dom';
import TimelineDot from '@mui/lab/TimelineDot';
import TimelineConnector from '@mui/lab/TimelineConnector';
import TimelineContent from '@mui/lab/TimelineContent';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { getSecondaryRepresentative, getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import ItemIcon from '../../../../components/ItemIcon';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import itemColor from '../../../../components/ItemColor';

export const incidentKnowledgeTimeLineQuery = graphql`
  query IncidentKnowledgeTimeLineCaseQuery(
    $id: String!
    $search: String
    $types: [String]
    $orderBy: StixObjectOrStixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    caseIncident(id: $id) {
      ...IncidentKnowledgeTimeLine_case
        @arguments(
          search: $search
          types: $types
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        )
    }
  }
`;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
    paddingBottom: 80,
  },
  paper: {
    padding: 15,
  },
});

const IncidentKnowledgeTimeLineComponent = ({
  caseData,
  dateAttribute,
  displayRelationships,
}) => {
  const classes = useStyles();
  const { fldt, t_i18n } = useFormatter();
  const { edges } = caseData.objects;
  return (
    <div id="container" className={classes.container}>
      <Timeline position="alternate">
        {edges.map((edge) => {
          const { node } = edge;
          const link = `${resolveLink(
            displayRelationships ? node.from.entity_type : node.entity_type,
          )}/${
            displayRelationships
              ? `${node.from.id}/knowledge/relations/${node.id}`
              : node.id
          }`;
          return (
            <TimelineItem key={node.id}>
              <TimelineOppositeContent
                sx={{ paddingTop: '18px' }}
                color="text.secondary"
              >
                {fldt(node[dateAttribute])}
                {displayRelationships && (
                  <span>
                    <br />
                    <i>{`${t_i18n(`relationship_${node.entity_type}`)}`}</i>
                  </span>
                )}
              </TimelineOppositeContent>
              <TimelineSeparator>
                <Link to={link}>
                  <TimelineDot
                    sx={{ borderColor: itemColor(node.entity_type) }}
                    variant="outlined"
                  >
                    <ItemIcon type={node.entity_type} />
                  </TimelineDot>
                </Link>
                <TimelineConnector />
              </TimelineSeparator>
              <TimelineContent>
                <Paper variant="outlined" className={classes.paper}>
                  <Typography variant="h2">{getMainRepresentative(node)}</Typography>
                  <div style={{ marginTop: -5, color: '#a8a8a8' }}>
                    <MarkdownDisplay
                      content={getSecondaryRepresentative(node)}
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
};

export default createFragmentContainer(IncidentKnowledgeTimeLineComponent, {
  caseData: graphql`
    fragment IncidentKnowledgeTimeLine_case on CaseIncident
    @argumentDefinitions(
      types: { type: "[String]" }
      search: { type: "String" }
      orderBy: {
        type: "StixObjectOrStixRelationshipsOrdering"
        defaultValue: name
      }
      orderMode: { type: "OrderingMode", defaultValue: asc }
      filters: { type: "FilterGroup" }
    ) {
      id
      name
      x_opencti_graph_data
      confidence
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
      objects(
        all: true
        types: $types
        search: $search
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      ) {
        edges {
          types
          node {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on StixCoreObject {
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
            ... on StixDomainObject {
              is_inferred
              created
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
            ... on ObservedData {
              name
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
              description
            }
            ... on DataSource {
              name
              description
            }
            ... on Case {
              name
              description
            }
            ... on CaseIncident {
              name
              description
            }
            ... on Feedback {
              name
              description
            }
            ... on CaseRfi {
              name
              description
            }
            ... on CaseRft {
              name
              description
            }
            ... on Task {
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
              observable_value
              x_opencti_description
            }
            ... on StixFile {
              observableName: name
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
              start_time
              stop_time
              confidence
              created
              is_inferred
              description
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
                ... on StixCoreRelationship {
                  relationship_type
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
                ... on ObservedData {
                  name
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
                  description
                }
                ... on DataSource {
                  name
                  description
                }
                ... on Case {
                  name
                  description
                }
                ... on CaseIncident {
                  name
                  description
                }
                ... on Feedback {
                  name
                  description
                }
                ... on CaseRfi {
                  name
                  description
                }
                ... on CaseRft {
                  name
                  description
                }
                ... on Task {
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
                  observable_value
                  x_opencti_description
                }
                ... on StixFile {
                  observableName: name
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
                ... on StixCoreRelationship {
                  relationship_type
                }
                ... on StixDomainObject {
                  is_inferred
                  created
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
                ... on ObservedData {
                  name
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
                  description
                }
                ... on DataSource {
                  name
                  description
                }
                ... on Case {
                  name
                  description
                }
                ... on CaseIncident {
                  name
                  description
                }
                ... on Feedback {
                  name
                  description
                }
                ... on CaseRfi {
                  name
                  description
                }
                ... on CaseRft {
                  name
                  description
                }
                ... on Task {
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
                  observable_value
                  x_opencti_description
                }
                ... on StixFile {
                  observableName: name
                }
              }
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
            ... on StixRefRelationship {
              relationship_type
              start_time
              stop_time
              confidence
              is_inferred
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
                ... on StixCoreRelationship {
                  relationship_type
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
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
              created_at
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
            ... on StixSightingRelationship {
              relationship_type
              first_seen
              last_seen
              confidence
              created
              is_inferred
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
                ... on StixCoreRelationship {
                  relationship_type
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
                ... on StixCoreRelationship {
                  relationship_type
                }
              }
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
          }
        }
      }
      ...ContainerHeader_container
    }
  `,
});
