import React from 'react';
import * as R from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import { Link } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { computeLink } from '../../../../utils/Entity';
import { defaultSecondaryValue, defaultValue } from '../../../../utils/Graph';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
}));

const ExternalReferenceStixCoreObjectsComponent = ({ externalReference }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const stixCoreObjects = R.map(
    (n) => n?.node,
    externalReference.references?.edges ?? [],
  );
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Linked objects')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <List classes={{ root: classes.list }}>
          {stixCoreObjects.map((stixCoreObjectOrRelationship) => (
            <ListItem
              key={stixCoreObjectOrRelationship?.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              component={Link}
              to={`${computeLink(stixCoreObjectOrRelationship)}`}
            >
              <ListItemIcon>
                <ItemIcon type={stixCoreObjectOrRelationship?.entity_type} />
              </ListItemIcon>
              <ListItemText
                primary={defaultValue(stixCoreObjectOrRelationship)}
                secondary={truncate(defaultSecondaryValue(stixCoreObjectOrRelationship), 150)}
              />
            </ListItem>
          ))}
        </List>
      </Paper>
    </div>
  );
};

const ExternalReferenceStixCoreObjects = createFragmentContainer(
  ExternalReferenceStixCoreObjectsComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceStixCoreObjects_externalReference on ExternalReference {
        id
        references(types: ["Stix-Core-Object", "Stix-Core-Relationship", "Stix-Sighting-Relationship"]) {
          edges {
            node {
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
                from {
                  ... on BasicObject {
                    id
                    entity_type
                    parent_types
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
                }
                to {
                  ... on BasicObject {
                    id
                    entity_type
                    parent_types
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
                }
              }
              ... on StixSightingRelationship {
                created_at
                relationship_type
                description
                from {
                  ... on BasicObject {
                    id
                    entity_type
                    parent_types
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
                }
                to {
                  ... on BasicObject {
                    id
                    entity_type
                    parent_types
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
              }
              ... on Report {
                name
                description
              }
              ... on Grouping {
                name
                description
              }
              ... on ObservedData {
                name
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
              ... on StixCyberObservable {
                observable_value
                x_opencti_description
              }
              ... on StixFile {
                observableName: name
              }
            }
          }
        }
      }
    `,
  },
);

export default ExternalReferenceStixCoreObjects;
