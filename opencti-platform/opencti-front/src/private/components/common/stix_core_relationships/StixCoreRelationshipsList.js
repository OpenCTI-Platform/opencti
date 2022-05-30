import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import Chip from '@mui/material/Chip';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import { defaultValue } from '../../../../utils/Graph';
import { convertFilters } from '../../../../utils/ListParameters';
import Filters, { isUniqFilter } from '../lists/Filters';
import { truncate } from '../../../../utils/String';
import ItemMarkings from '../../../../components/ItemMarkings';

const styles = (theme) => ({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
    paddingBottom: 10,
    marginBottom: 10,
  },
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 5,
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  itemIconDisabled: {
    marginRight: 0,
    color: theme.palette.grey[700],
  },
  parameters: {
    margin: '0 0 20px 0',
    padding: 0,
  },
  filters: {
    float: 'left',
    margin: '-4px 0 0 15px',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '0 10px 0 10px',
  },
  export: {
    float: 'right',
    margin: '0 0 0 20px',
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing(1) / 4,
  },
});

const stixCoreRelationshipsListQuery = graphql`
  query StixCoreRelationshipsListQuery(
    $search: String
    $fromId: [String]
    $toId: [String]
    $fromTypes: [String]
    $toTypes: [String]
    $first: Int!
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreRelationshipsFiltering]
  ) {
    stixCoreRelationships(
      search: $search
      fromId: $fromId
      toId: $toId
      fromTypes: $fromTypes
      toTypes: $toTypes
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
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
          fromRole
          toRole
          created_at
          updated_at
          is_inferred
          createdBy {
            ... on Identity {
              name
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
          objectLabel {
            edges {
              node {
                id
                value
                color
              }
            }
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
      }
    }
  }
`;

class StixCoreRelationshipsList extends Component {
  constructor(props) {
    super(props);
    this.state = {
      filters: R.propOr({}, 'filters', props.config),
    };
  }

  handleSaveConfig() {
    const { config, onConfigChange } = this.props;
    const { filters } = this.state;
    onConfigChange({ ...config, filters });
  }

  handleAddFilter(key, id, value, event = null) {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if (this.state.filters[key] && this.state.filters[key].length > 0) {
      this.setState(
        {
          filters: R.assoc(
            key,
            isUniqFilter(key)
              ? [{ id, value }]
              : R.uniqBy(R.prop('id'), [
                { id, value },
                ...this.state.filters[key],
              ]),
            this.state.filters,
          ),
        },
        () => this.handleSaveConfig(),
      );
    } else {
      this.setState(
        {
          filters: R.assoc(key, [{ id, value }], this.state.filters),
        },
        () => this.handleSaveConfig(),
      );
    }
  }

  handleRemoveFilter(key) {
    this.setState({ filters: R.dissoc(key, this.state.filters) }, () => this.handleSaveConfig());
  }

  renderContent() {
    const { filters } = this.state;
    const { t, fsd, dateAttribute, classes, startDate, endDate } = this.props;
    let finalFilters = convertFilters(filters);
    const fromId = R.head(finalFilters.filter((n) => n.key === 'fromId'))?.values || null;
    const toId = R.head(finalFilters.filter((n) => n.key === 'toId'))?.values || null;
    const fromTypes = R.head(finalFilters.filter((n) => n.key === 'fromTypes'))?.values || null;
    const toTypes = R.head(finalFilters.filter((n) => n.key === 'toTypes'))?.values || null;
    finalFilters = finalFilters.filter(
      (n) => !['fromId', 'toId', 'fromTypes', 'toTypes'].includes(n.key),
    );
    if (startDate) {
      finalFilters.push({
        key: 'created',
        values: [startDate],
        operator: 'gt',
      });
    }
    if (endDate) {
      finalFilters.push({
        key: 'created',
        values: [endDate],
        operator: 'lt',
      });
    }
    return (
      <QueryRenderer
        query={stixCoreRelationshipsListQuery}
        variables={{
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
            const data = props.stixCoreRelationships.edges;
            return (
              <div id="container" className={classes.container}>
                <List style={{ minWidth: 1350, marginTop: -10 }}>
                  {data.map((stixCoreRelationshipEdge) => {
                    const stixCoreRelationship = stixCoreRelationshipEdge.node;
                    const remoteNode = stixCoreRelationship.from
                      ? stixCoreRelationship.from
                      : stixCoreRelationship.to;
                    let link = null;
                    if (remoteNode) {
                      link = `${resolveLink(remoteNode.entity_type)}/${
                        remoteNode.id
                      }/knowledge/relations/${stixCoreRelationship.id}`;
                    }
                    return (
                      <ListItem
                        key={stixCoreRelationship.id}
                        dense={true}
                        button={true}
                        classes={{ root: classes.item }}
                        divider={true}
                        component={Link}
                        to={link}
                      >
                        <ListItemIcon classes={{ root: classes.itemIcon }}>
                          <ItemIcon
                            type={stixCoreRelationship.entity_type}
                            color="primary"
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <div>
                              <div
                                className={classes.bodyItem}
                                style={{
                                  width: '10%',
                                  display: 'flex',
                                }}
                              >
                                <ItemIcon
                                  type={
                                    stixCoreRelationship.from
                                    && stixCoreRelationship.from.entity_type
                                  }
                                  variant="inline"
                                />
                                {stixCoreRelationship.from
                                  ? t(
                                    `entity_${stixCoreRelationship.from.entity_type}`,
                                  )
                                  : t('Restricted')}
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '18%' }}
                              >
                                <code>
                                  {stixCoreRelationship.from
                                    ? defaultValue(
                                      stixCoreRelationship.from,
                                      true,
                                    )
                                    : t('Restricted')}
                                </code>
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{
                                  width: '10%',
                                }}
                              >
                                <i>
                                  {t(
                                    `relationship_${stixCoreRelationship.relationship_type}`,
                                  )}
                                </i>
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{
                                  width: '10%',
                                  display: 'flex',
                                }}
                              >
                                <ItemIcon
                                  type={
                                    stixCoreRelationship.to
                                    && stixCoreRelationship.to.entity_type
                                  }
                                  variant="inline"
                                />
                                {stixCoreRelationship.to
                                  ? t(
                                    `entity_${stixCoreRelationship.to.entity_type}`,
                                  )
                                  : t('Restricted')}
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '18%' }}
                              >
                                <code>
                                  {stixCoreRelationship.to
                                    ? defaultValue(
                                      stixCoreRelationship.to,
                                      true,
                                    )
                                    : t('Restricted')}
                                </code>
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '10%' }}
                              >
                                {fsd(stixCoreRelationship[dateAttribute])}
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '15%' }}
                              >
                                {R.pathOr(
                                  '',
                                  ['createdBy', 'name'],
                                  stixCoreRelationship,
                                )}
                              </div>
                              <div className={classes.bodyItem}>
                                <ItemMarkings
                                  markingDefinitions={R.pathOr(
                                    [],
                                    ['objectMarking', 'edges'],
                                    stixCoreRelationship,
                                  )}
                                  limit={1}
                                  variant="inList"
                                />
                              </div>
                            </div>
                          }
                        />
                      </ListItem>
                    );
                  })}
                </List>
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
    const { filters } = this.state;
    const { t, classes, title, variant, height, onConfigChange } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <div
          className={classes.parameters}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          }}
        >
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{
              float: 'left',
              margin: '2px 20px 0 0',
            }}
          >
            {title || t('Reports list')}
          </Typography>
          {onConfigChange && (
            <div style={{ marginTop: -4, float: 'left' }}>
              <Filters
                availableFilterKeys={[
                  'fromId',
                  'toId',
                  'fromTypes',
                  'toTypes',
                  'markedBy',
                  'createdBy',
                  'labelledBy',
                  'confidence_gt',
                ]}
                handleAddFilter={this.handleAddFilter.bind(this)}
                handleRemoveFilter={this.handleRemoveFilter.bind(this)}
                size="small"
                noDirectFilters={true}
              />
            </div>
          )}
          <div className={classes.filters}>
            {R.map((currentFilter) => {
              const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
              const values = (
                <span>
                  {R.map(
                    (n) => (
                      <span key={n.value}>
                        {n.value && n.value.length > 0
                          ? truncate(n.value, 15)
                          : t('No label')}{' '}
                        {R.last(currentFilter[1]).value !== n.value && (
                          <code>OR</code>
                        )}
                      </span>
                    ),
                    currentFilter[1],
                  )}
                </span>
              );
              return (
                <Tooltip
                  title={
                    <div>
                      <strong>{label}</strong>: {values}
                    </div>
                  }
                >
                  <span>
                    <Chip
                      key={currentFilter[0]}
                      label={
                        <div>
                          <strong>{label}</strong>: {values}
                        </div>
                      }
                      onDelete={this.handleRemoveFilter.bind(
                        this,
                        currentFilter[0],
                      )}
                      size="small"
                    />
                    {R.last(R.toPairs(filters))[0] !== currentFilter[0] && (
                      <Chip
                        size="small"
                        classes={{ root: classes.operator }}
                        label={t('AND')}
                      />
                    )}
                  </span>
                </Tooltip>
              );
            }, R.toPairs(filters))}
          </div>
          <div className="clearfix" />
        </div>
        {variant !== 'inLine' ? (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        ) : (
          this.renderContent()
        )}
      </div>
    );
  }
}

StixCoreRelationshipsList.propTypes = {
  title: PropTypes.string,
  containerId: PropTypes.string,
  types: PropTypes.array,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  height: PropTypes.number,
  dateAttribute: PropTypes.string,
  variant: PropTypes.string,
  config: PropTypes.object,
  onConfigChange: PropTypes.func,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreRelationshipsList);
