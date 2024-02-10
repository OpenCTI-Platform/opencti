import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetListCoreObjects from '../../../components/dashboard/WidgetListCoreObjects';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import { useFormatter } from '../../../components/i18n';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import { PublicStixRelationshipsListQuery } from './__generated__/PublicStixRelationshipsListQuery.graphql';
import WidgetListRelationships from '../../../components/dashboard/WidgetListRelationships';

const publicStixRelationshipsListQuery = graphql`
  query PublicStixRelationshipsListQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixRelationships(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
          relationship_type
          confidence
          ... on StixCoreRelationship {
            start_time
            stop_time
            description
            objectLabel {
              id
              value
              color
            }
          }
          ... on StixSightingRelationship {
            first_seen
            last_seen
          }
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
            id
            definition
            x_opencti_order
            x_opencti_color
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
              ... on Report {
                name
              }
              ... on StixRelationship {
                id
                relationship_type
                created_at
                ... on StixCoreRelationship {
                  start_time
                  stop_time
                  description
                }
                ... on StixSightingRelationship {
                  first_seen
                  last_seen
                }
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
                  ... on StixRelationship {
                    relationship_type
                    created_at
                    ... on StixCoreRelationship {
                      start_time
                      stop_time
                      description
                    }
                    ... on StixSightingRelationship {
                      first_seen
                      last_seen
                    }
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
                  ... on Report {
                    name
                  }
                  ... on ExternalReference {
                    source_name
                    url
                    external_id
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
                          ... on Report {
                            name
                          }
                          ... on ExternalReference {
                            source_name
                            url
                            external_id
                          }
                          ... on StixCyberObservable {
                            observable_value
                            x_opencti_description
                          }
                        }
                      }
                    }
                  }
                  ... on StixRelationship {
                    id
                    entity_type
                    relationship_type
                    ... on StixCoreRelationship {
                      start_time
                      stop_time
                      description
                    }
                    ... on StixSightingRelationship {
                      first_seen
                      last_seen
                    }
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
                      ... on StixRelationship {
                        created_at
                        ... on StixCoreRelationship {
                          start_time
                          stop_time
                          description
                        }
                        ... on StixSightingRelationship {
                          first_seen
                          last_seen
                        }
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
                      ... on Report {
                        name
                      }
                      ... on ExternalReference {
                        source_name
                        url
                        external_id
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
                      ... on StixRelationship {
                        created_at
                        ... on StixCoreRelationship {
                          start_time
                          stop_time
                          description
                        }
                        ... on StixSightingRelationship {
                          first_seen
                          last_seen
                        }
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
                      ... on Report {
                        name
                      }
                      ... on ExternalReference {
                        source_name
                        url
                        external_id
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
                              ... on ExternalReference {
                                source_name
                                url
                                external_id
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
                  ... on StixRelationship {
                    created_at
                    relationship_type
                    ... on StixCoreRelationship {
                      start_time
                      stop_time
                      description
                    }
                    ... on StixSightingRelationship {
                      first_seen
                      last_seen
                    }
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
                  ... on StixRelationship {
                    id
                    entity_type
                    relationship_type
                    ... on StixCoreRelationship {
                      start_time
                      stop_time
                      description
                    }
                    ... on StixSightingRelationship {
                      first_seen
                      last_seen
                    }
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
                      ... on StixRelationship {
                        created_at
                        ... on StixCoreRelationship {
                          start_time
                          stop_time
                          description
                        }
                        ... on StixSightingRelationship {
                          first_seen
                          last_seen
                        }
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
                      ... on Report {
                        name
                      }
                      ... on ExternalReference {
                        source_name
                        url
                        external_id
                      }
                      ... on MarkingDefinition {
                        definition_type
                        definition
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
                              ... on ExternalReference {
                                source_name
                                url
                                external_id
                              }
                              ... on MarkingDefinition {
                                definition_type
                                definition
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
                      ... on StixRelationship {
                        created_at
                        ... on StixCoreRelationship {
                          start_time
                          stop_time
                          description
                        }
                        ... on StixSightingRelationship {
                          first_seen
                          last_seen
                        }
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
                              ... on ExternalReference {
                                source_name
                                url
                                external_id
                              }
                              ... on MarkingDefinition {
                                definition_type
                                definition
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
                  ... on StixRelationship {
                    relationship_type
                    created_at
                    ... on StixCoreRelationship {
                      start_time
                      stop_time
                      description
                    }
                    ... on StixSightingRelationship {
                      first_seen
                      last_seen
                    }
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
                          ... on ExternalReference {
                            source_name
                            url
                            external_id
                          }
                          ... on MarkingDefinition {
                            definition_type
                            definition
                          }
                          ... on StixCyberObservable {
                            observable_value
                            x_opencti_description
                          }
                        }
                      }
                    }
                  }
                  ... on StixRelationship {
                    id
                    entity_type
                    relationship_type
                    ... on StixCoreRelationship {
                      start_time
                      stop_time
                      description
                    }
                    ... on StixSightingRelationship {
                      first_seen
                      last_seen
                    }
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
                      ... on StixRelationship {
                        created_at
                        ... on StixCoreRelationship {
                          start_time
                          stop_time
                          description
                        }
                        ... on StixSightingRelationship {
                          first_seen
                          last_seen
                        }
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
                      ... on StixRelationship {
                        created_at
                        ... on StixCoreRelationship {
                          start_time
                          stop_time
                          description
                        }
                        ... on StixSightingRelationship {
                          first_seen
                          last_seen
                        }
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
                  ... on StixRelationship {
                    created_at
                    relationship_type
                    ... on StixCoreRelationship {
                      start_time
                      stop_time
                      description
                    }
                    ... on StixSightingRelationship {
                      first_seen
                      last_seen
                    }
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
                  ... on StixRelationship {
                    id
                    entity_type
                    relationship_type
                    ... on StixCoreRelationship {
                      start_time
                      stop_time
                      description
                    }
                    ... on StixSightingRelationship {
                      first_seen
                      last_seen
                    }
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
                      ... on StixRelationship {
                        created_at
                        ... on StixCoreRelationship {
                          start_time
                          stop_time
                          description
                        }
                        ... on StixSightingRelationship {
                          first_seen
                          last_seen
                        }
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
                      ... on Report {
                        name
                      }
                      ... on ExternalReference {
                        source_name
                        url
                        external_id
                      }
                      ... on MarkingDefinition {
                        definition_type
                        definition
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
                      ... on StixRelationship {
                        created_at
                        ... on StixCoreRelationship {
                          start_time
                          stop_time
                          description
                        }
                        ... on StixSightingRelationship {
                          first_seen
                          last_seen
                        }
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
                      ... on Report {
                        name
                      }
                      ... on ExternalReference {
                        source_name
                        url
                        external_id
                      }
                      ... on MarkingDefinition {
                        definition_type
                        definition
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
            id
            definition
            x_opencti_order
            x_opencti_color
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
            ... on StixRelationship {
              created_at
              ... on StixCoreRelationship {
                start_time
                stop_time
                description
              }
              ... on StixSightingRelationship {
                first_seen
                last_seen
              }
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
            ... on Report {
              name
            }
            ... on Note {
              attribute_abstract
              content
            }
            ... on ExternalReference {
              source_name
              url
              external_id
            }
            ... on MarkingDefinition {
              definition_type
              definition
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
                    ... on Report {
                      name
                    }
                    ... on ExternalReference {
                      source_name
                      url
                      external_id
                    }
                    ... on MarkingDefinition {
                      definition_type
                      definition
                    }
                    ... on StixCyberObservable {
                      observable_value
                      x_opencti_description
                    }
                  }
                }
              }
            }
            ... on StixRelationship {
              id
              entity_type
              relationship_type
              ... on StixCoreRelationship {
                start_time
                stop_time
                description
              }
              ... on StixSightingRelationship {
                first_seen
                last_seen
              }
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
                ... on StixRelationship {
                  created_at
                  ... on StixCoreRelationship {
                    start_time
                    stop_time
                    description
                  }
                  ... on StixSightingRelationship {
                    first_seen
                    last_seen
                  }
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
                ... on Report {
                  name
                }
                ... on ExternalReference {
                  source_name
                  url
                  external_id
                }
                ... on MarkingDefinition {
                  definition_type
                  definition
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
                ... on StixRelationship {
                  created_at
                  ... on StixCoreRelationship {
                    start_time
                    stop_time
                    description
                  }
                  ... on StixSightingRelationship {
                    first_seen
                    last_seen
                  }
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
                ... on Report {
                  name
                }
                ... on ExternalReference {
                  source_name
                  url
                  external_id
                }
                ... on MarkingDefinition {
                  definition_type
                  definition
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
            ... on StixRelationship {
              created_at
              ... on StixCoreRelationship {
                start_time
                stop_time
                description
              }
              ... on StixSightingRelationship {
                first_seen
                last_seen
              }
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
            ... on Report {
              name
            }
            ... on Note {
              attribute_abstract
              content
            }
            ... on ExternalReference {
              source_name
              url
              external_id
            }
            ... on MarkingDefinition {
              definition_type
              definition
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
                    ... on Report {
                      name
                    }
                    ... on ExternalReference {
                      source_name
                      url
                      external_id
                    }
                    ... on MarkingDefinition {
                      definition_type
                      definition
                    }
                    ... on StixCyberObservable {
                      observable_value
                      x_opencti_description
                    }
                  }
                }
              }
            }
            ... on StixRelationship {
              id
              entity_type
              relationship_type
              ... on StixCoreRelationship {
                start_time
                stop_time
                description
              }
              ... on StixSightingRelationship {
                first_seen
                last_seen
              }
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
                ... on Report {
                  name
                }
                ... on ExternalReference {
                  source_name
                  url
                  external_id
                }
                ... on MarkingDefinition {
                  definition_type
                  definition
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
                ... on Report {
                  name
                }
                ... on ExternalReference {
                  source_name
                  url
                  external_id
                }
                ... on MarkingDefinition {
                  definition_type
                  definition
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

interface PublicStixRelationshipsListComponentProps {
  queryRef: PreloadedQuery<PublicStixRelationshipsListQuery>
  dateAttribute: string
}

const PublicStixRelationshipsListComponent = ({
  queryRef,
  dateAttribute,
}: PublicStixRelationshipsListComponentProps) => {
  const { publicStixRelationships } = usePreloadedQuery(
    publicStixRelationshipsListQuery,
    queryRef,
  );

  if (publicStixRelationships?.edges && publicStixRelationships.edges.length > 0) {
    return (
      <WidgetListRelationships
        data={[...publicStixRelationships.edges]}
        dateAttribute={dateAttribute}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsList = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsListQuery>(
    publicStixRelationshipsListQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  const dateAttribute = dataSelection[0].date_attribute ?? 'created_at';

  return (
    <WidgetContainer
      title={parameters.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <PublicStixRelationshipsListComponent
            queryRef={queryRef}
            dateAttribute={dateAttribute}
          />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixRelationshipsList;
