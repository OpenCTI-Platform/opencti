import React, { ReactNode, Suspense, useRef } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { getDefaultWidgetColumns } from '../../widgets/WidgetListsDefaultColumns';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetListRelationships from '../../../../components/dashboard/WidgetListRelationships';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetNoSavedFilters from 'src/components/dashboard/WidgetNoSavedFilters';
import type { StixRelationshipsListQuery, StixRelationshipsOrdering } from '@components/common/stix_relationships/__generated__/StixRelationshipsListQuery.graphql';
import { OrderingMode } from '@components/common/stix_relationships/__generated__/StixRelationshipsListQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';

export const stixRelationshipsListQuery = graphql`
  query StixRelationshipsListQuery(
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
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
      search: $search
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
          relationship_type
          confidence
          representative {
            main
          }
          from {
            ... on StixObject {
              representative {
                main
              }
            }
            ... on StixRelationship {
              representative {
                main
              }
            }
          }
          to {
            ... on StixObject {
              representative {
                main
              }
            }
            ... on StixRelationship {
              representative {
                main
              }
            }
          }
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
          created
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
                              ... on MalwareAnalysis {
                                result_name
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
                  ... on MalwareAnalysis {
                    result_name
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
                          ... on MalwareAnalysis {
                            result_name
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
                      ... on MalwareAnalysis {
                        result_name
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
                              ... on MalwareAnalysis {
                                result_name
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
                      ... on MalwareAnalysis {
                        result_name
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
                              ... on MalwareAnalysis {
                                result_name
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
                  ... on MalwareAnalysis {
                    result_name
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
                          ... on MalwareAnalysis {
                            result_name
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
                      ... on MalwareAnalysis {
                        result_name
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
                      ... on MalwareAnalysis {
                        result_name
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
                              ... on MalwareAnalysis {
                                result_name
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
                  ... on MalwareAnalysis {
                    result_name
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
                              ... on MalwareAnalysis {
                                result_name
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
                      ... on MalwareAnalysis {
                        result_name
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
                              ... on MalwareAnalysis {
                                result_name
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
              representative {
                main
              }
              entity_type
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
            ... on MalwareAnalysis {
              result_name
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
                    ... on MalwareAnalysis {
                      result_name
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
                ... on MalwareAnalysis {
                  result_name
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
                  representative {
                    main
                  }
                  entity_type
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
                ... on MalwareAnalysis {
                  result_name
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
            ... on MalwareAnalysis {
              result_name
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
                    ... on MalwareAnalysis {
                      result_name
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
                ... on MalwareAnalysis {
                  result_name
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
                ... on MalwareAnalysis {
                  result_name
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

interface StixRelationshipsListComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsListQuery>;
  dataSelection: WidgetDataSelection[];
  widgetId: string;
  rootRef: React.RefObject<HTMLDivElement | null>;
}

const StixRelationshipsListComponent = ({
  queryRef,
  dataSelection,
  widgetId,
  rootRef,
}: StixRelationshipsListComponentProps) => {
  const data = usePreloadedQuery(stixRelationshipsListQuery, queryRef);

  const selection = dataSelection[0];
  const columns
    = selection.columns ?? getDefaultWidgetColumns('relationships');
  const edges = data?.stixRelationships?.edges ?? [];

  if (!edges.length) {
    return <WidgetNoData />;
  }
  return (
    <WidgetListRelationships
      data={edges}
      widgetId={widgetId}
      columns={columns}
      rootRef={rootRef.current ?? undefined}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
): StixRelationshipsListQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const dateAttribute = selection.date_attribute?.length
    ? selection.date_attribute
    : 'created_at';
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    {
      dateAttribute,
      isKnowledgeRelationshipWidget: true,
    },
  );

  return {
    first: selection.number ?? 50,
    orderBy: (dateAttribute as StixRelationshipsOrdering),
    orderMode: (selection.sort_mode ?? 'desc') as OrderingMode,
    filters: normalizeFilterGroupForBackend(filters),
    dynamicFrom: normalizeFilterGroupForBackend(selection.dynamicFrom),
    dynamicTo: normalizeFilterGroupForBackend(selection.dynamicTo),
  };
};

interface StixRelationshipsListProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
  widgetId: string;
}

const StixRelationshipsList = ({
  variant,
  height,
  dataSelection,
  widgetId,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsListProps) => {
  const { t_i18n } = useFormatter();
  const rootRef = useRef<HTMLDivElement>(null);
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsListQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsListQuery,
    config,
    buildQueryVariables,
  });
  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (isMissingSavedFilters) {
      return <WidgetNoSavedFilters />;
    }

    if (!queryRef) return null;

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixRelationshipsListComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
          widgetId={widgetId}
          rootRef={rootRef}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      padding="horizontal"
      height={height}
      title={parameters.title ?? t_i18n('Relationships list')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div ref={rootRef} style={{ height: '100%' }}>
        {renderContent()}
      </div>
    </WidgetContainer>
  );
};

export default StixRelationshipsList;
