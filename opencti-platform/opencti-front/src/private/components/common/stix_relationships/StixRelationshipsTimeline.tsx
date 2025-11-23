import React from 'react';
import { graphql } from 'react-relay';
import { StixRelationshipsTimelineStixRelationshipQuery$data } from '@components/common/stix_relationships/__generated__/StixRelationshipsTimelineStixRelationshipQuery.graphql';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetTimeline from '../../../../components/dashboard/WidgetTimeline';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { WidgetDataSelection, WidgetParameters } from '../../../../utils/widget/widget';

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
          created_at
          created
          modified
          updated_at
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
            ... on BasicObject {
              id
              entity_type
            }
            ... on StixObject {
              representative {
                main
                secondary
              }
            }
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
            # additional info used by the timeline display
            ... on Report {
              description
              published
            }
            ... on AttackPattern {
              description
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
              description
            }
            ... on CourseOfAction {
              description
            }
            ... on Individual {
              description
            }
            ... on Organization {
              description
            }
            ... on Sector {
              description
            }
            ... on System {
              description
            }
            ... on Indicator {
              description
            }
            ... on Infrastructure {
              description
            }
            ... on IntrusionSet {
              description
            }
            ... on Position {
              description
            }
            ... on City {
              description
            }
            ... on AdministrativeArea {
              description
            }
            ... on Country {
              description
            }
            ... on Region {
              description
            }
            ... on Malware {
              description
            }
            ... on ThreatActor {
              description
            }
            ... on Tool {
              description
            }
            ... on Vulnerability {
              description
            }
            ... on Incident {
              description
            }
            ... on Event {
              description
            }
            ... on Channel {
              description
            }
            ... on Narrative {
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
                ... on StixObject {
                  representative {
                    main
                    secondary
                  }
                }
                ... on StixRelationship {
                  representative {
                    main
                    secondary
                  }
                }
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
                  description
                }
                ... on CourseOfAction {
                  description
                }
                ... on Individual {
                  description
                }
                ... on Organization {
                  description
                }
                ... on Sector {
                  description
                }
                ... on System {
                  description
                }
                ... on Indicator {
                  description
                }
                ... on Infrastructure {
                  description
                }
                ... on IntrusionSet {
                  description
                }
                ... on Position {
                  description
                }
                ... on City {
                  description
                }
                ... on Country {
                  description
                }
                ... on Region {
                  description
                }
                ... on Malware {
                  description
                }
                ... on ThreatActor {
                  description
                }
                ... on Tool {
                  description
                }
                ... on Vulnerability {
                  description
                }
                ... on Incident {
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
                ... on StixObject {
                  representative {
                    main
                    secondary
                  }
                }
                ... on StixRelationship {
                  representative {
                    main
                    secondary
                  }
                }
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
                  description
                }
                ... on CourseOfAction {
                  description
                }
                ... on Individual {
                  description
                }
                ... on Organization {
                  description
                }
                ... on Sector {
                  description
                }
                ... on System {
                  description
                }
                ... on Indicator {
                  description
                }
                ... on Infrastructure {
                  description
                }
                ... on IntrusionSet {
                  description
                }
                ... on Position {
                  description
                }
                ... on City {
                  description
                }
                ... on Country {
                  description
                }
                ... on Region {
                  description
                }
                ... on Malware {
                  description
                }
                ... on ThreatActor {
                  description
                }
                ... on Tool {
                  description
                }
                ... on Vulnerability {
                  description
                }
                ... on Incident {
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
            ... on StixObject {
              representative {
                main
                secondary
              }
            }
            ... on StixRelationship {
              representative {
                main
                secondary
              }
            }  
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
              description
            }
            ... on CourseOfAction {
              description
            }
            ... on Individual {
              description
            }
            ... on Organization {
              description
            }
            ... on Sector {
              description
            }
            ... on System {
              description
            }
            ... on Indicator {
              description
            }
            ... on Infrastructure {
              description
            }
            ... on IntrusionSet {
              description
            }
            ... on Position {
              description
            }
            ... on City {
              description
            }
            ... on Country {
              description
            }
            ... on Region {
              description
            }
            ... on Malware {
              description
            }
            ... on ThreatActor {
              description
            }
            ... on Tool {
              description
            }
            ... on Vulnerability {
              description
            }
            ... on Incident {
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
                ... on StixObject {
                  representative {
                    main
                    secondary
                  }
                }
                ... on StixRelationship {
                  representative {
                    main
                    secondary
                  }
                }
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
                  description
                }
                ... on CourseOfAction {
                  description
                }
                ... on Individual {
                  description
                }
                ... on Organization {
                  description
                }
                ... on Sector {
                  description
                }
                ... on System {
                  description
                }
                ... on Indicator {
                  description
                }
                ... on Infrastructure {
                  description
                }
                ... on IntrusionSet {
                  description
                }
                ... on Position {
                  description
                }
                ... on City {
                  description
                }
                ... on Country {
                  description
                }
                ... on Region {
                  description
                }
                ... on Malware {
                  description
                }
                ... on ThreatActor {
                  description
                }
                ... on Tool {
                  description
                }
                ... on Vulnerability {
                  description
                }
                ... on Incident {
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
                ... on StixObject {
                  representative {
                    main
                    secondary
                  }
                }
                ... on StixRelationship {
                  representative {
                    main
                    secondary
                  }
                }
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
                  description
                }
                ... on CourseOfAction {
                  description
                }
                ... on Individual {
                  description
                }
                ... on Organization {
                  description
                }
                ... on Sector {
                  description
                }
                ... on System {
                  description
                }
                ... on Indicator {
                  description
                }
                ... on Infrastructure {
                  description
                }
                ... on IntrusionSet {
                  description
                }
                ... on Position {
                  description
                }
                ... on City {
                  description
                }
                ... on Country {
                  description
                }
                ... on Region {
                  description
                }
                ... on Malware {
                  description
                }
                ... on ThreatActor {
                  description
                }
                ... on Tool {
                  description
                }
                ... on Vulnerability {
                  description
                }
                ... on Incident {
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

interface StixRelationshipsTimelineProps {
  variant: string,
  height?: number,
  startDate: string | null,
  endDate: string | null,
  dataSelection: WidgetDataSelection[],
  parameters?: WidgetParameters,
}

const StixRelationshipsTimeline = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}: StixRelationshipsTimelineProps) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, { startDate, endDate, dateAttribute, isKnowledgeRelationshipWidget: true });
    const fromId = filters?.filters.find((o) => o.key === 'fromId')?.values || null;
    return (
      <QueryRenderer
        query={stixRelationshipsTimelineStixRelationshipQuery}
        variables={{
          first: selection.number ?? 10,
          orderBy: dateAttribute,
          orderMode: selection.sort_mode ?? 'desc',
          filters,
          dynamicFrom: selection.dynamicFrom,
          dynamicTo: selection.dynamicTo,
        }}
        render={({ props }: { props: StixRelationshipsTimelineStixRelationshipQuery$data }) => {
          if (
            props
            && props.stixRelationships
            && props.stixRelationships.edges.length > 0
          ) {
            const stixRelationshipsEdges = props.stixRelationships.edges;
            const data = stixRelationshipsEdges.flatMap((stixRelationshipEdge) => {
              const stixRelationship = stixRelationshipEdge.node;
              const remoteNode = stixRelationship.from
              && fromId && fromId.includes(stixRelationship.from.id)
              && selection.isTo !== false
                ? stixRelationship.to
                : stixRelationship.from;
              if (!remoteNode) return [];

              const restricted = stixRelationship.from === null
                || stixRelationship.to === null;
              const link = restricted
                ? undefined
                : `${resolveLink(remoteNode.entity_type)}/${
                  remoteNode.id
                }/knowledge/relations/${stixRelationship.id}`;
              type StixRelationship = typeof stixRelationship;
              return {
                value: {
                  ...remoteNode,
                  created: stixRelationship[dateAttribute as keyof StixRelationship] ?? stixRelationship.created,
                },
                link,
              };
            });
            return <WidgetTimeline data={data} dateAttribute={dateAttribute} />;
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    );
  };
  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Relationships timeline')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsTimeline;
