import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { resolveLink } from '../../../../utils/Entity';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetTimeline from '../../../../components/dashboard/WidgetTimeline';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import {
  OrderingMode,
  StixRelationshipsOrdering,
  StixRelationshipsTimelineStixRelationshipQuery,
} from '@components/common/stix_relationships/__generated__/StixRelationshipsTimelineStixRelationshipQuery.graphql';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';

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

interface StixRelationshipsTimelineComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsTimelineStixRelationshipQuery>;
  dataSelection: WidgetDataSelection[];
}

const StixRelationshipsTimelineComponent = ({
  queryRef,
  dataSelection,
}: StixRelationshipsTimelineComponentProps) => {
  const data = usePreloadedQuery(
    stixRelationshipsTimelineStixRelationshipQuery,
    queryRef,
  );

  if (!data?.stixRelationships?.edges?.length) {
    return <WidgetNoData />;
  }

  const selection = dataSelection[0];
  const dateAttribute
    = selection.date_attribute?.length ? selection.date_attribute : 'created_at';
  const fromId
    = selection.filters?.filters?.find((o) => o.key === 'fromId')?.values ?? null;
  const edges = data.stixRelationships.edges;
  const timelineData = edges.flatMap((edge) => {
    const rel = edge.node;
    const remoteNode
      = rel.from
        && fromId
        && fromId.includes(rel.from.id)
        && selection.isTo !== false
        ? rel.to
        : rel.from;
    if (!remoteNode) return [];
    const restricted = rel.from === null || rel.to === null;
    const link = restricted
      ? undefined
      : `${resolveLink(remoteNode.entity_type)}/${remoteNode.id}/knowledge/relations/${rel.id}`;
    return {
      value: {
        ...remoteNode,
        created:
            rel[dateAttribute as keyof typeof rel] ?? rel.created,
      },
      link,
    };
  });

  return (
    <WidgetTimeline
      data={timelineData}
      dateAttribute={dateAttribute}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsTimelineStixRelationshipQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const dateAttribute
    = selection.date_attribute?.length ? selection.date_attribute : 'created_at';
  const { startDate, endDate } = computeStartEndDates(config);
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    {
      startDate,
      endDate,
      dateAttribute,
      isKnowledgeRelationshipWidget: true,
    },
  );

  type QueryFilterGroup
    = StixRelationshipsTimelineStixRelationshipQuery['variables']['dynamicFrom'];

  return {
    first: selection.number ?? 10,
    orderBy: dateAttribute as StixRelationshipsOrdering,
    orderMode: (selection.sort_mode ?? 'desc') as OrderingMode,
    filters,
    dynamicFrom: selection.dynamicFrom as unknown as QueryFilterGroup,
    dynamicTo: selection.dynamicTo as unknown as QueryFilterGroup,
  };
};

interface StixRelationshipsTimelineProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsTimeline = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsTimelineProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsTimelineStixRelationshipQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsTimelineStixRelationshipQuery,
    config,
    buildQueryVariables,
  });

  if (isMissingHostEntity) {
    return <WidgetNoHostEntity host={host} />;
  }
  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Relationships timeline')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixRelationshipsTimelineComponent
            queryRef={queryRef}
            dataSelection={resolvedDataSelection}
          />
        </Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default StixRelationshipsTimeline;
