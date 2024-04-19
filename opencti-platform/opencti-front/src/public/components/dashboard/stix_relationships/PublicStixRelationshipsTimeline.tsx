import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetTimeline from '../../../../components/dashboard/WidgetTimeline';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import { PublicStixRelationshipsTimelineQuery } from './__generated__/PublicStixRelationshipsTimelineQuery.graphql';
import type { PublicManifestWidget } from '../PublicManifest';

const publicStixRelationshipsTimelineQuery = graphql`
  query PublicStixRelationshipsTimelineQuery(
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

interface PublicStixRelationshipsTimelineComponentProps {
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsTimelineQuery>
}

const PublicStixRelationshipsTimelineComponent = ({
  dataSelection,
  queryRef,
}: PublicStixRelationshipsTimelineComponentProps) => {
  const { publicStixRelationships } = usePreloadedQuery(
    publicStixRelationshipsTimelineQuery,
    queryRef,
  );

  if (
    publicStixRelationships
    && publicStixRelationships?.edges
    && publicStixRelationships.edges.length > 0
  ) {
    const stixRelationshipsEdges = publicStixRelationships.edges;
    const data = stixRelationshipsEdges.flatMap((stixRelationshipEdge) => {
      const stixRelationship = stixRelationshipEdge?.node;
      if (!stixRelationship) return [];
      const remoteNode = stixRelationship.from
      && dataSelection[0].isTo
        ? stixRelationship.to
        : stixRelationship.from;
      if (!remoteNode) return [];

      return {
        value: {
          ...remoteNode,
          created: stixRelationship.created,
        },
      };
    });
    return <WidgetTimeline data={data} />;
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsTimeline = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsTimelineQuery>(
    publicStixRelationshipsTimelineQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <PublicStixRelationshipsTimelineComponent
            dataSelection={dataSelection}
            queryRef={queryRef}
          />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixRelationshipsTimeline;
