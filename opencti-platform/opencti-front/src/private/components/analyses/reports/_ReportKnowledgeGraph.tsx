import React, { CSSProperties, useMemo, useRef } from 'react';
import { useTheme } from '@mui/material/styles';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { graphql, useFragment } from 'react-relay';
import { knowledgeGraphStixCoreObjectQuery, knowledgeGraphStixRelationshipQuery } from '@components/common/containers/KnowledgeGraphQuery';
import { ReportKnowledgeGraph_fragment$key } from './__generated__/ReportKnowledgeGraph_fragment.graphql';
import type { Theme } from '../../../../components/Theme';
import Graph from '../../../../utils/graph/Graph';
import useGraphParser from '../../../../utils/graph/utils/useGraphParser';
import { deserializeObject } from '../../../../utils/object';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { ReportKnowledgeGraphDataMutation } from './__generated__/ReportKnowledgeGraphDataMutation.graphql';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import { encodeGraphData } from '../../../../utils/Graph';

const reportGraphFragment = graphql`
  fragment ReportKnowledgeGraph_fragment on Report {
    id
    name
    x_opencti_graph_data
    published
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
    objects(all: true) {
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
            x_mitre_id
          }
          ... on Campaign {
            name
            first_seen
            last_seen
          }
          ... on ObservedData {
            name
          }
          ... on CourseOfAction {
            name
          }
          ... on Note {
            attribute_abstract
            content
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            published
          }
          ... on Grouping {
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
            valid_from
          }
          ... on Infrastructure {
            name
          }
          ... on IntrusionSet {
            name
            first_seen
            last_seen
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
            first_seen
            last_seen
          }
          ... on MalwareAnalysis {
            result_name
          }
          ... on ThreatActor {
            name
            entity_type
            first_seen
            last_seen
          }
          ... on Tool {
            name
          }
          ... on Vulnerability {
            name
          }
          ... on Incident {
            name
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
          ... on StixFile {
            observableName: name
            x_opencti_additional_names
            hashes {
              algorithm
              hash
            }
          }
          ... on Label {
            value
            color
          }
          ... on MarkingDefinition {
            definition
            x_opencti_color
          }
          ... on KillChainPhase {
            kill_chain_name
            phase_name
          }
          ... on ExternalReference {
            url
            source_name
          }
          ... on BasicRelationship {
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
            start_time
            stop_time
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
            datable
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
`;

export const reportGraphDataMutation = graphql`
  mutation ReportKnowledgeGraphDataMutation($id: ID!, $input: [EditInput]!) {
    reportEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

interface ReportKnowledgeGraphProps {
  enableReferences: boolean
  data: ReportKnowledgeGraph_fragment$key
}

const ReportKnowledgeGraph = ({ enableReferences, data }: ReportKnowledgeGraphProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();
  const { buildGraphData } = useGraphParser();

  const [commitGraphDataMutation] = useApiMutation<ReportKnowledgeGraphDataMutation>(
    reportGraphDataMutation,
  );

  const report = useFragment(reportGraphFragment, data);
  const localStorageKey = `report-${report.id}-knowledge-graph`;

  const headerHeight = 64;
  const paddingHeight = 25;
  const breadcrumbHeight = 38;
  const titleHeight = 44;
  const tabsHeight = 72;
  const totalHeight = bannerHeight + headerHeight + paddingHeight + breadcrumbHeight + titleHeight + tabsHeight;
  const graphContainerStyle: CSSProperties = {
    margin: `-${theme.spacing(3)}`,
    height: `calc(100vh - ${totalHeight}px)`,
  };

  const graphData = useMemo(() => (
    buildGraphData(
      (report.objects?.edges ?? []).map((n) => ({ ...n.node, types: n.types })),
      deserializeObject(report.x_opencti_graph_data),
    )
  ), [report]);

  const savePositions = (positions: OctiGraphPositions) => {
    commitGraphDataMutation({
      variables: {
        id: report.id,
        input: [{
          key: 'x_opencti_graph_data',
          value: [encodeGraphData(positions)],
        }],
      },
    });
  };

  return (
    <div style={graphContainerStyle} ref={ref}>
      <Graph
        parentRef={ref}
        graphData={graphData}
        localStorageKey={localStorageKey}
        onPositionsChanged={savePositions}
        enableReferences={enableReferences}
        stixCoreObjectRefetchQuery={knowledgeGraphStixCoreObjectQuery}
        relationshipRefetchQuery={knowledgeGraphStixRelationshipQuery}
        container={{
          id: report.id,
          confidence: report.confidence,
          objects: report.objects?.edges ?? [],
          createdBy: report.createdBy,
          objectMarking: report.objectMarking ?? [],
        }}
      />
    </div>
  );
};

export default ReportKnowledgeGraph;
