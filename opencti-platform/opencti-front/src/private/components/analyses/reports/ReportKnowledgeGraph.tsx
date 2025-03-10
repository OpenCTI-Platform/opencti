import React, { CSSProperties, useMemo, useRef } from 'react';
import { useTheme } from '@mui/material/styles';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { graphql, useFragment } from 'react-relay';
import { knowledgeGraphStixCoreObjectQuery, knowledgeGraphStixRelationshipQuery } from '@components/common/containers/KnowledgeGraphQuery';
import ReportPopover from '@components/analyses/reports/ReportPopover';
import ContainerHeader from '@components/common/containers/ContainerHeader';
import useReportKnowledgeGraphDeleteRelation from './useReportKnowledgeGraphDeleteRelation';
import { ReportKnowledgeGraph_fragment$data, ReportKnowledgeGraph_fragment$key } from './__generated__/ReportKnowledgeGraph_fragment.graphql';
import type { Theme } from '../../../../components/Theme';
import Graph from '../../../../utils/graph/Graph';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import useReportKnowledgeGraphAddRelation from './useReportKnowledgeGraphAddRelation';
import { GraphProvider } from '../../../../utils/graph/GraphContext';
import useGraphInteractions from '../../../../utils/graph/utils/useGraphInteractions';
import useReportKnowledgeGraphEdit from './useReportKnowledgeGraphEdit';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import { ObjectToParse } from '../../../../utils/graph/utils/useGraphParser';
import { getObjectsToParse } from '../../../../utils/graph/utils/graphUtils';
import GraphToolbar, { GraphToolbarProps } from '../../../../utils/graph/GraphToolbar';
import { deserializeObjectB64, serializeObjectB64 } from '../../../../utils/object';
import { ReportKnowledgeGraphData_fragment$key } from './__generated__/ReportKnowledgeGraphData_fragment.graphql';

const reportGraphDataFragment = graphql`
  fragment ReportKnowledgeGraphData_fragment on Report {
    x_opencti_graph_data
  }
`;

const reportGraphFragment = graphql`
  fragment ReportKnowledgeGraph_fragment on Report {
    id
    name
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

export const reportKnowledgeGraphQuery = graphql`
  query ReportKnowledgeGraphQuery($id: String) {
    report(id: $id) {
      ...ReportKnowledgeGraph_fragment
      ...ReportKnowledgeGraphData_fragment
    }
  }
`;

interface ReportKnowledgeGraphComponentProps {
  mode: string
  enableReferences: boolean
  report: ReportKnowledgeGraph_fragment$data
}

const ReportKnowledgeGraphComponent = ({
  enableReferences,
  report,
  mode,
}: ReportKnowledgeGraphComponentProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();
  const { addLink } = useGraphInteractions();

  const [commitEditPositions] = useReportKnowledgeGraphEdit();
  const [commitAddRelation] = useReportKnowledgeGraphAddRelation();
  const [commitDeleteRelation] = useReportKnowledgeGraphDeleteRelation();

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

  const savePositions = (positions: OctiGraphPositions) => {
    commitEditPositions({
      variables: {
        id: report.id,
        input: [{
          key: 'x_opencti_graph_data',
          value: [serializeObjectB64(positions)],
        }],
      },
    });
  };

  const addRelationInGraph: GraphToolbarProps['onAddRelation'] = (rel) => {
    commitAddRelation({
      variables: {
        id: report.id,
        input: {
          toId: rel.id,
          relationship_type: 'object',
        },
      },
      onCompleted: () => {
        addLink(rel);
      },
    });
  };

  const deleteRelationInGraph: GraphToolbarProps['onDeleteRelation'] = (
    relId,
    onCompleted,
    commitMessage,
    references,
  ) => {
    commitDeleteRelation({
      variables: {
        id: report.id,
        toId: relId,
        relationship_type: 'object',
        commitMessage,
        references,
      },
      onCompleted,
    });
  };

  return (
    <div style={graphContainerStyle} ref={ref}>
      <ContainerHeader
        knowledge
        enableSuggestions
        container={report}
        currentMode={mode}
        PopoverComponent={<ReportPopover id={report.id} />}
        link={`/dashboard/analyses/reports/${report.id}/knowledge`}
        modes={['graph', 'content', 'timeline', 'correlation', 'matrix']}
        onApplied={(suggestions: ObjectToParse[]) => {
          suggestions.forEach((suggestion) => addLink(suggestion));
        }}
        investigationAddFromContainer={investigationAddFromContainer}
      />
      <Graph parentRef={ref} onPositionsChanged={savePositions}>
        <GraphToolbar
          enableReferences={enableReferences}
          stixCoreObjectRefetchQuery={knowledgeGraphStixCoreObjectQuery}
          relationshipRefetchQuery={knowledgeGraphStixRelationshipQuery}
          onAddRelation={addRelationInGraph}
          onDeleteRelation={deleteRelationInGraph}
          entity={report}
        />
      </Graph>
    </div>
  );
};

interface ReportKnowledgeGraphtProps extends Omit<ReportKnowledgeGraphComponentProps, 'report'> {
  data: ReportKnowledgeGraph_fragment$key
  graphData: ReportKnowledgeGraphData_fragment$key
}

const ReportKnowledgeGraph = ({
  data,
  graphData,
  ...otherProps
}: ReportKnowledgeGraphtProps) => {
  const report = useFragment(reportGraphFragment, data);
  const { x_opencti_graph_data } = useFragment(reportGraphDataFragment, graphData);
  const localStorageKey = `report-knowledge-graph-${report.id}`;

  const objects = useMemo(() => getObjectsToParse(report), [report]);
  const positions = useMemo(() => deserializeObjectB64(x_opencti_graph_data), [x_opencti_graph_data]);

  return (
    <GraphProvider
      localStorageKey={localStorageKey}
      objects={objects}
      positions={positions}
    >
      <ReportKnowledgeGraphComponent report={report} {...otherProps} />
    </GraphProvider>
  );
};

export default ReportKnowledgeGraph;
