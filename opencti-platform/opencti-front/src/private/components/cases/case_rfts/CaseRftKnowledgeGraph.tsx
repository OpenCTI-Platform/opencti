import React, { CSSProperties, useMemo, useRef } from 'react';
import { useTheme } from '@mui/material/styles';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { graphql, useFragment } from 'react-relay';
import { knowledgeGraphStixCoreObjectQuery, knowledgeGraphStixRelationshipQuery } from '@components/common/containers/KnowledgeGraphQuery';
import ContainerHeader from '@components/common/containers/ContainerHeader';
import { CaseRftKnowledgeGraphData_fragment$key } from './__generated__/CaseRftKnowledgeGraphData_fragment.graphql';
import { CaseRftKnowledgeGraph_fragment$data, CaseRftKnowledgeGraph_fragment$key } from './__generated__/CaseRftKnowledgeGraph_fragment.graphql';
import useCaseRftKnowledgeGraphEdit from './useCaseRftKnowledgeGraphEdit';
import useCaseRftKnowledgeGraphAddRelation from './useCaseRftKnowledgeGraphAddRelation';
import useCaseRftKnowledgeGraphDeleteRelation from './useCaseRftKnowledgeGraphDeleteRelation';
import CaseRftPopover from './CaseRftPopover';
import type { Theme } from '../../../../components/Theme';
import Graph from '../../../../utils/graph/Graph';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import { GraphProvider } from '../../../../utils/graph/GraphContext';
import useGraphInteractions from '../../../../utils/graph/utils/useGraphInteractions';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import { ObjectToParse } from '../../../../utils/graph/utils/useGraphParser';
import { getObjectsToParse } from '../../../../utils/graph/utils/graphUtils';
import GraphToolbar, { GraphToolbarProps } from '../../../../utils/graph/GraphToolbar';
import { deserializeObjectB64, serializeObjectB64 } from '../../../../utils/object';

const caseRftGraphDataFragment = graphql`
  fragment CaseRftKnowledgeGraphData_fragment on CaseRft {
    x_opencti_graph_data
  }
`;

const caseRftGraphFragment = graphql`
  fragment CaseRftKnowledgeGraph_fragment on CaseRft {
    id
    name
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
          ... on CaseRfi {
            name
          }
          ... on CaseIncident {
            name
          }
          ... on CaseRft {
            name
          }
          ... on Feedback {
            name
          }
          ... on Task {
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

export const caseRftKnowledgeGraphQuery = graphql`
  query CaseRftKnowledgeGraphQuery($id: String!) {
    caseRft(id: $id) {
      ...CaseRftKnowledgeGraph_fragment
      ...CaseRftKnowledgeGraphData_fragment
    }
  }
`;

interface CaseRftKnowledgeGraphComponentProps {
  mode: string
  enableReferences: boolean
  caseRft: CaseRftKnowledgeGraph_fragment$data
}

const CaseRftKnowledgeGraphComponent = ({
  enableReferences,
  caseRft,
  mode,
}: CaseRftKnowledgeGraphComponentProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();
  const { addLink } = useGraphInteractions();

  const [commitEditPositions] = useCaseRftKnowledgeGraphEdit();
  const [commitAddRelation] = useCaseRftKnowledgeGraphAddRelation();
  const [commitDeleteRelation] = useCaseRftKnowledgeGraphDeleteRelation();

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
        id: caseRft.id,
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
        id: caseRft.id,
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
  ) => {
    commitDeleteRelation({
      variables: {
        id: caseRft.id,
        toId: relId,
        relationship_type: 'object',
      },
      onCompleted,
    });
  };

  return (
    <div style={graphContainerStyle} ref={ref}>
      <ContainerHeader
        knowledge
        enableSuggestions
        container={caseRft}
        currentMode={mode}
        PopoverComponent={<CaseRftPopover id={caseRft.id} />}
        link={`/dashboard/cases/rfts/${caseRft.id}/knowledge`}
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
          entity={caseRft}
        />
      </Graph>
    </div>
  );
};

interface ReportKnowledgeGraphtProps extends Omit<CaseRftKnowledgeGraphComponentProps, 'caseRft'> {
  data: CaseRftKnowledgeGraph_fragment$key
  graphData: CaseRftKnowledgeGraphData_fragment$key
}

const CaseRftKnowledgeGraph = ({
  data,
  graphData,
  ...otherProps
}: ReportKnowledgeGraphtProps) => {
  const caseRft = useFragment(caseRftGraphFragment, data);
  const { x_opencti_graph_data } = useFragment(caseRftGraphDataFragment, graphData);
  const localStorageKey = `caseRft-knowledge-graph-${caseRft.id}`;

  const objects = useMemo(() => getObjectsToParse(caseRft), [caseRft]);
  const positions = useMemo(() => deserializeObjectB64(x_opencti_graph_data), [x_opencti_graph_data]);

  return (
    <GraphProvider
      localStorageKey={localStorageKey}
      objects={objects}
      positions={positions}
    >
      <CaseRftKnowledgeGraphComponent caseRft={caseRft} {...otherProps} />
    </GraphProvider>
  );
};

export default CaseRftKnowledgeGraph;
