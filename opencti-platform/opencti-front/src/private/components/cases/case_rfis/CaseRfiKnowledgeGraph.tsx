import React, { CSSProperties, useMemo, useRef } from 'react';
import { useTheme } from '@mui/material/styles';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { graphql, useFragment } from 'react-relay';
import { knowledgeGraphStixCoreObjectQuery, knowledgeGraphStixRelationshipQuery } from '@components/common/containers/KnowledgeGraphQuery';
import ContainerHeader from '@components/common/containers/ContainerHeader';
import { CaseRfiKnowledgeGraph_fragment$data, CaseRfiKnowledgeGraph_fragment$key } from './__generated__/CaseRfiKnowledgeGraph_fragment.graphql';
import useCaseRfiKnowledgeGraphEdit from './useCaseRfiKnowledgeGraphEdit';
import useCaseRfiKnowledgeGraphAddRelation from './useCaseRfiKnowledgeGraphAddRelation';
import useCaseRfiKnowledgeGraphDeleteRelation from './useCaseRfiKnowledgeGraphDeleteRelation';
import CaseRfiPopover from './CaseRfiPopover';
import type { Theme } from '../../../../components/Theme';
import Graph, { GraphProps } from '../../../../utils/graph/Graph';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import { encodeGraphData } from '../../../../utils/Graph';
import { GraphProvider } from '../../../../utils/graph/GraphContext';
import useGraphInteractions from '../../../../utils/graph/utils/useGraphInteractions';
import investigationAddFromContainer from '../../../../utils/InvestigationUtils';
import { ObjectToParse } from '../../../../utils/graph/utils/useGraphParser';
import { getObjectsToParse } from '../../../../utils/graph/utils/graphUtils';

const caseRfiGraphFragment = graphql`
  fragment CaseRfiKnowledgeGraph_fragment on CaseRfi {
    id
    name
    x_opencti_graph_data
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
          ... on Task {
            name
          }
          ... on Feedback {
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

export const caseRfiKnowledgeGraphQuery = graphql`
  query CaseRfiKnowledgeGraphQuery($id: String!) {
    caseRfi(id: $id) {
      ...CaseRfiKnowledgeGraph_fragment
    }
  }
`;

interface CaseRfiKnowledgeGraphComponentProps {
  mode: string
  enableReferences: boolean
  caseRfi: CaseRfiKnowledgeGraph_fragment$data
}

const CaseRfiKnowledgeGraphComponent = ({
  enableReferences,
  caseRfi,
  mode,
}: CaseRfiKnowledgeGraphComponentProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();
  const { addLink } = useGraphInteractions();

  const [commitEditPositions] = useCaseRfiKnowledgeGraphEdit();
  const [commitAddRelation] = useCaseRfiKnowledgeGraphAddRelation();
  const [commitDeleteRelation] = useCaseRfiKnowledgeGraphDeleteRelation();

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
        id: caseRfi.id,
        input: [{
          key: 'x_opencti_graph_data',
          value: [encodeGraphData(positions)],
        }],
      },
    });
  };

  const addRelationInGraph: GraphProps['onAddRelation'] = (rel) => {
    commitAddRelation({
      variables: {
        id: caseRfi.id,
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

  const deleteRelationInGraph: GraphProps['onContainerDeleteRelation'] = (
    relId,
    onCompleted,
  ) => {
    commitDeleteRelation({
      variables: {
        id: caseRfi.id,
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
        container={caseRfi}
        currentMode={mode}
        PopoverComponent={<CaseRfiPopover id={caseRfi.id} />}
        link={`/dashboard/cases/rfis/${caseRfi.id}/knowledge`}
        modes={['graph', 'content', 'timeline', 'correlation', 'matrix']}
        onApplied={(suggestions: ObjectToParse[]) => {
          suggestions.forEach((suggestion) => addLink(suggestion));
        }}
        investigationAddFromContainer={investigationAddFromContainer}
      />
      <Graph
        parentRef={ref}
        onPositionsChanged={savePositions}
        enableReferences={enableReferences}
        stixCoreObjectRefetchQuery={knowledgeGraphStixCoreObjectQuery}
        relationshipRefetchQuery={knowledgeGraphStixRelationshipQuery}
        onAddRelation={addRelationInGraph}
        onContainerDeleteRelation={deleteRelationInGraph}
        container={{
          id: caseRfi.id,
          confidence: caseRfi.confidence,
          objects: caseRfi.objects?.edges ?? [],
          createdBy: caseRfi.createdBy,
          objectMarking: caseRfi.objectMarking ?? [],
        }}
      />
    </div>
  );
};

interface ReportKnowledgeGraphtProps extends Omit<CaseRfiKnowledgeGraphComponentProps, 'caseRfi'> {
  data: CaseRfiKnowledgeGraph_fragment$key
}

const CaseRfiKnowledgeGraph = ({
  data,
  ...otherProps
}: ReportKnowledgeGraphtProps) => {
  const caseRfi = useFragment(caseRfiGraphFragment, data);
  const caseRfiData = useMemo(() => getObjectsToParse(caseRfi), [caseRfi]);
  const localStorageKey = `caseRfi-${caseRfi.id}-knowledge-graph`;

  return (
    <GraphProvider localStorageKey={localStorageKey} data={caseRfiData}>
      <CaseRfiKnowledgeGraphComponent caseRfi={caseRfi} {...otherProps} />
    </GraphProvider>
  );
};

export default CaseRfiKnowledgeGraph;
