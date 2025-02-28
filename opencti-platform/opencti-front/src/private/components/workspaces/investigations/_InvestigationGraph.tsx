import { graphql, useFragment } from 'react-relay';
import React, { CSSProperties, useMemo, useRef } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/material/styles';
import { knowledgeGraphStixCoreObjectQuery, knowledgeGraphStixRelationshipQuery } from '@components/common/containers/KnowledgeGraphQuery';
import WorkspaceHeader from '@components/workspaces/WorkspaceHeader';
import useInvestigationGraphEdit from '@components/workspaces/investigations/useInvestigationGraphEdit';
import { InvestigationGraphData_fragment$key } from '@components/workspaces/investigations/__generated__/InvestigationGraphData_fragment.graphql';
import useInvestigationGraphAddRelation from '@components/workspaces/investigations/useInvestigationGraphAddRelation';
import useInvestigationGraphDeleteRelation from '@components/workspaces/investigations/useInvestigationGraphDeleteRelation';
import { InvestigationGraph_fragment$data, InvestigationGraph_fragment$key } from './__generated__/InvestigationGraph_fragment.graphql';
import type { Theme } from '../../../../components/Theme';
import Graph from '../../../../utils/graph/Graph';
import { OctiGraphPositions } from '../../../../utils/graph/graph.types';
import { getObjectsToParse } from '../../../../utils/graph/utils/graphUtils';
import { GraphProvider } from '../../../../utils/graph/GraphContext';
import GraphToolbar, { GraphToolbarProps } from '../../../../utils/graph/GraphToolbar';
import { deserializeObjectB64, serializeObjectB64 } from '../../../../utils/object';
import useGraphInteractions from '../../../../utils/graph/utils/useGraphInteractions';

const investigationGraphDataFragment = graphql`
  fragment InvestigationGraphData_fragment on Workspace {
    graph_data
  }
`;

const investigationGraphFragment = graphql`
  fragment InvestigationGraph_fragment on Workspace {
    id
    name
    description
    manifest
    tags
    type
    owner {
      id
      name
      entity_type
    }
    currentUserAccessRight
    ...WorkspaceManageAccessDialog_authorizedMembers
    objects(all: true) {
      edges {
        node {
          ... on BasicObject {
            id
            entity_type
            parent_types
          }
          ... on StixCoreObject {
            created_at
            numberOfConnectedElement
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
            created
          }
          ... on AttackPattern {
            name
            x_mitre_id
          }
          ... on Campaign {
            name
            first_seen
          }
          ... on CourseOfAction {
            name
          }
          ... on Note {
            attribute_abstract
            content
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
            published
          }
          ... on Grouping {
            name
            description
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
          ... on StixMetaObject {
            created
          }
          ... on Label {
            value
            color
          }
          ... on KillChainPhase {
            kill_chain_name
            phase_name
          }
          ... on MarkingDefinition {
            definition
            x_opencti_color
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
          ... on StixRelationship {
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
                start_time
                stop_time
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
          }
          ... on StixRefRelationship {
            created_at
          }
          ... on StixCoreRelationship {
            relationship_type
            start_time
            stop_time
            confidence
            created
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
  }
`;

// export const investigationGraphQuery = graphql`
//   query InvestigationGraphQuery($id: String!) {
//     workspace(id: $id) {
//       ...InvestigationGraph_fragment
//       ...InvestigationGraphData_fragment
//     }
//   }
// `;

interface InvestigationGraphComponentProps {
  investigation: InvestigationGraph_fragment$data
}

const InvestigationGraphComponent = ({
  investigation,
}: InvestigationGraphComponentProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();
  const { addLink } = useGraphInteractions();

  const [commitEditPositions] = useInvestigationGraphEdit();
  const [commitAddRelation] = useInvestigationGraphAddRelation();
  const [commitDeleteRelation] = useInvestigationGraphDeleteRelation();

  const headerHeight = 64;
  const paddingHeight = 25;
  const titleHeight = 44;
  const totalHeight = bannerHeight + headerHeight + paddingHeight + titleHeight;
  const graphContainerStyle: CSSProperties = {
    margin: `-${theme.spacing(3)}`,
    height: `calc(100vh - ${totalHeight}px)`,
  };

  const savePositions = (positions: OctiGraphPositions) => {
    commitEditPositions({
      variables: {
        id: investigation.id,
        input: [{
          key: 'graph_data',
          value: [serializeObjectB64(positions)],
        }],
      },
    });
  };

  const addRelationInGraph: GraphToolbarProps['onAddRelation'] = (rel) => {
    commitAddRelation({
      variables: {
        id: investigation.id,
        input: [{
          key: 'investigated_entities_ids',
          operation: 'add',
          value: [rel.id],
        }],
      },
      onCompleted: () => {
        addLink(rel);
      },
    });
  };

  const removeInGraph: GraphToolbarProps['onRemove'] = (
    ids,
    onCompleted,
  ) => {
    commitDeleteRelation({
      variables: {
        id: investigation.id,
        input: [{
          key: 'investigated_entities_ids',
          operation: 'remove',
          value: ids,
        }],
      },
      onCompleted,
    });
  };

  return (
    <div style={graphContainerStyle} ref={ref}>
      <WorkspaceHeader
        workspace={investigation}
        variant="investigation"
        widgetActions={undefined}
        handleAddWidget={undefined}
      />
      <Graph parentRef={ref} onPositionsChanged={savePositions}>
        <GraphToolbar
          stixCoreObjectRefetchQuery={knowledgeGraphStixCoreObjectQuery}
          relationshipRefetchQuery={knowledgeGraphStixRelationshipQuery}
          entity={investigation}
          onAddRelation={addRelationInGraph}
          onRemove={removeInGraph}
        />
      </Graph>
    </div>
  );
};

interface InvestigationGraphProps {
  data: InvestigationGraph_fragment$key
  graphData: InvestigationGraphData_fragment$key
}

const InvestigationGraph = ({
  data,
  graphData,
}: InvestigationGraphProps) => {
  const investigation = useFragment(investigationGraphFragment, data);
  const { graph_data } = useFragment(investigationGraphDataFragment, graphData);
  const localStorageKey = `investigation-graph-${investigation.id}`;

  const objects = useMemo(() => getObjectsToParse(investigation), [investigation]);
  const positions = useMemo(() => deserializeObjectB64(graph_data), [graph_data]);

  return (
    <GraphProvider
      localStorageKey={localStorageKey}
      objects={objects}
      positions={positions}
      context='investigation'
    >
      <InvestigationGraphComponent investigation={investigation} />
    </GraphProvider>
  );
};

export default InvestigationGraph;
