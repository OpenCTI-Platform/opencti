import React, { CSSProperties, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { graphql, PreloadedQuery, useFragment } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import ContainerHeader from '@components/common/containers/ContainerHeader';
import { knowledgeGraphStixCoreObjectQuery, knowledgeGraphStixRelationshipQuery } from '@components/common/containers/KnowledgeGraphQuery';
import { ContainerHeader_container$key } from '@components/common/containers/__generated__/ContainerHeader_container.graphql';
import { deserializeObjectB64 } from '../../utils/object';
import { getObjectsToParse } from './utils/graphUtils';
import useDebounceCallback from '../../utils/hooks/useDebounceCallback';
import usePreloadedPaginationFragment from '../../utils/hooks/usePreloadedPaginationFragment';
import { GraphContainerKnowledgeObjectsQuery } from './__generated__/GraphContainerKnowledgeObjectsQuery.graphql';
import { GraphContainerKnowledgeObjects_fragment$key } from './__generated__/GraphContainerKnowledgeObjects_fragment.graphql';
import { GraphContainerKnowledgePositions_fragment$key } from './__generated__/GraphContainerKnowledgePositions_fragment.graphql';
import { GraphContainerKnowledgeData_fragment$key } from './__generated__/GraphContainerKnowledgeData_fragment.graphql';
import { GraphProvider } from './GraphContext';
import type { Theme } from '../Theme';
import GraphToolbar, { GraphToolbarProps } from './GraphToolbar';
import { ObjectToParse } from './utils/useGraphParser';
import investigationAddFromContainer from '../../utils/InvestigationUtils';
import useGraphInteractions from './utils/useGraphInteractions';
import Graph from './Graph';
import { OctiGraphPositions } from './graph.types';

// region Relay queries and fragments

const graphContainerKnowledgeDataFragment = graphql`
  fragment GraphContainerKnowledgeData_fragment on Container {
    id
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
    ... on Report {
      name
      published
    }
    ... on Grouping {
      name
      context
    }
    ... on CaseIncident {
      name
    }
    ... on CaseRfi {
      name
    }
    ... on CaseRft {
      name
    }
  }
`;

const graphContainerKnowledgePositionsFragment = graphql`
  fragment GraphContainerKnowledgePositions_fragment on StixDomainObject {
    x_opencti_graph_data
  }
`;

export const graphContainerKnowledgeObjectsQuery = graphql`
  query GraphContainerKnowledgeObjectsQuery($id: String!, $count: Int!, $cursor: ID) {
    ...GraphContainerKnowledgeObjects_fragment
    @arguments(
      id: $id
      count: $count
      cursor: $cursor
    )
  }
`;

const graphContainerKnowledgeObjectsFragment = graphql`
  fragment GraphContainerKnowledgeObjects_fragment on Query
  @refetchable(queryName: "GraphContainerKnowledgeObjectsRefetchQuery")
  @argumentDefinitions(
    id: { type: "String" }
    cursor: { type: "ID" }
    count: { type: "Int", defaultValue: 15 }
  ) {
    container(id: $id) {
      objects(first: $count, after: $cursor)
      @connection(key: "Pagination_graphContainerKnowledge_objects") {
        pageInfo {
          endCursor
          hasNextPage
          globalCount
        }
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
    }
  }
`;

// endregion

interface GraphContainerKnowledgeComponentProps {
  totalData: number
  currentData: number
  dataHeader: ContainerHeader_container$key
  dataContainer: GraphContainerKnowledgeData_fragment$key
  enableReferences: boolean
  onAddRelation: GraphToolbarProps['onAddRelation']
  onDeleteRelation: GraphToolbarProps['onDeleteRelation']
  onPositionsChanged: (positions: OctiGraphPositions) => void
  containerHeaderProps: {
    mode: string
    PopoverComponent: ReactNode
    link: string
    modes: string[]
  }
}

const GraphContainerKnowledgeComponent = ({
  totalData,
  currentData,
  dataHeader,
  dataContainer,
  enableReferences,
  onAddRelation,
  onDeleteRelation,
  onPositionsChanged,
  containerHeaderProps: {
    link,
    mode,
    modes,
    PopoverComponent,
  },
}: GraphContainerKnowledgeComponentProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();

  const {
    addLink,
    setLoadingCurrent,
    setLoadingTotal,
  } = useGraphInteractions();

  const container = useFragment(graphContainerKnowledgeDataFragment, dataContainer);

  useEffect(() => {
    setLoadingTotal(totalData);
    setLoadingCurrent(currentData);
  }, [totalData, currentData]);

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

  return (
    <div style={graphContainerStyle} ref={ref}>
      <ContainerHeader
        knowledge
        enableSuggestions
        container={dataHeader}
        currentMode={mode}
        PopoverComponent={PopoverComponent}
        link={link}
        modes={modes}
        onApplied={(suggestions: ObjectToParse[]) => {
          suggestions.forEach((suggestion) => addLink(suggestion));
        }}
        investigationAddFromContainer={investigationAddFromContainer}
      />
      <Graph parentRef={ref} onPositionsChanged={onPositionsChanged}>
        <GraphToolbar
          enableReferences={enableReferences}
          stixCoreObjectRefetchQuery={knowledgeGraphStixCoreObjectQuery}
          relationshipRefetchQuery={knowledgeGraphStixRelationshipQuery}
          onAddRelation={onAddRelation}
          onDeleteRelation={onDeleteRelation}
          entity={container}
        />
      </Graph>
    </div>
  );
};

const REFETCH_DEBOUNCE_MS = 50;

interface GraphContainerKnowledgeProps
  extends Omit<GraphContainerKnowledgeComponentProps, 'data' | 'currentData' | 'totalData'> {
  containerId: string
  containerType: string
  dataPositions: GraphContainerKnowledgePositions_fragment$key
  queryObjectsRef: PreloadedQuery<GraphContainerKnowledgeObjectsQuery>
  pageSize: number
}

const GraphContainerKnowledge = ({
  containerId,
  containerType,
  dataPositions,
  queryObjectsRef,
  pageSize,
  ...otherProps
}: GraphContainerKnowledgeProps) => {
  const localStorageKey = `${containerType}-knowledge-graph-${containerId}`;
  const [dataLoaded, setDataLoaded] = useState(0);

  const {
    data: { container },
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<
  GraphContainerKnowledgeObjectsQuery,
  GraphContainerKnowledgeObjects_fragment$key
  >({
    linesQuery: graphContainerKnowledgeObjectsQuery,
    linesFragment: graphContainerKnowledgeObjectsFragment,
    queryRef: queryObjectsRef,
  });

  // Use a debounce to avoid spamming too quickly the backend.
  const debounceFetchMore = useDebounceCallback(
    () => { loadMore(pageSize); },
    REFETCH_DEBOUNCE_MS,
  );
  // When finishing fetching a page, get the next if any.
  useEffect(() => {
    if (!isLoadingMore() && hasMore()) {
      debounceFetchMore();
    }
  }, [isLoadingMore(), hasMore()]);

  useEffect(() => {
    setDataLoaded(container?.objects?.edges?.length ?? 0);
  }, [container]);

  const { x_opencti_graph_data } = useFragment(
    graphContainerKnowledgePositionsFragment,
    dataPositions,
  );

  const objects = useMemo(() => (container ? getObjectsToParse(container) : []), [container]);
  const positions = useMemo(() => deserializeObjectB64(x_opencti_graph_data), [x_opencti_graph_data]);

  return (
    <GraphProvider
      localStorageKey={localStorageKey}
      objects={objects}
      positions={positions}
    >
      <GraphContainerKnowledgeComponent
        currentData={dataLoaded}
        totalData={container?.objects?.pageInfo.globalCount ?? 1}
        {...otherProps}
      />
    </GraphProvider>
  );
};

export default GraphContainerKnowledge;
