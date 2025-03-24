import { graphql, PreloadedQuery, useFragment } from 'react-relay';
import React, { CSSProperties, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { useTheme } from '@mui/material/styles';
import { knowledgeGraphStixCoreObjectQuery, knowledgeGraphStixRelationshipQuery } from '@components/common/containers/KnowledgeGraphQuery';
import WorkspaceHeader from '@components/workspaces/WorkspaceHeader';
import fetchMetaObjectsCount from '@components/workspaces/investigations/utils/fetchMetaObjectsCount';
import { InvestigationGraphObjectsQuery } from './__generated__/InvestigationGraphObjectsQuery.graphql';
import { InvestigationGraphObjects_fragment$key } from './__generated__/InvestigationGraphObjects_fragment.graphql';
import { InvestigationGraphQuery$data } from './__generated__/InvestigationGraphQuery.graphql';
import useInvestigationGraphEdit from './useInvestigationGraphEdit';
import { InvestigationGraphData_fragment$key } from './__generated__/InvestigationGraphData_fragment.graphql';
import useInvestigationGraphUpdateEntities from './useInvestigationGraphUpdateEntities';
import { InvestigationGraph_fragment$key } from './__generated__/InvestigationGraph_fragment.graphql';
import type { Theme } from '../../../../components/Theme';
import Graph from '../../../../components/graph/Graph';
import { OctiGraphPositions } from '../../../../components/graph/graph.types';
import { getObjectsToParse } from '../../../../components/graph/utils/graphUtils';
import { GraphProvider, useGraphContext } from '../../../../components/graph/GraphContext';
import GraphToolbar, { GraphToolbarProps } from '../../../../components/graph/GraphToolbar';
import { deserializeObjectB64, serializeObjectB64 } from '../../../../utils/object';
import useGraphInteractions from '../../../../components/graph/utils/useGraphInteractions';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useDebounceCallback from '../../../../utils/hooks/useDebounceCallback';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { ObjectToParse } from '../../../../components/graph/utils/useGraphParser';

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
  }
`;

const investigationGraphObjectsQuery = graphql`
  query InvestigationGraphObjectsQuery($id: String!, $count: Int!, $cursor: ID) {
    ...InvestigationGraphObjects_fragment
    @arguments(
      id: $id
      count: $count
      cursor: $cursor
    )
  }
`;

const investigationGraphObjectsFragment = graphql`
  fragment InvestigationGraphObjects_fragment on Query
  @refetchable(queryName: "InvestigationGraphObjectsRefetchQuery")
  @argumentDefinitions(
    id: { type: "String!" }
    cursor: { type: "ID" }
    count: { type: "Int", defaultValue: 15 }
  ) {
    workspace(id: $id) {
      objects(first: $count, after: $cursor)
      @connection(key: "Pagination_investigationGraph_objects") {
        pageInfo {
          endCursor
          hasNextPage
          globalCount
        }
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
              numberOfConnectedElement
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
  }
`;

export const investigationGraphQuery = graphql`
  query InvestigationGraphQuery($id: String!) {
    workspace(id: $id) {
      ...InvestigationGraph_fragment
      ...InvestigationGraphData_fragment
    }
  }
`;

// To count the number of relationships for MetaObjects and Identities.
//
// /!\ It counts only rels that point towards given ids. So the value may not be
// exactly the total number of rels in some cases when entities (Identities) also
// have relations where there are the source of the relation.
// This issue can be fixed by making a second query fetching the count in the
// other direction.
export const investigationGraphCountRelToQuery = graphql`
  query InvestigationGraphStixCountRelToQuery($objectIds: [String!]!) {
    stixRelationshipsDistribution(
      field: "internal_id"
      isTo: true
      operation: count
      toId: $objectIds
      relationship_type: "stix-relationship"
    ) {
      label
      value
    }
  }
`;

interface InvestigationGraphComponentProps {
  totalData: number
  currentData: number
  dataInvestigation: InvestigationGraph_fragment$key
}

const InvestigationGraphComponent = ({
  totalData,
  currentData,
  dataInvestigation,
}: InvestigationGraphComponentProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();
  const { rawObjects } = useGraphContext();

  const {
    addLink,
    setLoadingCurrent,
    setLoadingTotal,
    rebuildGraphData,
  } = useGraphInteractions();

  const investigation = useFragment(investigationGraphFragment, dataInvestigation);

  useEffect(() => {
    setLoadingTotal(totalData);
    setLoadingCurrent(currentData);
  }, [totalData, currentData]);

  const [commitEditPositions] = useInvestigationGraphEdit();
  const [commitUpdateEntities] = useInvestigationGraphUpdateEntities();

  const headerHeight = 64;
  const paddingHeight = 25;
  const titleHeight = 44;
  const totalHeight = bannerHeight + headerHeight + paddingHeight + titleHeight;
  const graphContainerStyle: CSSProperties = {
    margin: `0 -${theme.spacing(3)}`,
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

  const updateInvestigationEntitiesGraph = (
    ids: string[],
    operation: 'add' | 'remove' | 'replace',
    onCompleted?: () => void,
  ) => {
    commitUpdateEntities({
      variables: {
        id: investigation.id,
        input: [{
          key: 'investigated_entities_ids',
          operation,
          value: ids,
        }],
      },
      onCompleted,
    });
  };

  const addRelationInGraph: GraphToolbarProps['onAddRelation'] = (rel) => {
    updateInvestigationEntitiesGraph([rel.id], 'add', () => addLink(rel));
  };

  const addInGraph: GraphToolbarProps['onInvestigationExpand'] = async (newObjects) => {
    updateInvestigationEntitiesGraph(newObjects.map((o) => o.id), 'add');
    rebuildGraphData([
      ...rawObjects,
      ...await fetchMetaObjectsCount(newObjects),
    ]);
  };

  const removeInGraph: GraphToolbarProps['onRemove'] = (ids, onCompleted) => {
    updateInvestigationEntitiesGraph(ids, 'remove', onCompleted);
  };

  const replaceInGraph: GraphToolbarProps['onInvestigationRollback'] = (ids, onCompleted) => {
    updateInvestigationEntitiesGraph(ids, 'replace', onCompleted);
  };

  return (
    <div style={{ display: 'flex', flexFlow: 'column' }}>
      <WorkspaceHeader
        workspace={investigation}
        variant="investigation"
        widgetActions={undefined}
        handleAddWidget={undefined}
      />
      <div style={graphContainerStyle} ref={ref}>
        <Graph parentRef={ref} onPositionsChanged={savePositions}>
          <GraphToolbar
            stixCoreObjectRefetchQuery={knowledgeGraphStixCoreObjectQuery}
            relationshipRefetchQuery={knowledgeGraphStixRelationshipQuery}
            entity={investigation}
            onAddRelation={addRelationInGraph}
            onRemove={removeInGraph}
            onInvestigationExpand={addInGraph}
            onInvestigationRollback={replaceInGraph}
          />
        </Graph>
      </div>
    </div>
  );
};

const REFETCH_DEBOUNCE_MS = 50;

interface InvestigationGraphLoaderProps
  extends Omit<InvestigationGraphComponentProps, 'currentData' | 'totalData'> {
  investigationId: string
  dataPositions: InvestigationGraphData_fragment$key
  queryObjectsRef: PreloadedQuery<InvestigationGraphObjectsQuery>
  pageSize: number
}

const InvestigationGraphLoader = ({
  investigationId,
  dataPositions,
  queryObjectsRef,
  pageSize,
  ...otherProps
}: InvestigationGraphLoaderProps) => {
  const localStorageKey = `investigation-graph-${investigationId}`;
  const [dataLoaded, setDataLoaded] = useState(0);

  const {
    data: { workspace },
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<
  InvestigationGraphObjectsQuery,
  InvestigationGraphObjects_fragment$key
  >({
    linesQuery: investigationGraphObjectsQuery,
    linesFragment: investigationGraphObjectsFragment,
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
    setDataLoaded(workspace?.objects?.edges?.length ?? 0);
  }, [workspace]);

  const { graph_data } = useFragment(investigationGraphDataFragment, dataPositions);

  const [objects, setObjects] = useState<ObjectToParse[]>([]);
  useEffect(() => {
    const workspaceObjects = workspace ? getObjectsToParse(workspace) : [];
    async function fetchCounts() {
      setObjects(await fetchMetaObjectsCount(workspaceObjects));
    }
    fetchCounts();
  }, [workspace]);

  const positions = useMemo(() => deserializeObjectB64(graph_data), [graph_data]);

  return (
    <GraphProvider
      localStorageKey={localStorageKey}
      objects={objects}
      positions={positions}
      context='investigation'
    >
      <InvestigationGraphComponent
        currentData={dataLoaded}
        totalData={workspace?.objects?.pageInfo.globalCount ?? 1}
        {...otherProps}
      />
    </GraphProvider>
  );
};

interface InvestigationGraphProps {
  id: string
  data: NonNullable<InvestigationGraphQuery$data['workspace']>
}

const InvestigationGraph = ({
  id,
  data,
}: InvestigationGraphProps) => {
  const PAGE_SIZE = 500;
  const queryObjectsRef = useQueryLoading<InvestigationGraphObjectsQuery>(
    investigationGraphObjectsQuery,
    { id, count: PAGE_SIZE },
  );

  if (!queryObjectsRef) return null;

  return (
    <Suspense fallback={<Loader />}>
      <InvestigationGraphLoader
        pageSize={PAGE_SIZE}
        queryObjectsRef={queryObjectsRef}
        investigationId={id}
        dataPositions={data}
        dataInvestigation={data}
      />
    </Suspense>
  );
};

export default InvestigationGraph;
