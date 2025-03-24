import { graphql, PreloadedQuery, useFragment } from 'react-relay';
import React, { CSSProperties, useEffect, useMemo, useRef, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import { useSettingsMessagesBannerHeight } from '@components/settings/settings_messages/SettingsMessagesBanner';
import { knowledgeCorrelationStixCoreObjectQuery, knowledgeCorrelationStixCoreRelationshipQuery } from '@components/common/containers/KnowledgeCorrelationQuery';
import type { Theme } from '../Theme';
import Graph from './Graph';
import GraphToolbar from './GraphToolbar';
import { GraphProvider } from './GraphContext';
import usePreloadedPaginationFragment from '../../utils/hooks/usePreloadedPaginationFragment';
import { GraphContainerCorrelationObjectsQuery } from './__generated__/GraphContainerCorrelationObjectsQuery.graphql';
import { GraphContainerCorrelationObjects_fragment$key } from './__generated__/GraphContainerCorrelationObjects_fragment.graphql';
import useDebounceCallback from '../../utils/hooks/useDebounceCallback';
import { GraphContainerCorrelationPositions_fragment$key } from './__generated__/GraphContainerCorrelationPositions_fragment.graphql';
import { getObjectsToParse } from './utils/graphUtils';
import { deserializeObjectB64 } from '../../utils/object';
import { OctiGraphPositions } from './graph.types';
import useGraphInteractions from './utils/useGraphInteractions';

// region Relay queries and fragments

const graphContainerCorrelationPositionsFragment = graphql`
  fragment GraphContainerCorrelationPositions_fragment on StixDomainObject {
    x_opencti_graph_data
  }
`;

export const graphContainerCorrelationObjectsQuery = graphql`
  query GraphContainerCorrelationObjectsQuery($id: String!, $count: Int!, $cursor: ID) {
    ...GraphContainerCorrelationObjects_fragment
    @arguments(
      id: $id
      count: $count
      cursor: $cursor
    )
  }
`;

const graphContainerCorrelationObjectsFragment = graphql`
  fragment GraphContainerCorrelationObjects_fragment on Query
  @refetchable(queryName: "GraphContainerCorrelationObjectsRefetchQuery")
  @argumentDefinitions(
    id: { type: "String" }
    cursor: { type: "ID" }
    count: { type: "Int", defaultValue: 15 }
  ) {
    container(id: $id) {
      objects(first: $count, after: $cursor)
      @connection(key: "Pagination_graphContainerCorrelation_objects") {
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
              reports(first: 20) {
                edges {
                  node {
                    id
                    name
                    published
                    confidence
                    entity_type
                    parent_types
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
              groupings(first: 20) {
                edges {
                  node {
                    id
                    name
                    context
                    confidence
                    entity_type
                    parent_types
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
              cases(first: 20) {
                edges {
                  node {
                    id
                    name
                    confidence
                    entity_type
                    parent_types
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
              last_seen
            }
            ... on CourseOfAction {
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
            ... on Case {
              name
            }
            ... on Incident {
              name
              first_seen
              last_seen
            }
            ... on StixCyberObservable {
              observable_value
              reports(first: 20) {
                edges {
                  node {
                    id
                    name
                    published
                    confidence
                    entity_type
                    parent_types
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
              groupings(first: 20) {
                edges {
                  node {
                    id
                    name
                    context
                    confidence
                    entity_type
                    parent_types
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
              cases(first: 20) {
                edges {
                  node {
                    id
                    name
                    confidence
                    entity_type
                    parent_types
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
            ... on StixFile {
              observableName: name
            }
          }
        }
      }
    }
  }
`;

// endregion

interface GraphContainerCorrelationComponentProps {
  totalData: number
  currentData: number
  onPositionsChanged: (positions: OctiGraphPositions) => void
}

const GraphContainerCorrelationComponent = ({
  totalData,
  currentData,
  onPositionsChanged,
}: GraphContainerCorrelationComponentProps) => {
  const ref = useRef(null);
  const theme = useTheme<Theme>();
  const bannerHeight = useSettingsMessagesBannerHeight();

  const {
    setLoadingCurrent,
    setLoadingTotal,
  } = useGraphInteractions();

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
      <Graph parentRef={ref} onPositionsChanged={onPositionsChanged}>
        <GraphToolbar
          stixCoreObjectRefetchQuery={knowledgeCorrelationStixCoreObjectQuery}
          relationshipRefetchQuery={knowledgeCorrelationStixCoreRelationshipQuery}
        />
      </Graph>
    </div>
  );
};

const REFETCH_DEBOUNCE_MS = 50;

interface GraphContainerCorrelationProps
  extends Omit<GraphContainerCorrelationComponentProps, 'currentData' | 'totalData'> {
  containerId: string
  containerType: string
  dataPositions: GraphContainerCorrelationPositions_fragment$key
  queryObjectsRef: PreloadedQuery<GraphContainerCorrelationObjectsQuery>
  pageSize: number
}

const GraphContainerCorrelation = ({
  containerId,
  containerType,
  dataPositions,
  queryObjectsRef,
  pageSize,
  ...otherProps
}: GraphContainerCorrelationProps) => {
  const localStorageKey = `${containerType}-correlation-graph-${containerId}`;
  const [dataLoaded, setDataLoaded] = useState(0);

  const {
    data: { container },
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<
  GraphContainerCorrelationObjectsQuery,
  GraphContainerCorrelationObjects_fragment$key
  >({
    linesQuery: graphContainerCorrelationObjectsQuery,
    linesFragment: graphContainerCorrelationObjectsFragment,
    queryRef: queryObjectsRef,
  });

  // Use debounce to avoid spamming too quickly the backend.
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
    graphContainerCorrelationPositionsFragment,
    dataPositions,
  );

  const objects = useMemo(() => (container ? getObjectsToParse(container) : []), [container]);
  const positions = useMemo(() => deserializeObjectB64(x_opencti_graph_data), [x_opencti_graph_data]);

  return (
    <GraphProvider
      localStorageKey={localStorageKey}
      objects={objects}
      positions={positions}
      context='correlation'
    >
      <GraphContainerCorrelationComponent
        currentData={dataLoaded}
        totalData={container?.objects?.pageInfo.globalCount ?? 1}
        {...otherProps}
      />
    </GraphProvider>
  );
};

export default GraphContainerCorrelation;
